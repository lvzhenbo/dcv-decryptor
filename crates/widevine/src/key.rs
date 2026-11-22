use std::fmt::Write;

use aes::Aes128;
use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use cbc::Decryptor;

use crate::Error;
use widevine_proto::license_protocol::license::{
    KeyContainer, key_container::KeyType as PbKeyType,
};

/// Set of Widevine keys
#[derive(Debug, Clone)]
pub struct KeySet(Vec<Key>);

/// Widevine key
#[derive(Clone)]
pub struct Key {
    /// Widevine key type
    pub typ: KeyType,
    /// Key ID
    pub kid: [u8; 16],
    /// Key
    pub key: Vec<u8>,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}] ", self.typ)?;
        data_encoding::HEXLOWER.encode_write(&self.kid, f)?;
        f.write_char(':')?;
        data_encoding::HEXLOWER.encode_write(&self.key, f)?;
        Ok(())
    }
}

/// Widevine key type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum KeyType {
    /// Key used for signing requests/responses
    SIGNING = 1,
    /// Key used for decrypting content
    CONTENT = 2,
    /// Key control block for license renewals. No key.
    KEY_CONTROL = 3,
    /// Wrapped keys for auxiliary crypto operations
    OPERATOR_SESSION = 4,
    /// Entitlement keys
    ENTITLEMENT = 5,
    /// Partner-specific content key
    OEM_CONTENT = 6,
}

impl From<PbKeyType> for KeyType {
    fn from(value: PbKeyType) -> Self {
        match value {
            PbKeyType::SIGNING => Self::SIGNING,
            PbKeyType::CONTENT => Self::CONTENT,
            PbKeyType::KEY_CONTROL => Self::KEY_CONTROL,
            PbKeyType::OPERATOR_SESSION => Self::OPERATOR_SESSION,
            PbKeyType::ENTITLEMENT => Self::ENTITLEMENT,
            PbKeyType::OEM_CONTENT => Self::OEM_CONTENT,
        }
    }
}

impl KeySet {
    pub(crate) fn from_key_container(container: Vec<KeyContainer>, enc_key: &[u8; 16]) -> Self {
        Self(
            container
                .into_iter()
                .filter_map(|c| Key::from_key_container(c, enc_key).ok())
                .collect(),
        )
    }

    /// Returns an iterator providing keys of a specific type
    pub fn of_type(&self, typ: KeyType) -> impl Iterator<Item = &'_ Key> {
        self.0.iter().filter(move |key| key.typ == typ)
    }

    /// Get the first key of the given type
    pub fn first_of_type(&self, typ: KeyType) -> Result<&'_ Key, Error> {
        self.0
            .iter()
            .find(|key| key.typ == typ)
            .ok_or_else(|| Error::InvalidLicense(format!("did not receive {typ:?} key").into()))
    }

    /// Get a content key with the given ID
    pub fn content_key(&self, id: &[u8]) -> Result<&'_ Key, Error> {
        self.0
            .iter()
            .find(|key| key.typ == KeyType::CONTENT && key.kid == id)
            .ok_or_else(|| {
                Error::InvalidLicense(
                    format!("did not receive key {}", data_encoding::HEXLOWER.encode(id)).into(),
                )
            })
    }
}

impl Key {
    pub(crate) fn from_key_container(
        container: KeyContainer,
        enc_key: &[u8; 16],
    ) -> Result<Self, Error> {
        if container.id().len() > 16 {
            return Err(Error::InvalidLicense(
                "Key ID is longer than 16 bytes".into(),
            ));
        }
        let mut kid = [0u8; 16];
        kid[..container.id().len()].copy_from_slice(container.id());

        let iv: [u8; 16] = container
            .iv()
            .try_into()
            .map_err(|_| Error::InvalidLicense("Key IV has unexpected length".into()))?;
        let dec = Decryptor::<Aes128>::new(enc_key.into(), &iv.into());
        let key = dec
            .decrypt_padded_vec::<Pkcs7>(container.key())
            .map_err(|_| Error::InvalidLicense("Padding error decrypting key".into()))?;

        Ok(Self {
            typ: container.type_().into(),
            kid,
            key,
        })
    }
}
