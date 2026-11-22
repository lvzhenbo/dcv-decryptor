use std::sync::{Arc, atomic::AtomicU64};

use aes::Aes128;
use aes::cipher::{BlockModeEncrypt, KeyInit, KeyIvInit, block_padding::Pkcs7};
use cbc::Encryptor;
use cmac::{Cmac, Mac};
use hmac::Hmac;
use protobuf::{Message, MessageField};
use rand::{Rng, RngExt};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{BoxedUint, Oaep, Pss, PublicKey};
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::Error;
use crate::key::KeySet;
use crate::pssh::Pssh;
use widevine_proto::license_protocol::{
    DrmCertificate, EncryptedClientIdentification, License, LicenseRequest, ProtocolVersion,
    SignedDrmCertificate, SignedMessage, license_request::RequestType,
    license_request::content_identification::WidevinePsshData, signed_message::MessageType,
};

use crate::device::{Device, DeviceType};

const ROOT_PUBLIC_KEY_N: [u8; 384] = [
    145, 95, 51, 210, 80, 130, 100, 180, 120, 63, 85, 150, 166, 206, 181, 247, 18, 232, 18, 167,
    111, 3, 229, 7, 62, 81, 212, 248, 185, 220, 28, 254, 197, 61, 65, 109, 136, 210, 18, 172, 60,
    147, 88, 236, 35, 184, 17, 18, 39, 71, 228, 43, 231, 231, 24, 253, 8, 165, 255, 132, 21, 104,
    125, 76, 138, 148, 124, 129, 28, 49, 151, 127, 75, 234, 60, 71, 228, 55, 13, 89, 224, 36, 179,
    17, 31, 236, 53, 200, 136, 68, 86, 13, 130, 1, 159, 242, 178, 25, 237, 37, 20, 173, 19, 57,
    140, 105, 94, 6, 41, 228, 191, 76, 96, 130, 220, 143, 120, 176, 127, 190, 220, 109, 25, 210,
    111, 239, 117, 220, 23, 91, 119, 72, 94, 79, 250, 48, 170, 183, 210, 251, 0, 61, 17, 26, 96,
    124, 186, 83, 195, 235, 220, 17, 255, 51, 69, 94, 82, 121, 152, 2, 224, 18, 230, 180, 142, 184,
    249, 177, 51, 140, 202, 52, 116, 228, 54, 107, 255, 17, 108, 200, 245, 101, 14, 146, 24, 170,
    132, 72, 136, 155, 184, 39, 31, 137, 186, 75, 236, 125, 185, 51, 178, 183, 43, 72, 130, 253,
    252, 99, 25, 62, 23, 138, 233, 176, 126, 114, 156, 203, 180, 193, 92, 130, 77, 180, 41, 189,
    193, 250, 160, 114, 62, 188, 111, 147, 37, 226, 39, 80, 64, 126, 253, 32, 38, 112, 32, 130,
    136, 168, 204, 215, 132, 235, 151, 154, 83, 156, 133, 37, 25, 225, 215, 214, 69, 113, 157, 169,
    16, 34, 217, 186, 169, 118, 174, 223, 76, 214, 146, 15, 143, 19, 118, 167, 253, 9, 253, 95, 71,
    62, 83, 105, 72, 181, 75, 236, 114, 91, 83, 171, 139, 35, 52, 190, 34, 128, 53, 176, 251, 171,
    57, 132, 138, 203, 67, 14, 70, 47, 93, 104, 22, 21, 120, 152, 33, 197, 223, 102, 190, 184, 127,
    114, 38, 149, 169, 64, 156, 63, 210, 54, 179, 219, 120, 166, 125, 53, 109, 246, 76, 83, 3, 87,
    160, 53, 159, 251, 220, 223, 101, 135, 219, 16, 177, 35, 77, 231, 242, 155, 94, 195, 242, 205,
    104, 232, 9, 151, 17, 60, 219, 3, 144, 101, 195, 57, 254, 180,
];

/// Widevine CDM (Content Decryption Module)
///
/// The CDM can be cheaply cloned since it uses an [`Arc`] inside.
#[derive(Clone)]
pub struct Cdm {
    inner: Arc<CdmInner>,
}

struct CdmInner {
    device: Arc<Device>,
    session_ctr: AtomicU64,
}

/// Session with the CDM
pub struct CdmSession {
    device: Arc<Device>,
    number: u64,
    service_certificate: Option<ServiceCertificate>,
}

/// License request using the CDM
pub struct CdmLicenseRequest {
    session: CdmSession,
    license_request: Vec<u8>,
}

/// Certificate for a Widevine-protected service
///
/// The Service Certificate is used to encrypt Client IDs in Licenses. This is also
/// known as Privacy Mode and may be required for some services or for some devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceCertificate {
    /// URL of the provider
    pub provider_id: String,
    /// Certificate serial number
    pub serial_number: Vec<u8>,
    /// RSA public key of the certificate
    pub public_key: PublicKey,
}

struct DerivedKeys {
    enc_key: [u8; 16],
    mac_key_server: [u8; 32],
}

impl TryFrom<&[u8]> for ServiceCertificate {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let signed_drm_certificate = SignedMessage::parse_from_bytes(value)
            .ok()
            .filter(|msg| msg.type_() == MessageType::SERVICE_CERTIFICATE)
            .map_or_else(
                || SignedDrmCertificate::parse_from_bytes(value),
                |msg| SignedDrmCertificate::parse_from_bytes(msg.msg()),
            )?;

        let root_key = PublicKey::new_unchecked(
            BoxedUint::from_le_slice_vartime(&ROOT_PUBLIC_KEY_N),
            BoxedUint::from_le_slice_vartime(&[1, 0, 1]),
        );
        let digest = Sha1::digest(signed_drm_certificate.drm_certificate());
        root_key.verify(
            Pss::<Sha1>::new(),
            &digest,
            signed_drm_certificate.signature(),
        )?;

        let drm_certificate =
            DrmCertificate::parse_from_bytes(signed_drm_certificate.drm_certificate())?;
        let public_key = PublicKey::from_pkcs1_der(drm_certificate.public_key())
            .map_err(|e| Error::InvalidInput(e.to_string().into()))?;

        Ok(Self {
            provider_id: drm_certificate.provider_id.unwrap_or_default(),
            serial_number: drm_certificate.serial_number.unwrap_or_default(),
            public_key,
        })
    }
}

impl TryFrom<&Vec<u8>> for ServiceCertificate {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

/// Widevine license type
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub enum LicenseType {
    /// Normal one-time-use license
    #[default]
    STREAMING,
    /// Offline-use licence, usually for downloaded content
    OFFLINE,
    /// License type decision is left to provider
    AUTOMATIC,
}

impl From<LicenseType> for widevine_proto::license_protocol::LicenseType {
    fn from(value: LicenseType) -> Self {
        match value {
            LicenseType::STREAMING => Self::STREAMING,
            LicenseType::OFFLINE => Self::OFFLINE,
            LicenseType::AUTOMATIC => Self::AUTOMATIC,
        }
    }
}

impl Cdm {
    /// Create a new CDM using the given device
    pub fn new(device: Device) -> Self {
        Self {
            inner: CdmInner {
                device: Arc::new(device),
                session_ctr: AtomicU64::new(1),
            }
            .into(),
        }
    }

    /// Get the [`Device`] used by the CDM
    #[must_use]
    pub fn device(&self) -> &Device {
        &self.inner.device
    }

    /// Open a new session with the CDM
    #[must_use]
    pub fn open(&self) -> CdmSession {
        CdmSession {
            device: self.inner.device.clone(),
            number: self
                .inner
                .session_ctr
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel),
            service_certificate: None,
        }
    }
}

impl CdmSession {
    /// Set a Service Privacy Certificate for Privacy Mode (optional but recommended).
    ///
    /// The Service Certificate is used to encrypt Client IDs in Licenses. This is also
    /// known as Privacy Mode and may be required for some services or for some devices.
    /// Chrome CDM requires it as of the enforcement of VMP (Verified Media Path).
    ///
    /// We reject direct DrmCertificates as they do not have signature verification and
    /// cannot be verified. You must provide a SignedDrmCertificate or a SignedMessage
    /// containing a SignedDrmCertificate.
    pub fn set_service_certificate<C>(mut self, certificate: C) -> Result<Self, Error>
    where
        C: TryInto<ServiceCertificate, Error: Into<Error>>,
    {
        self.service_certificate = Some(certificate.try_into().map_err(Into::into)?);
        Ok(self)
    }

    /// Use the hardcoded Privacy Certificate used by Google's production license server (license.google.com).
    ///
    /// Not publicly accessible directly, but a lot of services have their own gateways to it.
    #[must_use]
    pub fn set_service_certificate_common(mut self) -> Self {
        self.service_certificate = Some(ServiceCertificate {
            provider_id: "license.widevine.com".to_owned(),
            serial_number: vec![
                23, 5, 185, 23, 204, 18, 4, 134, 139, 6, 51, 58, 47, 119, 42, 140,
            ],
            public_key: PublicKey::new_unchecked(
                BoxedUint::from_le_slice_vartime(&[
                    9, 90, 159, 156, 1, 80, 18, 207, 27, 113, 180, 8, 211, 251, 100, 223, 110, 94,
                    252, 176, 93, 159, 107, 11, 47, 88, 226, 67, 40, 232, 89, 12, 1, 47, 75, 175,
                    55, 236, 78, 167, 144, 68, 19, 243, 197, 74, 44, 216, 198, 103, 111, 13, 104,
                    130, 112, 112, 36, 206, 237, 89, 131, 11, 18, 150, 185, 130, 160, 115, 92, 197,
                    215, 108, 231, 208, 226, 100, 245, 186, 91, 245, 238, 252, 154, 146, 96, 189,
                    238, 151, 191, 164, 32, 149, 76, 186, 196, 209, 4, 198, 176, 64, 191, 225, 49,
                    253, 66, 100, 251, 111, 61, 241, 146, 51, 222, 202, 241, 186, 221, 24, 130, 67,
                    93, 170, 126, 164, 12, 73, 71, 202, 16, 74, 189, 236, 78, 251, 33, 58, 152, 93,
                    112, 51, 235, 205, 124, 214, 168, 55, 177, 87, 132, 172, 79, 224, 220, 122, 96,
                    168, 88, 128, 14, 230, 20, 61, 38, 70, 95, 164, 232, 129, 87, 30, 158, 1, 225,
                    119, 234, 254, 251, 191, 33, 126, 140, 135, 140, 21, 111, 11, 97, 8, 48, 57,
                    121, 18, 169, 56, 14, 175, 225, 167, 35, 64, 88, 88, 29, 41, 149, 7, 158, 74,
                    94, 90, 114, 78, 140, 184, 27, 177, 173, 227, 140, 173, 65, 4, 81, 64, 223,
                    184, 118, 216, 20, 184, 69, 6, 62, 80, 55, 203, 188, 213, 10, 82, 152, 181,
                    149, 42, 182, 195, 239, 36, 94, 171, 125, 50, 59, 91, 237, 153,
                ]),
                BoxedUint::from_le_slice_vartime(&[1, 0, 1]),
            ),
        });
        self
    }

    /// Use the hardcoded Privacy Certificate used by Google's staging license server (staging.google.com).
    ///
    /// This can be publicly accessed without authentication using <https://cwip-shaka-proxy.appspot.com/no_auth>.
    #[must_use]
    pub fn set_service_certificate_staging(mut self) -> Self {
        self.service_certificate = Some(ServiceCertificate {
            provider_id: "staging.google.com".to_owned(),
            serial_number: vec![
                40, 112, 52, 84, 192, 8, 246, 54, 24, 173, 231, 68, 61, 182, 196, 200,
            ],
            public_key: PublicKey::new_unchecked(
                BoxedUint::from_le_slice_vartime(&[
                    67, 217, 154, 127, 160, 103, 253, 36, 175, 157, 188, 134, 148, 19, 56, 54, 76,
                    51, 3, 71, 96, 1, 239, 60, 153, 160, 208, 192, 160, 96, 77, 247, 162, 188, 194,
                    147, 216, 69, 13, 8, 104, 214, 241, 8, 88, 229, 190, 144, 147, 88, 114, 171,
                    84, 66, 79, 61, 40, 246, 62, 243, 103, 103, 72, 66, 239, 239, 223, 183, 86, 54,
                    146, 144, 94, 144, 189, 80, 120, 33, 172, 43, 83, 0, 31, 192, 140, 73, 14, 74,
                    247, 1, 81, 173, 173, 6, 106, 100, 220, 125, 202, 146, 15, 152, 145, 90, 103,
                    77, 241, 216, 220, 238, 64, 199, 187, 9, 11, 197, 64, 160, 163, 128, 255, 239,
                    129, 240, 65, 76, 90, 192, 138, 33, 90, 91, 24, 211, 161, 52, 241, 109, 23, 20,
                    126, 42, 186, 77, 173, 245, 170, 182, 249, 30, 94, 127, 137, 24, 39, 96, 76,
                    62, 13, 99, 102, 79, 28, 23, 170, 98, 121, 133, 185, 242, 148, 184, 166, 185,
                    225, 38, 13, 29, 129, 239, 102, 91, 7, 111, 81, 178, 148, 234, 90, 212, 137,
                    122, 192, 10, 95, 187, 103, 224, 245, 199, 162, 34, 179, 116, 98, 154, 94, 129,
                    7, 84, 233, 223, 8, 220, 95, 213, 70, 153, 183, 130, 49, 188, 42, 61, 30, 102,
                    222, 67, 103, 176, 91, 53, 239, 190, 210, 216, 124, 23, 180, 73, 198, 193, 81,
                    194, 226, 149, 93, 204, 63, 2, 93, 208, 184, 18, 33, 181,
                ]),
                BoxedUint::from_le_slice_vartime(&[1, 0, 1]),
            ),
        });
        self
    }

    /// Create a new [`CdmLicenseRequest`] to send to a License Server
    pub fn get_license_request(
        self,
        pssh: Pssh,
        license_type: LicenseType,
    ) -> Result<CdmLicenseRequest, Error> {
        let mut request_id = vec![0u8; 16];
        let mut rng = rand::rng();
        if self.device.device_type() == DeviceType::ANDROID {
            // OEMCrypto's request_id seems to be in AES CTR Counter block form with no suffix
            // Bytes 5-8 does not seem random, in real tests they have been consecutive \x00 or \xFF
            // Real example: A0DCE548000000000500000000000000
            rng.fill(&mut request_id[..4]);
            let n_bts = self.number.to_le_bytes();
            request_id[8..(8 + 8)].copy_from_slice(&n_bts);
        } else {
            rng.fill_bytes(&mut request_id);
        }

        let mut license_request = LicenseRequest::new();
        if self.service_certificate.is_some() {
            license_request.encrypted_client_id = MessageField::some(self.encrypt_client_id()?);
        } else {
            license_request.client_id = MessageField::some(self.device.client_id.clone());
        }
        let mut pd = WidevinePsshData::new();
        pd.pssh_data.push(pssh.init_data);
        pd.set_license_type(license_type.into());
        pd.set_request_id(request_id);
        license_request
            .content_id
            .mut_or_insert_default()
            .set_widevine_pssh_data(pd);
        license_request.set_type(RequestType::NEW);
        license_request.set_request_time(
            i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
            .expect("system time is out of range"),
        );
        license_request.set_protocol_version(ProtocolVersion::VERSION_2_1);
        license_request.set_key_control_nonce(rand::rng().random_range(1..2147483648));

        let license_request_bts = license_request.write_to_bytes()?;
        Ok(CdmLicenseRequest {
            session: self,
            license_request: license_request_bts,
        })
    }

    fn encrypt_client_id(&self) -> Result<EncryptedClientIdentification, Error> {
        let service_cert = self
            .service_certificate
            .as_ref()
            .ok_or(Error::InvalidInput(
                "Privacy mode requires a service certificate".into(),
            ))?;

        let privacy_key = random_key();
        let privacy_iv = random_key();

        let enc = Encryptor::<Aes128>::new(&privacy_key.into(), &privacy_iv.into());
        let client_id_bts = self.device.client_id.write_to_bytes()?;
        let client_id_enc = enc.encrypt_padded_vec::<Pkcs7>(&client_id_bts);

        let privacy_key_enc =
            service_cert
                .public_key
                .encrypt(&mut rand::rng(), Oaep::<Sha1>::new(), &privacy_key)?;

        let mut ident = EncryptedClientIdentification::new();
        ident.set_provider_id(service_cert.provider_id.clone());
        ident.set_service_certificate_serial_number(service_cert.serial_number.clone());
        ident.set_encrypted_client_id(client_id_enc);
        ident.set_encrypted_client_id_iv(privacy_iv.to_vec());
        ident.set_encrypted_privacy_key(privacy_key_enc);

        Ok(ident)
    }
}

impl CdmLicenseRequest {
    /// Get the License Request data (Challenge) to send to a License Server.
    ///
    /// Returns a SignedMessage containing a LicenseRequest message. It's signed with
    /// the private key of the device provision.
    pub fn challenge(&self) -> Result<Vec<u8>, Error> {
        let digest = Sha1::digest(&self.license_request);
        let mut rng = rand::rng();
        let signature =
            self.session
                .device
                .private_key
                .sign_with_rng(&mut rng, Pss::<Sha1>::new(), &digest)?;

        let mut signed_license_request = SignedMessage::new();
        signed_license_request.set_type(MessageType::LICENSE_REQUEST);
        signed_license_request.set_msg(self.license_request.clone());
        signed_license_request.set_signature(signature);

        Ok(signed_license_request.write_to_bytes()?)
    }

    /// Decrypt the License Message received from the License Server and get the keys
    pub fn get_keys(&self, license_message: &[u8]) -> Result<KeySet, Error> {
        let license_message = SignedMessage::parse_from_bytes(license_message)?;
        if license_message.type_() != MessageType::LICENSE {
            return Err(Error::InvalidLicense(
                format!(
                    "Expecting a LICENSE message, not a {:?}",
                    license_message.type_()
                )
                .into(),
            ));
        }

        let license = License::parse_from_bytes(license_message.msg())?;
        let key: [u8; 16] = self
            .session
            .device
            .private_key
            .decrypt(Oaep::<Sha1>::new(), license_message.session_key())?
            .try_into()
            .map_err(|_| Error::InvalidLicense("unexpected key length".into()))?;
        let derived_keys = self.derive_keys(key);

        let mut hmac = Hmac::<Sha256>::new_from_slice(&derived_keys.mac_key_server).unwrap();
        hmac.update(license_message.oemcrypto_core_message());
        hmac.update(license_message.msg());
        let computed_signature = hmac.finalize().into_bytes();

        if license_message.signature() != computed_signature.as_slice() {
            return Err(Error::InvalidLicense(
                "Signature Mismatch on License Message, rejecting license".into(),
            ));
        }

        let key_set = KeySet::from_key_container(license.key, &derived_keys.enc_key);
        Ok(key_set)
    }

    fn derive_context(&self) -> (Vec<u8>, Vec<u8>) {
        let mut enc_context = b"ENCRYPTION\0".to_vec();
        enc_context.extend_from_slice(&self.license_request);
        enc_context.extend_from_slice(&128u32.to_be_bytes());

        let mut mac_context = b"AUTHENTICATION\0".to_vec();
        mac_context.extend_from_slice(&self.license_request);
        mac_context.extend_from_slice(&512u32.to_be_bytes());

        (enc_context, mac_context)
    }

    fn derive_keys(&self, key: [u8; 16]) -> DerivedKeys {
        let derive = |context: &[u8], counter: u8| -> [u8; 16] {
            let mut cmac = Cmac::<Aes128>::new_from_slice(&key).expect("16-byte CMAC key");
            cmac.update(&[counter]);
            cmac.update(context);
            cmac.finalize().into_bytes().into()
        };

        let (enc_context, mac_context) = self.derive_context();

        let enc_key = derive(&enc_context, 1);
        let mac_key_server1 = derive(&mac_context, 1);
        let mac_key_server2 = derive(&mac_context, 2);

        let mut mac_key_server = [0u8; 32];
        mac_key_server[..16].copy_from_slice(&mac_key_server1);
        mac_key_server[16..].copy_from_slice(&mac_key_server2);

        DerivedKeys {
            enc_key,
            mac_key_server,
        }
    }
}

fn random_key() -> [u8; 16] {
    rand::random()
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::BufReader};

    use path_macro::path;

    use super::*;

    #[test]
    fn parse_privacy_cert() {
        let path = path!(env!("CARGO_MANIFEST_DIR") / "testfiles" / "device.wvd");
        let device = Device::read_wvd(BufReader::new(File::open(path).unwrap())).unwrap();
        let cdm = Cdm::new(device);

        // Original certificates from pyvidewine
        let common_privacy_cert = data_encoding::BASE64.decode(b"CAUSxwUKwQIIAxIQFwW5F8wSBIaLBjM6L3cqjBiCtIKSBSKOAjCCAQoCggEBAJntWzsyfateJO/DtiqVtZhSCtW8yzdQPgZFuBTYdrjfQFEEQa2M462xG7iMTnJaXkqeB5UpHVhYQCOn4a8OOKkSeTkwCGELbxWMh4x+Ib/7/up34QGeHleB6KRfRiY9FOYOgFioYHrc4E+shFexN6jWfM3rM3BdmDoh+07svUoQykdJDKR+ql1DghjduvHK3jOS8T1v+2RC/THhv0CwxgTRxLpMlSCkv5fuvWCSmvzu9Vu69WTi0Ods18Vcc6CCuZYSC4NZ7c4kcHCCaA1vZ8bYLErF8xNEkKdO7DevSy8BDFnoKEPiWC8La59dsPxebt9k+9MItHEbzxJQAZyfWgkCAwEAAToUbGljZW5zZS53aWRldmluZS5jb20SgAOuNHMUtag1KX8nE4j7e7jLUnfSSYI83dHaMLkzOVEes8y96gS5RLknwSE0bv296snUE5F+bsF2oQQ4RgpQO8GVK5uk5M4PxL/CCpgIqq9L/NGcHc/N9XTMrCjRtBBBbPneiAQwHL2zNMr80NQJeEI6ZC5UYT3wr8+WykqSSdhV5Cs6cD7xdn9qm9Nta/gr52u/DLpP3lnSq8x2/rZCR7hcQx+8pSJmthn8NpeVQ/ypy727+voOGlXnVaPHvOZV+WRvWCq5z3CqCLl5+Gf2Ogsrf9s2LFvE7NVV2FvKqcWTw4PIV9Sdqrd+QLeFHd/SSZiAjjWyWOddeOrAyhb3BHMEwg2T7eTo/xxvF+YkPj89qPwXCYcOxF+6gjomPwzvofcJOxkJkoMmMzcFBDopvab5tDQsyN9UPLGhGC98X/8z8QSQ+spbJTYLdgFenFoGq47gLwDS6NWYYQSqzE3Udf2W7pzk4ybyG4PHBYV3s4cyzdq8amvtE/sNSdOKReuHpfQ=").unwrap();
        let staging_privacy_cert = data_encoding::BASE64.decode(b"CAUSxQUKvwIIAxIQKHA0VMAI9jYYredEPbbEyBiL5/mQBSKOAjCCAQoCggEBALUhErjQXQI/zF2V4sJRwcZJtBd82NK+7zVbsGdD3mYePSq8MYK3mUbVX9wI3+lUB4FemmJ0syKix/XgZ7tfCsB6idRa6pSyUW8HW2bvgR0NJuG5priU8rmFeWKqFxxPZmMNPkxgJxiJf14e+baq9a1Nuip+FBdt8TSh0xhbWiGKwFpMQfCB7/+Ao6BAxQsJu8dA7tzY8U1nWpGYD5LKfdxkagatrVEB90oOSYzAHwBTK6wheFC9kF6QkjZWt9/v70JIZ2fzPvYoPU9CVKtyWJOQvuVYCPHWaAgNRdiTwryi901goMDQoJk87wFgRwMzTDY4E5SGvJ2vJP1noH+a2UMCAwEAAToSc3RhZ2luZy5nb29nbGUuY29tEoADmD4wNSZ19AunFfwkm9rl1KxySaJmZSHkNlVzlSlyH/iA4KrvxeJ7yYDa6tq/P8OG0ISgLIJTeEjMdT/0l7ARp9qXeIoA4qprhM19ccB6SOv2FgLMpaPzIDCnKVww2pFbkdwYubyVk7jei7UPDe3BKTi46eA5zd4Y+oLoG7AyYw/pVdhaVmzhVDAL9tTBvRJpZjVrKH1lexjOY9Dv1F/FJp6X6rEctWPlVkOyb/SfEJwhAa/K81uDLyiPDZ1Flg4lnoX7XSTb0s+Cdkxd2b9yfvvpyGH4aTIfat4YkF9Nkvmm2mU224R1hx0WjocLsjA89wxul4TJPS3oRa2CYr5+DU4uSgdZzvgtEJ0lksckKfjAF0K64rPeytvDPD5fS69eFuy3Tq26/LfGcF96njtvOUA4P5xRFtICogySKe6WnCUZcYMDtQ0BMMM1LgawFNg4VA+KDCJ8ABHg9bOOTimO0sswHrRWSWX1XF15dXolCk65yEqz5lOfa2/fVomeopkU").unwrap();

        let r_common = cdm.open().set_service_certificate_common();
        let r2 = cdm
            .open()
            .set_service_certificate(&common_privacy_cert)
            .unwrap();
        assert_eq!(
            r_common.service_certificate.unwrap(),
            r2.service_certificate.unwrap()
        );

        let r_staging = cdm.open().set_service_certificate_staging();
        let r2 = cdm
            .open()
            .set_service_certificate(&staging_privacy_cert)
            .unwrap();
        assert_eq!(
            r_staging.service_certificate.unwrap(),
            r2.service_certificate.unwrap()
        );
    }
}
