use std::io::{Cursor, Read};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use protobuf::Message;
use widevine_proto::license_protocol::WidevinePsshData;

use crate::Error;

/// PSSH (Protection System Specific Header)
///
/// The PSSH object is used to identify the protected medium.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
#[non_exhaustive]
pub struct Pssh {
    pub version: u8,
    pub flags: u32,
    pub init_data: Vec<u8>,
    pub key_ids: Vec<[u8; 16]>,
}

/// Widevine DRM System ID: `edef8ba979d6-4acea3-c827dcd51d21ed`
const WIDEVINE_SYSTEM_ID: [u8; 16] = [
    0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed,
];

impl Pssh {
    /// Parse base64-formatted PSSH data
    pub fn from_b64(pssh: &str) -> Result<Self, Error> {
        let pssh_bts = data_encoding::BASE64
            .decode(pssh.as_bytes())
            .map_err(|e| Error::InvalidInput(format!("base64: {e}").into()))?;
        Self::from_bytes(&pssh_bts)
    }

    /// Create a new PSSH object from either a PSSH box (also MP4 variant) or a WidevineCencHeader
    pub fn from_bytes(pssh: &[u8]) -> Result<Self, Error> {
        if let Ok(pssh) = Self::from_box(pssh) {
            return Ok(pssh);
        }

        if let Ok(pssh) = Self::from_box_content(pssh) {
            return Ok(pssh);
        }

        Self::from_cenc_header(pssh)
    }

    /// Create a new PSSH object from the PSSH box content (with size field and "pssh" header name)
    pub fn from_box(pssh: &[u8]) -> Result<Self, Error> {
        let mut rdr = Cursor::new(pssh);
        let size = rdr.read_u32::<BigEndian>()?;
        if pssh.len() != usize::try_from(size).unwrap_or(usize::MAX) {
            return Err(Error::InvalidInput("unexpected length".into()));
        }

        let mut box_header = [0u8; 4];
        rdr.read_exact(&mut box_header)?;
        if &box_header != b"pssh" {
            return Err(Error::InvalidInput("no pssh header".into()));
        }

        Self::from_box_content(&pssh[usize::try_from(rdr.position()).expect("cursor position")..])
    }

    /// Create a new PSSH object from the MP4 PSSH box content (without size field and "pssh" header name)
    pub fn from_box_content(pssh: &[u8]) -> Result<Self, Error> {
        let mut rdr = Cursor::new(pssh);
        let version_and_flags = rdr.read_u32::<BigEndian>()?;
        let version: u8 = (version_and_flags >> 24) as u8;
        let flags = version_and_flags & 0xffffff;
        if version > 1 {
            return Err(Error::InvalidInput(
                format!("unsupported PSSH version {version}").into(),
            ));
        }

        let mut system_id = [0u8; 16];
        rdr.read_exact(&mut system_id)?;
        if system_id != WIDEVINE_SYSTEM_ID {
            return Err(Error::InvalidInput(
                format!(
                    "unsupported DRM system ID: {}",
                    data_encoding::HEXLOWER.encode(&system_id)
                )
                .into(),
            ));
        }

        let mut key_ids = Vec::new();
        if version == 1 {
            let kid_count = rdr.read_u32::<BigEndian>()?;
            key_ids.reserve(kid_count as usize);
            for _ in 0..kid_count {
                let mut key_id = [0u8; 16];
                rdr.read_exact(&mut key_id)?;
                key_ids.push(key_id);
            }
        }

        let init_data_len = rdr.read_u32::<BigEndian>()?;
        let mut init_data = vec![0; init_data_len as usize];
        rdr.read_exact(&mut init_data)?;
        _ = WidevinePsshData::parse_from_bytes(&init_data)?;

        Ok(Self {
            version,
            flags,
            init_data,
            key_ids,
        })
    }

    /// Create a new PSSH object from WidevineCencHeader
    pub fn from_cenc_header(pssh: &[u8]) -> Result<Self, Error> {
        _ = WidevinePsshData::parse_from_bytes(pssh)?;
        Ok(Pssh {
            version: 0,
            flags: 0,
            init_data: pssh.to_vec(),
            key_ids: Vec::new(),
        })
    }

    /// Try to extract a PSSH object from the header of a MP4 file
    pub fn from_mp4_file<T: Read>(rdr: &mut T) -> Result<Self, Error> {
        crate::mp4::extract_pssh_from_mp4(rdr).map_err(Error::from)
    }

    /// Convert the PSSH into a binary format
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let size = self.len();
        let mut res = Vec::with_capacity(size);
        _ = res.write_u32::<BigEndian>(size.try_into().expect("pssh too big"));
        res.extend_from_slice(b"pssh");
        _ = res.write_u32::<BigEndian>((u32::from(self.version) << 24) | (self.flags & 0xffffff));
        res.extend_from_slice(&WIDEVINE_SYSTEM_ID);
        if self.version == 1 {
            _ = res
                .write_u32::<BigEndian>(self.key_ids.len().try_into().expect("key id len too big"));
            for kid in &self.key_ids {
                res.extend_from_slice(kid);
            }
        }
        _ = res.write_u32::<BigEndian>(
            self.init_data
                .len()
                .try_into()
                .expect("init data len too big"),
        );
        res.extend_from_slice(&self.init_data);
        res
    }

    /// Convert the PSSH into the Base64 format
    #[must_use]
    pub fn to_b64(&self) -> String {
        data_encoding::BASE64.encode(&self.to_bytes())
    }

    /// Get the size of the PSSH object in bytes
    fn len(&self) -> usize {
        let mut size = self.init_data.len() + 32;
        if self.version == 1 {
            size += 4 + self.key_ids.len() * 16;
        }
        size
    }
}

impl TryFrom<&[u8]> for Pssh {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

impl std::fmt::Display for Pssh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        data_encoding::BASE64.encode_write(&self.to_bytes(), f)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::BufReader};

    use path_macro::path;

    use super::*;

    const SAMPLE_V0_PSSH: &str = concat!(
        "AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa7z2FmMPGj2hoNd2lkZXZpbmVfdGVz",
        "dCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA=="
    );
    const SAMPLE_V1_PSSH: &str = concat!(
        "AAAAb3Bzc2gBAAAA7e+LqXnWSs6jyCfc1R0h7QAAAAHrZ2q7yzRelrvPYWYw8aPaAAAAOwgBEhDrZ2q7yzRelrvP",
        "YWYw8aPaGg13aWRldmluZV90ZXN0IhBma2ozbGphU2RmYWxrcjNqKgJIRDIA"
    );

    const SAMPLE_INIT_DATA: [u8; 59] = [
        8, 1, 18, 16, 235, 103, 106, 187, 203, 52, 94, 150, 187, 207, 97, 102, 48, 241, 163, 218,
        26, 13, 119, 105, 100, 101, 118, 105, 110, 101, 95, 116, 101, 115, 116, 34, 16, 102, 107,
        106, 51, 108, 106, 97, 83, 100, 102, 97, 108, 107, 114, 51, 106, 42, 2, 72, 68, 50, 0,
    ];

    const SAMPLE_KID: [u8; 16] = [
        235, 103, 106, 187, 203, 52, 94, 150, 187, 207, 97, 102, 48, 241, 163, 218,
    ];

    #[test]
    fn parse_v0_pssh_box() {
        let pssh = Pssh::from_b64(SAMPLE_V0_PSSH).unwrap();
        assert_eq!(pssh.init_data, SAMPLE_INIT_DATA);
        assert!(pssh.key_ids.is_empty());
    }

    #[test]
    fn parse_v1_pssh_box() {
        let pssh = Pssh::from_b64(SAMPLE_V1_PSSH).unwrap();
        assert_eq!(pssh.init_data, SAMPLE_INIT_DATA);
        assert_eq!(pssh.key_ids, vec![SAMPLE_KID]);
    }

    #[test]
    fn parse_box_content() {
        let pssh = Pssh::from_b64(concat!(
            "AAAAAO3vi6l51krOo8gn3NUdIe0AAAA7CAESEOtnarvLNF6Wu89hZjDx",
            "o9oaDXdpZGV2aW5lX3Rlc3QiEGZrajNsamFTZGZhbGtyM2oqAkhEMgA="
        ))
        .unwrap();
        assert_eq!(pssh.init_data, SAMPLE_INIT_DATA);
        assert!(pssh.key_ids.is_empty());
    }

    #[test]
    fn parse_cenc_header() {
        let pssh = Pssh::from_b64(
            "CAESEOtnarvLNF6Wu89hZjDxo9oaDXdpZGV2aW5lX3Rlc3QiEGZrajNsamFTZGZhbGtyM2oqAkhEMgA=",
        )
        .unwrap();
        assert_eq!(pssh.init_data, SAMPLE_INIT_DATA);
        assert!(pssh.key_ids.is_empty());
    }

    #[test]
    fn parse_mp4() {
        let path = path!(env!("CARGO_MANIFEST_DIR") / "testfiles" / "test.mp4.head");

        let mut reader = BufReader::new(File::open(&path).unwrap()).take(1000);
        let pssh = Pssh::from_mp4_file(&mut reader).unwrap();
        assert_eq!(
            pssh.to_b64(),
            "AAAAOHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAABgiEGijTzthw0pzsAb3Y40LwU5I49yVmwY="
        );
    }

    #[test]
    fn build_v0_pssh() {
        let pssh = Pssh {
            version: 0,
            flags: 0,
            init_data: SAMPLE_INIT_DATA.to_vec(),
            key_ids: Vec::new(),
        };
        assert_eq!(pssh.to_b64(), SAMPLE_V0_PSSH);
    }

    #[test]
    fn build_v1_pssh() {
        let pssh = Pssh {
            version: 1,
            flags: 0,
            init_data: SAMPLE_INIT_DATA.to_vec(),
            key_ids: vec![SAMPLE_KID],
        };
        assert_eq!(pssh.to_b64(), SAMPLE_V1_PSSH);
    }
}
