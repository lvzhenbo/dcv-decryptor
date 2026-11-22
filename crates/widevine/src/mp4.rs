//! This is a simplified version of Mozilla's MP4 parser to extract PSSHs from MP4 files.
//! The parser is more error-tolerant and capable of parsing truncated files.
//!
//! Original source: <https://github.com/mozilla/mp4parse-rust>
//! License: MPL-2.0

use std::borrow::Cow;
use std::fmt;
use std::io::{Read, Take};

use byteorder::{BigEndian, ReadBytesExt};

use crate::{Error, Pssh};

#[derive(Debug, thiserror::Error)]
pub enum Mp4ParseError {
    /// File I/O error
    #[error("i/o: {0}")]
    Io(std::io::Error),
    /// Reflect `std::io::ErrorKind::UnexpectedEof` for short data.
    #[error("unexpected end of file")]
    UnexpectedEOF,
    #[error("{0}")]
    Msg(Cow<'static, str>),
}

impl From<Mp4ParseError> for Error {
    fn from(value: Mp4ParseError) -> Self {
        match value {
            Mp4ParseError::Io(error) => Self::Io(error),
            Mp4ParseError::UnexpectedEOF => Self::InvalidInput("unexpected end of file".into()),
            Mp4ParseError::Msg(msg) => Self::InvalidInput(msg),
        }
    }
}

impl From<std::io::Error> for Mp4ParseError {
    fn from(value: std::io::Error) -> Self {
        if value.kind() == std::io::ErrorKind::UnexpectedEof {
            Self::UnexpectedEOF
        } else {
            Self::Io(value)
        }
    }
}

pub fn extract_pssh_from_mp4<T: Read>(f: &mut T) -> Result<Pssh, Mp4ParseError> {
    let mut iter = BoxIter::new(f);
    let mut found_moov = false;

    while let Some(mut b) = iter.next_box()? {
        if b.head.name == BoxType::MovieBox {
            found_moov = true;
            if let Some(pssh) = extract_pssh_from_moov(&mut b)? {
                return Ok(pssh);
            }
            break;
        }
        _ = skip_box_content(&mut b);
    }

    if found_moov {
        Err(Mp4ParseError::Msg("no pssh found".into()))
    } else {
        Err(Mp4ParseError::Msg("no moov atom found".into()))
    }
}

fn extract_pssh_from_moov<'a, T: Read>(
    f: &'a mut BMFFBox<'a, T>,
) -> Result<Option<Pssh>, Mp4ParseError> {
    let mut iter = f.box_iter();
    while let Some(mut b) = iter.next_box().ok().flatten() {
        if b.head.name == BoxType::ProtectionSystemSpecificHeaderBox {
            let len = usize::try_from(b.bytes_left())
                .map_err(|_| Mp4ParseError::Msg("pssh box too large".into()))?;
            let mut pssh_data = vec![0; len];
            b.read_exact(&mut pssh_data)?;

            if let Ok(pssh) = Pssh::from_box_content(&pssh_data) {
                return Ok(Some(pssh));
            }
        } else {
            _ = skip_box_content(&mut b);
        }
    }
    Ok(None)
}

/// Basic ISO box structure.
///
/// mp4 files are a sequence of possibly-nested 'box' structures.  Each box
/// begins with a header describing the length of the box's data and a
/// four-byte box type which identifies the type of the box. Together these
/// are enough to interpret the contents of that section of the file.
///
/// See ISOBMFF (ISO 14496-12:2020) § 4.2
#[derive(Debug, Clone, Copy)]
struct BoxHeader {
    /// Box type.
    name: BoxType,
    /// Size of the box in bytes.
    size: u64,
    /// Offset to the start of the contained data (or header size).
    offset: u64,
    /// Uuid for extended type.
    #[allow(dead_code)] // See https://github.com/mozilla/mp4parse-rust/issues/340
    uuid: Option<[u8; 16]>,
}

impl BoxHeader {
    const MIN_SIZE: u64 = 8; // 4-byte size + 4-byte type
    const MIN_LARGE_SIZE: u64 = 16; // 4-byte size + 4-byte type + 16-byte size
}

/// Read and parse a box header.
///
/// Call this first to determine the type of a particular mp4 box
/// and its length. Used internally for dispatching to specific
/// parsers for the internal content, or to get the length to
/// skip unknown or uninteresting boxes.
///
/// See ISOBMFF (ISO 14496-12:2020) § 4.2
fn read_box_header<T: ReadBytesExt>(src: &mut T) -> Result<BoxHeader, Mp4ParseError> {
    let size32 = src.read_u32::<BigEndian>()?;
    let name = BoxType::from(src.read_u32::<BigEndian>()?);
    let size = match size32 {
        // valid only for top-level box and indicates it's the last box in the file.  usually mdat.
        0 => {
            if name == BoxType::MediaDataBox {
                0
            } else {
                return Err(Mp4ParseError::Msg("unknown sized box".into()));
            }
        }
        1 => src.read_u64::<BigEndian>()?,
        _ => u64::from(size32),
    };
    let mut offset = match size32 {
        1 => BoxHeader::MIN_LARGE_SIZE,
        _ => BoxHeader::MIN_SIZE,
    };
    let uuid = if name == BoxType::UuidBox {
        if size >= offset + 16 {
            let mut buffer = [0u8; 16];
            let count = src.read(&mut buffer)?;
            offset += u64::try_from(count).unwrap();
            if count == 16 {
                Some(buffer)
            } else {
                return Err(Mp4ParseError::UnexpectedEOF);
            }
        } else {
            None
        }
    } else {
        None
    };
    match size32 {
        0 => (),
        1 if offset > size => return Err(Mp4ParseError::Msg("malformed wide size".into())),
        _ if offset > size => return Err(Mp4ParseError::Msg("malformed size".into())),
        _ => (),
    }
    Ok(BoxHeader {
        name,
        size,
        offset,
        uuid,
    })
}

/// See ISOBMFF (ISO 14496-12:2020) § 4.2
struct BMFFBox<'a, T: 'a> {
    head: BoxHeader,
    content: Take<&'a mut T>,
}

impl<T: Read> Read for BMFFBox<'_, T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.content.read(buf)
    }
}

impl<'a, T: Read> BMFFBox<'a, T> {
    fn bytes_left(&self) -> u64 {
        self.content.limit()
    }

    fn get_header(&self) -> &BoxHeader {
        &self.head
    }

    fn box_iter(&'a mut self) -> BoxIter<'a, BMFFBox<'a, T>> {
        BoxIter::new(self)
    }
}

struct BoxIter<'a, T: 'a> {
    src: &'a mut T,
}

impl<T: Read> BoxIter<'_, T> {
    fn new(src: &mut T) -> BoxIter<'_, T> {
        BoxIter { src }
    }

    fn next_box(&mut self) -> Result<Option<BMFFBox<'_, T>>, Mp4ParseError> {
        let r = read_box_header(self.src);
        match r {
            Ok(h) => Ok(Some(BMFFBox {
                head: h,
                content: self.src.take(h.size.saturating_sub(h.offset)),
            })),
            Err(Mp4ParseError::UnexpectedEOF) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Skip over the entire contents of a box.
fn skip_box_content<T: Read>(src: &mut BMFFBox<T>) -> Result<(), Mp4ParseError> {
    // Skip the contents of unknown chunks.
    let to_skip = {
        let header = src.get_header();
        header
            .size
            .checked_sub(header.offset)
            .ok_or(Mp4ParseError::Msg("Skipping past unknown sized box".into()))?
    };
    assert_eq!(to_skip, src.bytes_left());
    std::io::copy(&mut src.take(to_skip), &mut std::io::sink())?;
    Ok(())
}

macro_rules! box_database {
    ($($(#[$attr:meta])* $boxenum:ident $boxtype:expr),*,) => {
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub enum BoxType {
            $($(#[$attr])* $boxenum),*,
            Unknown(u32),
        }

        impl From<u32> for BoxType {
            fn from(t: u32) -> BoxType {
                use self::BoxType::*;
                match t {
                    $($(#[$attr])* $boxtype => $boxenum),*,
                    _ => Unknown(t),
                }
            }
        }

        impl From<BoxType> for u32 {
            fn from(b: BoxType) -> u32 {
                use self::BoxType::*;
                match b {
                    $($(#[$attr])* $boxenum => $boxtype),*,
                    Unknown(t) => t,
                }
            }
        }

    }
}

impl fmt::Debug for BoxType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let val = u32::from(*self).to_be_bytes();
        match std::str::from_utf8(&val) {
            Ok(s) => f.write_str(s),
            Err(_) => val.fmt(f),
        }
    }
}

box_database!(
    MediaDataBox                      0x6d64_6174, // "mdat"
    MovieBox                          0x6d6f_6f76, // "moov"
    ProtectionSystemSpecificHeaderBox 0x7073_7368, // "pssh"
    UuidBox                           0x7575_6964, // "uuid"
);
