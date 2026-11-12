//! EFI_GUID in its on-the-wire (mixed-endian) layout.

use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    pub const fn new(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Self {
        let a = d1.to_le_bytes();
        let b = d2.to_le_bytes();
        let c = d3.to_le_bytes();
        Self([
            a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4],
            d4[5], d4[6], d4[7],
        ])
    }

    pub fn from_slice(b: &[u8]) -> Option<Self> {
        Some(Self(b.get(..16)?.try_into().ok()?))
    }

    #[cfg(test)]
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().trim_start_matches('{').trim_end_matches('}');
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 5 || parts[3].len() != 4 || parts[4].len() != 12 {
            return None;
        }
        let d1 = u32::from_str_radix(parts[0], 16).ok()?;
        let d2 = u16::from_str_radix(parts[1], 16).ok()?;
        let d3 = u16::from_str_radix(parts[2], 16).ok()?;
        let tail = hex::decode(format!("{}{}", parts[3], parts[4])).ok()?;
        Some(Self::new(d1, d2, d3, tail.try_into().ok()?))
    }

    /// Friendly name for well-known owner / type GUIDs.
    pub fn well_known(&self) -> Option<&'static str> {
        KNOWN.iter().find(|(g, _)| g == self).map(|(_, n)| *n)
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u16::from_le_bytes([b[4], b[5]]),
            u16::from_le_bytes([b[6], b[7]]),
            b[8],
            b[9],
            hex::encode(&b[10..16])
        )
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl serde::Serialize for Guid {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

pub const EFI_GLOBAL_VARIABLE: Guid = Guid::new(
    0x8be4df61,
    0x93ca,
    0x11d2,
    [0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
);
pub const IMAGE_SECURITY_DATABASE: Guid = Guid::new(
    0xd719b2cb,
    0x3d3a,
    0x4596,
    [0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f],
);
pub const SHIM_LOCK: Guid = Guid::new(
    0x605dab50,
    0xe046,
    0x4300,
    [0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23],
);
pub const MICROSOFT_OWNER: Guid = Guid::new(
    0x77fa9abd,
    0x0359,
    0x4d32,
    [0xbd, 0x60, 0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b],
);

pub const CERT_SHA1: Guid = Guid::new(
    0x826ca512,
    0xcf10,
    0x4ac9,
    [0xb1, 0x87, 0xbe, 0x01, 0x49, 0x66, 0x31, 0xbd],
);
pub const CERT_SHA224: Guid = Guid::new(
    0x0b6e5233,
    0xa65c,
    0x44c9,
    [0x94, 0x07, 0xd9, 0xab, 0x83, 0xbf, 0xc8, 0xbd],
);
pub const CERT_SHA256: Guid = Guid::new(
    0xc1c41626,
    0x504c,
    0x4092,
    [0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28],
);
pub const CERT_SHA384: Guid = Guid::new(
    0xff3e5307,
    0x9fd0,
    0x48c9,
    [0x85, 0xf1, 0x8a, 0xd5, 0x6c, 0x70, 0x1e, 0x01],
);
pub const CERT_SHA512: Guid = Guid::new(
    0x093e0fae,
    0xa6c4,
    0x4f50,
    [0x9f, 0x1b, 0xd4, 0x1e, 0x2b, 0x89, 0xc1, 0x9a],
);
pub const CERT_RSA2048: Guid = Guid::new(
    0x3c5766e8,
    0x269c,
    0x4e34,
    [0xaa, 0x14, 0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6],
);
pub const CERT_X509: Guid = Guid::new(
    0xa5c059a1,
    0x94e4,
    0x4aa7,
    [0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72],
);
pub const CERT_X509_SHA256: Guid = Guid::new(
    0x3bd2a492,
    0x96c0,
    0x4079,
    [0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed],
);
pub const CERT_X509_SHA384: Guid = Guid::new(
    0x7076876e,
    0x80c2,
    0x4ee6,
    [0xaa, 0xd2, 0x28, 0xb3, 0x49, 0xa6, 0x86, 0x5b],
);
pub const CERT_X509_SHA512: Guid = Guid::new(
    0x446dbf63,
    0x2502,
    0x4cda,
    [0xbc, 0xfa, 0x24, 0x65, 0xd2, 0xb0, 0xfe, 0x9d],
);

const KNOWN: &[(Guid, &str)] = &[
    (EFI_GLOBAL_VARIABLE, "EFI_GLOBAL_VARIABLE"),
    (IMAGE_SECURITY_DATABASE, "EFI_IMAGE_SECURITY_DATABASE"),
    (SHIM_LOCK, "SHIM_LOCK"),
    (MICROSOFT_OWNER, "Microsoft"),
    (CERT_SHA1, "EFI_CERT_SHA1"),
    (CERT_SHA224, "EFI_CERT_SHA224"),
    (CERT_SHA256, "EFI_CERT_SHA256"),
    (CERT_SHA384, "EFI_CERT_SHA384"),
    (CERT_SHA512, "EFI_CERT_SHA512"),
    (CERT_RSA2048, "EFI_CERT_RSA2048"),
    (CERT_X509, "EFI_CERT_X509"),
    (CERT_X509_SHA256, "EFI_CERT_X509_SHA256"),
    (CERT_X509_SHA384, "EFI_CERT_X509_SHA384"),
    (CERT_X509_SHA512, "EFI_CERT_X509_SHA512"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_display_parse() {
        let s = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
        assert_eq!(EFI_GLOBAL_VARIABLE.to_string(), s);
        assert_eq!(Guid::parse(s), Some(EFI_GLOBAL_VARIABLE));
        assert_eq!(
            Guid::parse("{D719B2CB-3D3A-4596-A3BC-DAD00E67656F}"),
            Some(IMAGE_SECURITY_DATABASE)
        );
        assert_eq!(Guid::parse("nope"), None);
    }

    #[test]
    fn wire_layout_is_mixed_endian() {
        assert_eq!(&EFI_GLOBAL_VARIABLE.0[..4], &[0x61, 0xdf, 0xe4, 0x8b]);
        assert_eq!(
            &EFI_GLOBAL_VARIABLE.0[8..],
            &[0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c]
        );
    }
}
