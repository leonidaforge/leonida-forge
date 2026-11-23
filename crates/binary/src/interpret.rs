#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Endian {
    #[default]
    Little,
    Big,
}

/// Primitive values at the start of a byte slice. A value is `None` when the
/// slice is too short for it.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Values {
    pub u8: Option<u8>,
    pub i8: Option<i8>,
    pub u16: Option<u16>,
    pub i16: Option<i16>,
    pub u32: Option<u32>,
    pub i32: Option<i32>,
    pub u64: Option<u64>,
    pub i64: Option<i64>,
    pub f32: Option<f32>,
    pub f64: Option<f64>,
}

pub fn interpret(bytes: &[u8], endian: Endian) -> Values {
    macro_rules! value {
        ($ty:ty) => {
            bytes
                .get(..size_of::<$ty>())
                .and_then(|slice| slice.try_into().ok())
                .map(|array| match endian {
                    Endian::Little => <$ty>::from_le_bytes(array),
                    Endian::Big => <$ty>::from_be_bytes(array),
                })
        };
    }
    Values {
        u8: value!(u8),
        i8: value!(i8),
        u16: value!(u16),
        i16: value!(i16),
        u32: value!(u32),
        i32: value!(i32),
        u64: value!(u64),
        i64: value!(i64),
        f32: value!(f32),
        f64: value!(f64),
    }
}

macro_rules! format_float {
    ($name:ident, $ty:ty) => {
        /// Formats non-finite values by name and switches to scientific
        /// notation for very large or very small magnitudes.
        pub fn $name(value: $ty) -> String {
            if value.is_nan() {
                "NaN".to_string()
            } else if value.is_infinite() {
                if value > 0. { "+Infinity" } else { "-Infinity" }.to_string()
            } else if value != 0. && !(1e-5..1e16).contains(&value.abs()) {
                format!("{value:e}")
            } else {
                format!("{value}")
            }
        }
    };
}

format_float!(format_f32, f32);
format_float!(format_f64, f64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Utf8Preview {
    /// The bytes decode as UTF-8. A sequence cut off by the end of the slice
    /// is left out, since the bytes after it may complete it.
    Text(String),
    /// Decoding stops at an invalid byte `offset` bytes in.
    Invalid { text: String, offset: usize },
}

/// Decodes UTF-8 up to the first invalid sequence. Control characters are
/// escaped, e.g. `\u{0}`, so the preview stays on one line.
pub fn utf8_preview(bytes: &[u8]) -> Utf8Preview {
    let (valid, invalid_at) = match std::str::from_utf8(bytes) {
        Ok(text) => (text, None),
        Err(err) => {
            let valid = std::str::from_utf8(&bytes[..err.valid_up_to()]).unwrap_or_default();
            (valid, err.error_len().map(|_| err.valid_up_to()))
        }
    };
    let mut text = String::with_capacity(valid.len());
    for c in valid.chars() {
        if c.is_control() {
            text.extend(c.escape_default());
        } else {
            text.push(c);
        }
    }
    match invalid_at {
        Some(offset) => Utf8Preview::Invalid { text, offset },
        None => Utf8Preview::Text(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_follow_endianness() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let little = interpret(&bytes, Endian::Little);
        let big = interpret(&bytes, Endian::Big);
        assert_eq!(little.u8, Some(1));
        assert_eq!(big.u8, Some(1));
        assert_eq!(little.u16, Some(0x0201));
        assert_eq!(big.u16, Some(0x0102));
        assert_eq!(little.u32, Some(0x0403_0201));
        assert_eq!(big.u32, Some(0x0102_0304));
        assert_eq!(little.u64, Some(0x0807_0605_0403_0201));
        assert_eq!(big.u64, Some(0x0102_0304_0506_0708));
    }

    #[test]
    fn signed_integers_use_twos_complement() {
        let bytes = [0xFF; 8];
        let values = interpret(&bytes, Endian::Little);
        assert_eq!(values.u8, Some(255));
        assert_eq!(values.i8, Some(-1));
        assert_eq!(values.i16, Some(-1));
        assert_eq!(values.u16, Some(u16::MAX));
        assert_eq!(values.i32, Some(-1));
        assert_eq!(values.i64, Some(-1));
        assert_eq!(values.u64, Some(u64::MAX));

        let min = interpret(&[0x80, 0, 0, 0], Endian::Big);
        assert_eq!(min.i8, Some(i8::MIN));
        assert_eq!(min.i32, Some(i32::MIN));
        assert_eq!(min.u32, Some(0x8000_0000));
    }

    #[test]
    fn floats_follow_endianness() {
        let little = interpret(&1.0f32.to_le_bytes(), Endian::Little);
        assert_eq!(little.f32, Some(1.0));
        assert_eq!(little.f64, None);
        let big = interpret(&(-2.5f64).to_be_bytes(), Endian::Big);
        assert_eq!(big.f64, Some(-2.5));
        assert_eq!(big.f32.map(f32::to_bits), Some(0xC004_0000));
    }

    #[test]
    fn short_input_leaves_wider_types_unavailable() {
        let values = interpret(&[0xAB, 0xCD, 0xEF], Endian::Little);
        assert_eq!(values.u8, Some(0xAB));
        assert_eq!(values.u16, Some(0xCDAB));
        assert_eq!(values.u32, None);
        assert_eq!(values.f32, None);
        assert_eq!(values.u64, None);
        assert_eq!(interpret(&[], Endian::Big), Values::default());
    }

    #[test]
    fn formats_floats_including_non_finite_values() {
        assert_eq!(format_f32(1.0), "1");
        assert_eq!(format_f32(0.1), "0.1");
        assert_eq!(format_f64(0.1), "0.1");
        assert_eq!(format_f32(-0.0), "-0");
        assert_eq!(format_f32(f32::NAN), "NaN");
        assert_eq!(format_f64(f64::INFINITY), "+Infinity");
        assert_eq!(format_f64(f64::NEG_INFINITY), "-Infinity");
        assert_eq!(format_f64(1e300), "1e300");
        assert_eq!(format_f32(f32::from_bits(1)), "1e-45");
        let nan_bits = interpret(&[0x00, 0x00, 0xC0, 0x7F], Endian::Little);
        assert!(nan_bits.f32.unwrap().is_nan());
    }

    #[test]
    fn previews_utf8_and_marks_invalid_bytes() {
        assert_eq!(
            utf8_preview("Größe\0".as_bytes()),
            Utf8Preview::Text("Größe\\u{0}".into())
        );
        assert_eq!(
            utf8_preview(b"ab\xFFcd"),
            Utf8Preview::Invalid {
                text: "ab".into(),
                offset: 2
            }
        );
        assert_eq!(
            utf8_preview(b"\x80"),
            Utf8Preview::Invalid {
                text: String::new(),
                offset: 0
            }
        );
        // "é" cut after its first byte by the end of the slice.
        assert_eq!(utf8_preview(b"caf\xC3"), Utf8Preview::Text("caf".into()));
        assert_eq!(
            utf8_preview(b"a\tb\n"),
            Utf8Preview::Text("a\\tb\\n".into())
        );
    }
}
