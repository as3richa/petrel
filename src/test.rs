#[cfg(test)]
mod test {
    fn hex_str_to_bytes(hex_str: &str) -> Vec<u8> {
        fn parse_hex_digit(digit: u8) -> u8 {
            if 0x30 <= digit && digit <= 0x39 {
                digit - 0x30
            } else if 0x61 <= digit && digit <= 0x66 {
                digit + 10 - 0x61
            } else {
                panic!();
            }
        }

        hex_str
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                pair.iter()
                    .fold(0u8, |value, &digit| 16 * value + parse_hex_digit(digit))
            })
            .collect()
    }

    fn assert_matches(bytes: &[u8], hex_str: &str) {
        assert!(hex_str.len() == 2 * bytes.len());
        assert_eq!(bytes, hex_str_to_bytes(hex_str))
    }

    mod sha1 {
        use super::assert_matches;
        use crate::Digest;
        use crate::SHA1Digest;

        #[test]
        fn adam() {
            assert_matches(
                &SHA1Digest::hash("adam"),
                "0e18f44c1fec03ec4083422cb58ba6a09ac4fb2a",
            );
        }

        #[test]
        fn iggy() {
            let mut digest = SHA1Digest::new();
            digest.update("ignatius");
            assert_matches(
                &digest.finalize(),
                "e21faca29de66a77c4df8f131610a4cba6ee50d9",
            );
        }

        mod sha256 {
            use super::assert_matches;
            use crate::Digest;
            use crate::SHA256Digest;

            #[test]
            fn adam() {
                assert_matches(
                    &SHA256Digest::hash("adam"),
                    "f7f376a1fcd0d0e11a10ed1b6577c99784d3a6bbe669b1d13fae43eb64634f6e",
                );
            }

            #[test]
            fn iggy() {
                let mut digest = SHA256Digest::new();
                digest.update("ignatius");
                assert_matches(
                    &digest.finalize(),
                    "ef5d04df6b1b3e76c6c63acea484151e2f469eace1d1a8f6d0ae28751e1e427d",
                );
            }
        }
    }
}
