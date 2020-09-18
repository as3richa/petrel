#[cfg(test)]
mod test {
    mod sha1 {
        use crate::sha1;
        use crate::Digest;

        fn assert_matches(bytes: [u8; 20], hex_str: &str) {
            assert!(hex_str.len() == 40);

            fn parse_hex_digit(digit: u8) -> u8 {
                if 0x30 <= digit && digit <= 0x39 {
                    digit - 0x30
                } else if 0x61 <= digit && digit <= 0x66 {
                    digit + 10 - 0x61
                } else {
                    panic!();
                }
            }

            let hex_bytes = hex_str.as_bytes();
            let mut expectation = [0u8; 20];

            for i in 0..20 {
                expectation[i] =
                    16 * parse_hex_digit(hex_bytes[2 * i]) + parse_hex_digit(hex_bytes[2 * i + 1]);
            }

            assert_eq!(bytes, expectation);
        }

        #[test]
        fn adam() {
            assert_matches(
                sha1::SHA1Digest::hash("adam"),
                "0e18f44c1fec03ec4083422cb58ba6a09ac4fb2a",
            );
        }

        #[test]
        fn iggy() {
            let mut digest = sha1::SHA1Digest::new();
            digest.update("ignatius");
            assert_matches(
                digest.finalize(),
                "e21faca29de66a77c4df8f131610a4cba6ee50d9",
            );
        }
    }
}
