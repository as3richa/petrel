#[cfg(test)]
mod test {
    use crate::{
        Digest, SHA1Digest, SHA224Digest, SHA256Digest, SHA384Digest, SHA512Digest,
        SHA512x224Digest, SHA512x256Digest,
    };

    use rand::RngCore;
    use std::fs::{read, File};
    use std::io::{BufRead, BufReader};

    const ALGORITHMS: [&str; 7] = [
        "SHA1",
        "SHA256",
        "SHA224",
        "SHA512",
        "SHA384",
        "SHA512/224",
        "SHA512/256",
    ];

    fn hex_str_to_bytes(hex_str: &str) -> Vec<u8> {
        assert!(hex_str.len() % 2 == 0);

        fn hex_digit_to_byte(digit: u8) -> u8 {
            if 0x30 <= digit && digit <= 0x39 {
                digit - 0x30
            } else if 0x61 <= digit && digit <= 0x66 {
                10 + digit - 0x61
            } else {
                panic!()
            }
        }

        hex_str
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                pair.iter()
                    .fold(0u8, |sum, &digit| 16 * sum + hex_digit_to_byte(digit))
            })
            .collect::<Vec<u8>>()
    }

    fn check_digest<Res: Into<Vec<u8>>, D: Digest<Res>>(bytes: &[u8], expectation: &[u8]) {
        assert_eq!(D::hash(bytes).into(), expectation);
        assert_eq!(D::new().chain(bytes).finalize().into(), expectation);

        let mut d1 = D::new();
        d1.update(bytes);
        assert_eq!(d1.finalize().into(), expectation);

        let mut d2 = D::new();
        d2.update(bytes);
        assert_eq!(d2.finalize_reset().into(), expectation);
        d2.update(bytes);
        assert_eq!(d2.finalize_reset().into(), expectation);

        fn dice_bytes(bytes: &[u8]) -> Vec<&[u8]> {
            if bytes.is_empty() {
                return vec![];
            }

            let mut rng = rand::thread_rng();
            let index = bytes.len() - 1 - (rng.next_u64() as usize) % bytes.len();
            let mut diced = dice_bytes(&bytes[0..index]);
            diced.push(&bytes[index..]);
            diced
        }

        let diced = dice_bytes(bytes);

        let mut d3 = D::new();
        for seg in diced.clone() {
            d3.update(seg);
        }
        assert_eq!(d3.finalize().into(), expectation);

        let d4 = diced.iter().fold(D::new(), |d, seg| d.chain(seg));
        assert_eq!(d4.finalize().into(), expectation);
    }

    #[test]
    fn words() {
        let file = File::open("gen/data/word-hashes.list").unwrap();
        let mut it = BufReader::new(file).lines().map(|line| line.unwrap());

        let line = it.next().unwrap();
        let header = line.split("\t").collect::<Vec<&str>>();
        assert_eq!(header[0], "word");
        assert_eq!(&header[1..8], &ALGORITHMS);

        for line in it {
            let case = line.split("\t").collect::<Vec<&str>>();
            let bytes = case[0].as_bytes();
            check_digest::<[u8; 20], SHA1Digest>(bytes, &hex_str_to_bytes(case[1]));
            check_digest::<[u8; 32], SHA256Digest>(bytes, &hex_str_to_bytes(case[2]));
            check_digest::<[u8; 28], SHA224Digest>(bytes, &hex_str_to_bytes(case[3]));
            check_digest::<[u8; 64], SHA512Digest>(bytes, &hex_str_to_bytes(case[4]));
            check_digest::<[u8; 48], SHA384Digest>(bytes, &hex_str_to_bytes(case[5]));
            check_digest::<[u8; 28], SHA512x224Digest>(bytes, &hex_str_to_bytes(case[6]));
            check_digest::<[u8; 32], SHA512x256Digest>(bytes, &hex_str_to_bytes(case[7]));
        }
    }

    #[test]
    fn blobs() {
        let file = File::open("gen/data/blob-hashes.list").unwrap();
        let mut it = BufReader::new(file).lines().map(|line| line.unwrap());

        let line = it.next().unwrap();
        let header = line.split("\t").collect::<Vec<&str>>();
        assert_eq!(header[0], "filename");
        assert_eq!(&header[1..8], &ALGORITHMS);

        for line in it {
            let case = line.split("\t").collect::<Vec<&str>>();
            let filename = "gen/data/".to_owned() + case[0];
            let bytes = &read(filename).unwrap();
            check_digest::<[u8; 20], SHA1Digest>(bytes, &hex_str_to_bytes(case[1]));
            check_digest::<[u8; 32], SHA256Digest>(bytes, &hex_str_to_bytes(case[2]));
            check_digest::<[u8; 28], SHA224Digest>(bytes, &hex_str_to_bytes(case[3]));
            check_digest::<[u8; 64], SHA512Digest>(bytes, &hex_str_to_bytes(case[4]));
            check_digest::<[u8; 48], SHA384Digest>(bytes, &hex_str_to_bytes(case[5]));
            check_digest::<[u8; 28], SHA512x224Digest>(bytes, &hex_str_to_bytes(case[6]));
            check_digest::<[u8; 32], SHA512x256Digest>(bytes, &hex_str_to_bytes(case[7]));
        }
    }
}
