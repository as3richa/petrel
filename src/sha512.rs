use crate::digest::{Digest1024, HashState, Schedule1024};

#[derive(Clone)]
pub struct SHA512State(u64, u64, u64, u64, u64, u64, u64, u64);

#[allow(clippy::many_single_char_names)]
impl SHA512State {
    fn step(&self, (k, w): (u64, u64)) -> Self {
        fn ch(x: u64, y: u64, z: u64) -> u64 {
            (x & y) ^ (!x & z)
        }

        fn maj(x: u64, y: u64, z: u64) -> u64 {
            (x & y) ^ (x & z) ^ (y & z)
        }

        fn big_sigma_0(x: u64) -> u64 {
            x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
        }

        fn big_sigma_1(x: u64) -> u64 {
            x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
        }

        let Self(a, b, c, d, e, f, g, h) = *self;
        let t1 = h
            .wrapping_add(big_sigma_1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(k)
            .wrapping_add(w);
        let t2 = big_sigma_0(a).wrapping_add(maj(a, b, c));
        Self(t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g)
    }

    fn merge(&self, other: &Self) -> Self {
        let Self(a, b, c, d, e, f, g, h) = *self;
        let Self(a_o, b_o, c_o, d_o, e_o, f_o, g_o, h_o) = *other;
        Self(
            a.wrapping_add(a_o),
            b.wrapping_add(b_o),
            c.wrapping_add(c_o),
            d.wrapping_add(d_o),
            e.wrapping_add(e_o),
            f.wrapping_add(f_o),
            g.wrapping_add(g_o),
            h.wrapping_add(h_o),
        )
    }
}

#[allow(clippy::many_single_char_names)]
impl HashState<[u8; 64], (u64, u64)> for SHA512State {
    fn new() -> Self {
        let a = 0x6a09e667f3bcc908u64;
        let b = 0xbb67ae8584caa73bu64;
        let c = 0x3c6ef372fe94f82bu64;
        let d = 0xa54ff53a5f1d36f1u64;
        let e = 0x510e527fade682d1u64;
        let f = 0x9b05688c2b3e6c1fu64;
        let g = 0x1f83d9abfb41bd6bu64;
        let h = 0x5be0cd19137e2179u64;
        Self(a, b, c, d, e, f, g, h)
    }

    fn step(&self, (k, w): (u64, u64)) -> Self {
        Self::step(self, (k, w))
    }

    fn merge(&self, other: &Self) -> Self {
        Self::merge(self, other)
    }

    fn to_bytes(&self) -> [u8; 64] {
        let Self(a, b, c, d, e, f, g, h) = *self;
        let mut bytes = [0u8; 64];
        for (i, &word) in [a, b, c, d, e, f, g, h].iter().enumerate() {
            bytes[8 * i..8 * (i + 1)].copy_from_slice(&word.to_be_bytes());
        }
        bytes
    }
}

#[allow(clippy::many_single_char_names)]
impl HashState<[u8; 48], (u64, u64)> for SHA512State {
    fn new() -> Self {
        let a = 0xcbbb9d5dc1059ed8u64;
        let b = 0x629a292a367cd507u64;
        let c = 0x9159015a3070dd17u64;
        let d = 0x152fecd8f70e5939u64;
        let e = 0x67332667ffc00b31u64;
        let f = 0x8eb44a8768581511u64;
        let g = 0xdb0c2e0d64f98fa7u64;
        let h = 0x47b5481dbefa4fa4u64;
        Self(a, b, c, d, e, f, g, h)
    }

    fn step(&self, (k, w): (u64, u64)) -> Self {
        Self::step(self, (k, w))
    }

    fn merge(&self, other: &Self) -> Self {
        Self::merge(self, other)
    }

    fn to_bytes(&self) -> [u8; 48] {
        let Self(a, b, c, d, e, f, _, _) = *self;
        let mut bytes = [0u8; 48];
        for (i, &word) in [a, b, c, d, e, f].iter().enumerate() {
            bytes[8 * i..8 * (i + 1)].copy_from_slice(&word.to_be_bytes());
        }
        bytes
    }
}

#[allow(clippy::many_single_char_names)]
impl HashState<[u8; 28], (u64, u64)> for SHA512State {
    fn new() -> Self {
        let a = 0x8c3d37c819544da2u64;
        let b = 0x73e1996689dcd4d6u64;
        let c = 0x1dfab7ae32ff9c82u64;
        let d = 0x679dd514582f9fcfu64;
        let e = 0x0f6d2b697bd44da8u64;
        let f = 0x77e36f7304c48942u64;
        let g = 0x3f9d85a86a1d36c8u64;
        let h = 0x1112e6ad91d692a1u64;
        Self(a, b, c, d, e, f, g, h)
    }

    fn step(&self, (k, w): (u64, u64)) -> Self {
        Self::step(self, (k, w))
    }

    fn merge(&self, other: &Self) -> Self {
        Self::merge(self, other)
    }

    fn to_bytes(&self) -> [u8; 28] {
        let Self(a, b, c, d, _, _, _, _) = *self;
        let mut bytes = [0u8; 28];
        for (i, &word) in [a, b, c].iter().enumerate() {
            bytes[8 * i..8 * (i + 1)].copy_from_slice(&word.to_be_bytes());
        }
        bytes[24..28].copy_from_slice(&d.to_be_bytes()[0..4]);
        bytes
    }
}

#[allow(clippy::many_single_char_names)]
impl HashState<[u8; 32], (u64, u64)> for SHA512State {
    fn new() -> Self {
        let a = 0x22312194fc2bf72cu64;
        let b = 0x9f555fa3c84c64c2u64;
        let c = 0x2393b86b6f53b151u64;
        let d = 0x963877195940eabdu64;
        let e = 0x96283ee2a88effe3u64;
        let f = 0xbe5e1e2553863992u64;
        let g = 0x2b0199fc2c85b8aau64;
        let h = 0x0eb72ddc81c52ca2u64;
        Self(a, b, c, d, e, f, g, h)
    }

    fn step(&self, (k, w): (u64, u64)) -> Self {
        Self::step(self, (k, w))
    }

    fn merge(&self, other: &Self) -> Self {
        Self::merge(self, other)
    }

    fn to_bytes(&self) -> [u8; 32] {
        let Self(a, b, c, d, _, _, _, _) = *self;
        let mut bytes = [0u8; 32];
        for (i, &word) in [a, b, c, d].iter().enumerate() {
            bytes[8 * i..8 * (i + 1)].copy_from_slice(&word.to_be_bytes());
        }
        bytes
    }
}

pub struct SHA512Schedule {
    w: [u64; 80],
    t: usize,
}

impl SHA512Schedule {
    const K: [u64; 80] = [
        0x428a2f98d728ae22u64,
        0x7137449123ef65cdu64,
        0xb5c0fbcfec4d3b2fu64,
        0xe9b5dba58189dbbcu64,
        0x3956c25bf348b538u64,
        0x59f111f1b605d019u64,
        0x923f82a4af194f9bu64,
        0xab1c5ed5da6d8118u64,
        0xd807aa98a3030242u64,
        0x12835b0145706fbeu64,
        0x243185be4ee4b28cu64,
        0x550c7dc3d5ffb4e2u64,
        0x72be5d74f27b896fu64,
        0x80deb1fe3b1696b1u64,
        0x9bdc06a725c71235u64,
        0xc19bf174cf692694u64,
        0xe49b69c19ef14ad2u64,
        0xefbe4786384f25e3u64,
        0x0fc19dc68b8cd5b5u64,
        0x240ca1cc77ac9c65u64,
        0x2de92c6f592b0275u64,
        0x4a7484aa6ea6e483u64,
        0x5cb0a9dcbd41fbd4u64,
        0x76f988da831153b5u64,
        0x983e5152ee66dfabu64,
        0xa831c66d2db43210u64,
        0xb00327c898fb213fu64,
        0xbf597fc7beef0ee4u64,
        0xc6e00bf33da88fc2u64,
        0xd5a79147930aa725u64,
        0x06ca6351e003826fu64,
        0x142929670a0e6e70u64,
        0x27b70a8546d22ffcu64,
        0x2e1b21385c26c926u64,
        0x4d2c6dfc5ac42aedu64,
        0x53380d139d95b3dfu64,
        0x650a73548baf63deu64,
        0x766a0abb3c77b2a8u64,
        0x81c2c92e47edaee6u64,
        0x92722c851482353bu64,
        0xa2bfe8a14cf10364u64,
        0xa81a664bbc423001u64,
        0xc24b8b70d0f89791u64,
        0xc76c51a30654be30u64,
        0xd192e819d6ef5218u64,
        0xd69906245565a910u64,
        0xf40e35855771202au64,
        0x106aa07032bbd1b8u64,
        0x19a4c116b8d2d0c8u64,
        0x1e376c085141ab53u64,
        0x2748774cdf8eeb99u64,
        0x34b0bcb5e19b48a8u64,
        0x391c0cb3c5c95a63u64,
        0x4ed8aa4ae3418acbu64,
        0x5b9cca4f7763e373u64,
        0x682e6ff3d6b2b8a3u64,
        0x748f82ee5defb2fcu64,
        0x78a5636f43172f60u64,
        0x84c87814a1f0ab72u64,
        0x8cc702081a6439ecu64,
        0x90befffa23631e28u64,
        0xa4506cebde82bde9u64,
        0xbef9a3f7b2c67915u64,
        0xc67178f2e372532bu64,
        0xca273eceea26619cu64,
        0xd186b8c721c0c207u64,
        0xeada7dd6cde0eb1eu64,
        0xf57d4f7fee6ed178u64,
        0x06f067aa72176fbau64,
        0x0a637dc5a2c898a6u64,
        0x113f9804bef90daeu64,
        0x1b710b35131c471bu64,
        0x28db77f523047d84u64,
        0x32caab7b40c72493u64,
        0x3c9ebe0a15c9bebcu64,
        0x431d67c49c100d4cu64,
        0x4cc5d4becb3e42b6u64,
        0x597f299cfc657e2au64,
        0x5fcb6fab3ad6faecu64,
        0x6c44198c4a475817u64,
    ];
}

impl Schedule1024 for SHA512Schedule {
    fn new(block: &[u8; 128]) -> Self {
        let mut w = [0u64; 80];

        for (i, w) in w[0..16].iter_mut().enumerate() {
            let base = 8 * i;
            let bytes = [
                block[base],
                block[base + 1],
                block[base + 2],
                block[base + 3],
                block[base + 4],
                block[base + 5],
                block[base + 6],
                block[base + 7],
            ];
            *w = u64::from_be_bytes(bytes);
        }

        fn sigma_0(x: u64) -> u64 {
            x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
        }
        fn sigma_1(x: u64) -> u64 {
            x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
        }

        for i in 16..80 {
            w[i] = sigma_1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(sigma_0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        Self { w, t: 0 }
    }
}

impl Iterator for SHA512Schedule {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        if self.t < 80 {
            let item = (Self::K[self.t], self.w[self.t]);
            self.t += 1;
            Some(item)
        } else {
            None
        }
    }
}

pub type SHA512Digest = Digest1024<[u8; 64], SHA512Schedule, SHA512State>;
pub type SHA384Digest = Digest1024<[u8; 48], SHA512Schedule, SHA512State>;
pub type SHA512x224Digest = Digest1024<[u8; 28], SHA512Schedule, SHA512State>;
pub type SHA512x256Digest = Digest1024<[u8; 32], SHA512Schedule, SHA512State>;
