use crate::digest::{Digest512, HashState, Schedule512};

#[derive(Clone)]
pub struct SHA256State(u32, u32, u32, u32, u32, u32, u32, u32);

#[allow(clippy::many_single_char_names)]
impl SHA256State {
    pub fn step(&self, (k, w): (u32, u32)) -> SHA256State {
        let SHA256State(a, b, c, d, e, f, g, h) = *self;

        fn ch(x: u32, y: u32, z: u32) -> u32 {
            (x & y) ^ (!x & z)
        }

        fn maj(x: u32, y: u32, z: u32) -> u32 {
            (x & y) ^ (x & z) ^ (y & z)
        }

        fn big_sigma_0(x: u32) -> u32 {
            x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
        }

        fn big_sigma_1(x: u32) -> u32 {
            x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
        }

        let t1 = h
            .wrapping_add(big_sigma_1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(k)
            .wrapping_add(w);
        let t2 = big_sigma_0(a).wrapping_add(maj(a, b, c));
        SHA256State(t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g)
    }

    fn merge(&self, other: &SHA256State) -> SHA256State {
        let SHA256State(a, b, c, d, e, f, g, h) = *self;
        let SHA256State(a_o, b_o, c_o, d_o, e_o, f_o, g_o, h_o) = *other;
        SHA256State(
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
impl HashState<[u8; 32], (u32, u32)> for SHA256State {
    fn new() -> SHA256State {
        let a = 0x6a09e667u32;
        let b = 0xbb67ae85u32;
        let c = 0x3c6ef372u32;
        let d = 0xa54ff53au32;
        let e = 0x510e527fu32;
        let f = 0x9b05688cu32;
        let g = 0x1f83d9abu32;
        let h = 0x5be0cd19u32;
        SHA256State(a, b, c, d, e, f, g, h)
    }

    fn step(&self, (k, w): (u32, u32)) -> Self {
        self.step((k, w))
    }

    fn merge(&self, other: &Self) -> Self {
        self.merge(other)
    }

    fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0; 32];
        let SHA256State(a, b, c, d, e, f, g, h) = self;
        for (i, x) in [a, b, c, d, e, f, g, h].iter().enumerate() {
            bytes[4 * i..4 * (i + 1)].copy_from_slice(&x.to_be_bytes())
        }
        bytes
    }
}

#[allow(clippy::many_single_char_names)]
impl HashState<[u8; 28], (u32, u32)> for SHA256State {
    fn new() -> SHA256State {
        let a = 0xc1059ed8u32;
        let b = 0x367cd507u32;
        let c = 0x3070dd17u32;
        let d = 0xf70e5939u32;
        let f = 0xffc00b31u32;
        let e = 0x68581511u32;
        let g = 0x64f98fa7u32;
        let h = 0xbefa4fa4u32;
        SHA256State(a, b, c, d, f, e, g, h)
    }

    fn step(&self, (k, w): (u32, u32)) -> Self {
        self.step((k, w))
    }

    fn merge(&self, other: &Self) -> Self {
        self.merge(other)
    }

    fn to_bytes(&self) -> [u8; 28] {
        let mut bytes = [0u8; 28];
        let SHA256State(a, b, c, d, e, f, g, _) = *self;
        for (i, x) in [a, b, c, d, e, f, g].iter().enumerate() {
            bytes[4 * i..4 * (i + 1)].copy_from_slice(&x.to_be_bytes());
        }
        bytes
    }
}

pub struct SHA256Schedule {
    w: [u32; 64],
    t: usize,
}

impl SHA256Schedule {
    const K: [u32; 64] = [
        0x428a2f98u32,
        0x71374491u32,
        0xb5c0fbcfu32,
        0xe9b5dba5u32,
        0x3956c25bu32,
        0x59f111f1u32,
        0x923f82a4u32,
        0xab1c5ed5u32,
        0xd807aa98u32,
        0x12835b01u32,
        0x243185beu32,
        0x550c7dc3u32,
        0x72be5d74u32,
        0x80deb1feu32,
        0x9bdc06a7u32,
        0xc19bf174u32,
        0xe49b69c1u32,
        0xefbe4786u32,
        0x0fc19dc6u32,
        0x240ca1ccu32,
        0x2de92c6fu32,
        0x4a7484aau32,
        0x5cb0a9dcu32,
        0x76f988dau32,
        0x983e5152u32,
        0xa831c66du32,
        0xb00327c8u32,
        0xbf597fc7u32,
        0xc6e00bf3u32,
        0xd5a79147u32,
        0x06ca6351u32,
        0x14292967u32,
        0x27b70a85u32,
        0x2e1b2138u32,
        0x4d2c6dfcu32,
        0x53380d13u32,
        0x650a7354u32,
        0x766a0abbu32,
        0x81c2c92eu32,
        0x92722c85u32,
        0xa2bfe8a1u32,
        0xa81a664bu32,
        0xc24b8b70u32,
        0xc76c51a3u32,
        0xd192e819u32,
        0xd6990624u32,
        0xf40e3585u32,
        0x106aa070u32,
        0x19a4c116u32,
        0x1e376c08u32,
        0x2748774cu32,
        0x34b0bcb5u32,
        0x391c0cb3u32,
        0x4ed8aa4au32,
        0x5b9cca4fu32,
        0x682e6ff3u32,
        0x748f82eeu32,
        0x78a5636fu32,
        0x84c87814u32,
        0x8cc70208u32,
        0x90befffau32,
        0xa4506cebu32,
        0xbef9a3f7u32,
        0xc67178f2u32,
    ];
}

impl Schedule512 for SHA256Schedule {
    fn new(block: &[u8; 64]) -> SHA256Schedule {
        let mut w = [0u32; 64];

        for (i, w) in w[0..16].iter_mut().enumerate() {
            let base = 4 * i;
            *w = u32::from_be_bytes([
                block[base],
                block[base + 1],
                block[base + 2],
                block[base + 3],
            ]);
        }

        pub fn sigma_0(x: u32) -> u32 {
            x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
        }

        pub fn sigma_1(x: u32) -> u32 {
            x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
        }

        for i in 16..64 {
            w[i] = sigma_1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(sigma_0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        SHA256Schedule { w, t: 0 }
    }
}

impl Iterator for SHA256Schedule {
    type Item = (u32, u32);

    fn next(&mut self) -> Option<Self::Item> {
        if self.t < 64 {
            let result = Some((Self::K[self.t], self.w[self.t]));
            self.t += 1;
            result
        } else {
            None
        }
    }
}

pub type SHA256Digest = Digest512<[u8; 32], SHA256Schedule, SHA256State>;
pub type SHA224Digest = Digest512<[u8; 28], SHA256Schedule, SHA256State>;
