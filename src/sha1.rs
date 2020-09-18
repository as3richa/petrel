use crate::digest::{Digest512, HashState, Schedule512};

#[derive(Clone)]
pub struct SHA1State(u32, u32, u32, u32, u32);

type SHA1Function = fn(u32, u32, u32) -> u32;

#[allow(clippy::many_single_char_names)]
impl HashState<[u8; 20], (SHA1Function, u32, u32)> for SHA1State {
    fn new() -> SHA1State {
        let h0 = 0x67452301u32;
        let h1 = 0xefcdab89u32;
        let h2 = 0x98badcfeu32;
        let h3 = 0x10325476u32;
        let h4 = 0xc3d2e1f0u32;
        SHA1State(h0, h1, h2, h3, h4)
    }

    fn step(&self, (f, k, w): (SHA1Function, u32, u32)) -> SHA1State {
        let SHA1State(a, b, c, d, e) = *self;
        let t = a
            .rotate_left(5)
            .wrapping_add(f(b, c, d))
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w);
        SHA1State(t, a, b.rotate_left(30), c, d)
    }

    fn merge(&self, other: &SHA1State) -> SHA1State {
        let SHA1State(a, b, c, d, e) = self;
        let SHA1State(a_o, b_o, c_o, d_o, e_o) = other;
        SHA1State(
            a.wrapping_add(*a_o),
            b.wrapping_add(*b_o),
            c.wrapping_add(*c_o),
            d.wrapping_add(*d_o),
            e.wrapping_add(*e_o),
        )
    }

    fn to_bytes(&self) -> [u8; 20] {
        let mut bytes = [0; 20];
        let SHA1State(a, b, c, d, e) = self;
        for (i, x) in [a, b, c, d, e].iter().enumerate() {
            bytes[4 * i..4 * (i + 1)].copy_from_slice(&x.to_be_bytes())
        }
        bytes
    }
}

pub struct SHA1Schedule {
    w: [u32; 80],
    t: usize,
}

impl Schedule512 for SHA1Schedule {
    fn new(block: &[u8; 64]) -> SHA1Schedule {
        let mut w = [0u32; 80];

        for (i, w) in w[0..16].iter_mut().enumerate() {
            let base = 4 * i;
            *w = u32::from_be_bytes([
                block[base],
                block[base + 1],
                block[base + 2],
                block[base + 3],
            ]);
        }

        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        SHA1Schedule { w, t: 0 }
    }
}

impl Iterator for SHA1Schedule {
    type Item = (SHA1Function, u32, u32);

    fn next(&mut self) -> Option<Self::Item> {
        fn ch(x: u32, y: u32, z: u32) -> u32 {
            (x & y) ^ (!x & z)
        }

        fn parity(x: u32, y: u32, z: u32) -> u32 {
            x ^ y ^ z
        }

        fn maj(x: u32, y: u32, z: u32) -> u32 {
            (x & y) ^ (x & z) ^ (y & z)
        }

        if self.t < 80 {
            let (f, k) = if self.t < 20 {
                (ch as SHA1Function, 0x5a827999u32)
            } else if self.t < 40 {
                (parity as SHA1Function, 0x6ed9eba1u32)
            } else if self.t < 60 {
                (maj as SHA1Function, 0x8f1bbcdcu32)
            } else {
                (parity as SHA1Function, 0xca62c1d6u32)
            };
            let w = self.w[self.t];
            self.t += 1;
            Some((f, k, w))
        } else {
            None
        }
    }
}

pub type SHA1Digest = Digest512<[u8; 20], SHA1Schedule, SHA1State>;
