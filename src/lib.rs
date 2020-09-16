#![no_std]

mod padding;

pub mod petrel {
    #[derive(Clone)]
    struct SHA1State(u32, u32, u32, u32, u32);

    impl SHA1State {
        fn new() -> SHA1State {
            let h0 = 0x67452301u32;
            let h1 = 0xefcdab89u32;
            let h2 = 0x98badcfeu32;
            let h3 = 0x10325476u32;
            let h4 = 0xc3d2e1f0u32;
            SHA1State(h0, h1, h2, h3, h4)
        }

        fn step(&self, f: fn(u32, u32, u32) -> u32, k: u32, w: u32) -> SHA1State {
            match *self {
                SHA1State(a, b, c, d, e) => {
                    let t = a
                        .rotate_left(5)
                        .wrapping_add(f(b, c, d))
                        .wrapping_add(e)
                        .wrapping_add(k)
                        .wrapping_add(w);
                    SHA1State(t, a, b.rotate_left(30), c, d)
                }
            }
        }

        fn merge(&self, other: &SHA1State) -> SHA1State {
            match (self, other) {
                (SHA1State(a, b, c, d, e), SHA1State(a_o, b_o, c_o, d_o, e_o)) => SHA1State(
                    a.wrapping_add(*a_o),
                    b.wrapping_add(*b_o),
                    c.wrapping_add(*c_o),
                    d.wrapping_add(*d_o),
                    e.wrapping_add(*e_o),
                ),
            }
        }

        fn to_bytes(self) -> [u8; 20] {
            let mut digest = [0; 20];
            match self {
                SHA1State(a, b, c, d, e) => {
                    for (i, x) in [a, b, c, d, e].iter().enumerate() {
                        digest[4 * i..4 * (i + 1)].copy_from_slice(&x.to_be_bytes())
                    }
                }
            }
            digest
        }
    }

    struct SHA1ScheduleIterator {
        w: [u32; 80],
        t: usize,
    }

    impl SHA1ScheduleIterator {
        fn new(block: &[u8; 64]) -> SHA1ScheduleIterator {
            let mut w = [0u32; 80];

            for i in 0..16 {
                let base = 4 * i;
                w[i] = u32::from_be_bytes([
                    block[base],
                    block[base + 1],
                    block[base + 2],
                    block[base + 3],
                ]);
            }

            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }

            SHA1ScheduleIterator { w: w, t: 0 }
        }

        fn ch(x: u32, y: u32, z: u32) -> u32 {
            (x & y) ^ (!x & z)
        }

        fn parity(x: u32, y: u32, z: u32) -> u32 {
            x ^ y ^ z
        }

        fn maj(x: u32, y: u32, z: u32) -> u32 {
            (x & y) ^ (x & z) ^ (y & z)
        }
    }

    impl Iterator for SHA1ScheduleIterator {
        type Item = (fn(u32, u32, u32) -> u32, u32, u32);

        fn next(&mut self) -> Option<Self::Item> {
            if self.t < 80 {
                let (f, k) = if self.t < 20 {
                    (
                        SHA1ScheduleIterator::ch as fn(u32, u32, u32) -> u32,
                        0x5a827999u32,
                    )
                } else if self.t < 40 {
                    (
                        SHA1ScheduleIterator::parity as fn(u32, u32, u32) -> u32,
                        0x6ed9eba1u32,
                    )
                } else if self.t < 60 {
                    (
                        SHA1ScheduleIterator::maj as fn(u32, u32, u32) -> u32,
                        0x8f1bbcdcu32,
                    )
                } else {
                    (
                        SHA1ScheduleIterator::parity as fn(u32, u32, u32) -> u32,
                        0xca62c1d6u32,
                    )
                };
                let w = self.w[self.t];
                self.t += 1;
                Some((f, k, w))
            } else {
                None
            }
        }
    }

    struct StreamingPadder512<State> {
        buffer: [u8; 64],
        len: u64,
        state: State,
        f: fn(&State, &[u8; 64]) -> State,
    }

    impl<State> StreamingPadder512<State> {
        fn new(state: State, f: fn(&State, &[u8; 64]) -> State) -> Self {
            StreamingPadder512 {
                buffer: [0; 64],
                len: 0,
                state,
                f: f,
            }
        }

        fn emit(&mut self) {
            self.state = (self.f)(&self.state, &self.buffer);
        }

        fn update(&mut self, data: impl AsRef<[u8]>) {
            let slice = data.as_ref();
            let buffer_len = (self.len % 64) as usize;

            if buffer_len + slice.len() >= 64 {
                self.buffer[buffer_len..64].copy_from_slice(&slice[0..64 - buffer_len]);
                self.emit();

                for block in slice[64 - buffer_len..].chunks(64) {
                    self.buffer.copy_from_slice(block);
                    if block.len() == 64 {
                        self.emit();
                    }
                }
            } else {
                self.buffer[buffer_len..buffer_len + slice.len()].copy_from_slice(slice)
            }

            self.len += slice.len() as u64;
        }

        fn finalize(mut self) -> State {
            let buffer_len = (self.len % 64) as usize;

            self.buffer[buffer_len] = 0x80;

            if 64 - buffer_len >= 9 {
                for it in &mut self.buffer[buffer_len + 1..56] {
                    *it = 0x00;
                }
            } else {
                for it in &mut self.buffer[buffer_len + 1..64] {
                    *it = 0x00;
                }
                self.emit();
                for it in &mut self.buffer[0..buffer_len + 1] {
                    *it = 0x00;
                }
            }

            self.buffer[56..64].copy_from_slice(&(8 * self.len).to_be_bytes());
            self.emit();

            self.state
        }
    }

    pub struct SHA1Digest {
        padder: StreamingPadder512<SHA1State>,
    }

    impl SHA1Digest {
        pub fn new() -> SHA1Digest {
            SHA1Digest {
                padder: StreamingPadder512::new(SHA1State::new(), |state, block| {
                    let u = SHA1ScheduleIterator::new(block)
                        .fold(state.clone(), |state, (f, k, w)| state.step(f, k, w));
                    state.merge(&u)
                }),
            }
        }

        pub fn update(&mut self, data: impl AsRef<[u8]>) {
            self.padder.update(data);
        }

        pub fn finalize(self) -> [u8; 20] {
            self.padder.finalize().to_bytes()
        }
    }
}
