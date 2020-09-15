macro_rules! counter_trait {
    ($name:ident, $bits:literal) => {
        trait $name {
            fn add(self, addend: usize) -> Self;
            fn mask(self, mask: usize) -> usize;
            fn to_bytes(self) -> [u8; $bits / 8];
        }
    };
}

counter_trait!(Counter64, 64);

impl Counter64 for u64 {
    fn add(self, addend: usize) -> u64 {
        self + (addend as u64)
    }

    fn mask(self, mask: usize) -> usize {
        (self as usize) & mask
    }

    fn to_bytes(self) -> [u8; 8] {
        self.to_be_bytes()
    }
}

macro_rules! block_iterator_impl {
    ($name:ident, $bits:literal) => {
        enum $name<'a> {
            Prepend([u8; $bits / 8], usize, &'a [u8]),
            Chunks(&'a[u8])
        }

        impl<'a> $name<'a> {
            fn prepend(prefix: &[u8], bytes: &'a [u8]) -> Self {
                let mut buffer = [0u8; $bits / 8];
                buffer[0..prefix.len()].copy_from_slice(prefix);
                Self::Prepend(buffer, prefix.len(), bytes)
            }

            fn empty() -> Self {
                Self::Chunks(&[])
            }

            fn next(&mut self, buffer: &mut [u8; $bits/8]) -> bool {
                use $name::{Chunks, Prepend};

                let (more, next) = match *self {
                    Prepend(prefix, len, bytes) =>
                        if len + bytes.len() < $bits / 8 {
                            (false, Prepend(prefix, len, bytes))
                        } else {
                            buffer[0..prefix.len()].copy_from_slice(&prefix[0..len]);
                            buffer[prefix.len()..$bits/8].copy_from_slice(&bytes[0..$bits/8 - prefix.len()]);
                            (true, Chunks(&bytes[$bits/8 - prefix.len()..]))
                        }
                    
                        Chunks(bytes) =>
                            if bytes.len() < $bits / 8 {
                                (false, Chunks(bytes))
                            } else {
                                buffer[0..$bits/8].copy_from_slice(&bytes[0..$bits/8]);
                                (true, Chunks(&bytes[$bits/8..]))
                            }
                };

                *self = next;
                more
            }
        }
    }
}

macro_rules! streaming_padder_impl {
    ($name:ident, $bits:literal, $counter:ty, $block_iter:ty) => {
        pub struct $name {
            buffer: [u8; $bits / 8],
            len: $counter
        }

        impl $name {
            fn feed(&mut self, bytes: &[u8]) -> BlockIterator512 {
                let buffer_len = self.len.mask(($bits / 8) - 1);

                let it = if buffer_len + bytes.len() < $bits / 8 {
                    self.buffer[buffer_len..buffer_len+bytes.len()].copy_from_slice(bytes);
                    <$block_iter>::empty()
                } else {
                    let it = <$block_iter>::prepend(&self.buffer[0..buffer_len], bytes);
                    let tail_len = (buffer_len + bytes.len()) & (($bits / 8) - 1);
                    self.buffer[0..tail_len].copy_from_slice(&bytes[bytes.len() - tail_len..]);
                    it
                };

                self.len.add(bytes.len());
                it
            }
        }
    };
}

block_iterator_impl!(BlockIterator512, 512);
streaming_padder_impl!(StreamingPadder512, 512, u64, BlockIterator512);