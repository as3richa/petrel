trait Counter {
    fn new() -> Self;
    fn from_usize(value: usize) -> Self;
    fn increment(self, value: usize) -> Self;
    fn bitwise_and(self, mask: usize) -> usize;
}

#[derive(Clone, Copy)]
struct Counter64(u64);

impl Counter for Counter64 {
    fn new() -> Counter64 {
        Counter64(0)
    }

    fn from_usize(value: usize) -> Counter64 {
        Counter64(value as u64)
    }

    fn increment(self, value: usize) -> Counter64 {
        Counter64(self.0 + (value as u64))
    }

    fn bitwise_and(self, mask: usize) -> usize {
        (self.0 as usize) & mask
    }
}

enum Padding512 {
    FinalBlock([u8; 64]),
    PaddingBlock([u8; 64], [u8; 8]),
}

impl Counter64 {
    fn pad_final_block(self, buffer: &[u8]) -> Padding512 {
        assert!(buffer.len() < 64);

        let mut block = [0u8; 64];
        block[0..buffer.len()].copy_from_slice(buffer);
        block[buffer.len()] = 0x80u8;

        if buffer.len() <= 55 {
            for (i, &x) in (56..64).zip(self.0.to_be_bytes().iter()) {
                block[i] = x;
            }
            Padding512::FinalBlock(block)
        } else {
            Padding512::PaddingBlock(block, self.0.to_be_bytes())
        }
    }
}

trait BlockIterator512 {
    fn next(&mut self, block: &mut [u8; 64]) -> bool;
}

impl BlockIterator512 for Option<Padding512> {
    fn next(&mut self, buffer: &mut [u8; 64]) -> bool {
        let more = self.is_some();
        *self = match self {
            Some(Padding512::FinalBlock(block)) => {
                for (dest, src) in buffer.iter_mut().zip(block.iter()) {
                    *dest = *src;
                }
                None
            }
            Some(Padding512::PaddingBlock(mut block, counter_bytes)) => {
                for (dest, src) in buffer.iter_mut().zip(block.iter()) {
                    *dest = *src;
                }
                for i in 0..56 {
                    block[i] = 0;
                }
                for i in 0..8 {
                    block[56 + i] = counter_bytes[i];
                }
                Some(Padding512::FinalBlock(block))
            }
            None => None,
        };
        more
    }
}

trait BlockConsumer512<R> {
    fn handle(&mut self, block: &[u8; 64]);
    fn finalize(self) -> R;
    fn finalize_reset(&mut self) -> R;
}

use core::marker::PhantomData;

struct StreamingPadder512<R, BC: BlockConsumer512<R>> {
    buffer: [u8; 64],
    len: Counter64,
    consumer: BC,
    result_marker: PhantomData<R>,
}

impl<R, BC: BlockConsumer512<R>> StreamingPadder512<R, BC> {
    fn new(consumer: BC) -> Self {
        Self {
            buffer: [0u8; 64],
            len: Counter64::new(),
            consumer: consumer,
            result_marker: PhantomData
        }
    }

    fn feed(&mut self, bytes: &[u8]) {
        let buffer_len = self.len.bitwise_and(64 - 1);

        if buffer_len + bytes.len() < 64 {
            self.buffer[buffer_len..buffer_len+bytes.len()].copy_from_slice(bytes);
        } else {
            self.buffer[buffer_len..64].copy_from_slice(&bytes[0..64-buffer_len]);
            self.consumer.handle(&self.buffer);
            
            let tail = &bytes[64-buffer_len..];
            for block_start in (1..).map(|i| 64 * i).take_while(|i| i < &tail.len()) {
                self.buffer[0..64].copy_from_slice(&tail[block_start..block_start + 64]);
                self.consumer.handle(&self.buffer);
            }

            self.buffer[0..tail.len() % 64].copy_from_slice(&tail[tail.len() - tail.len() % 64..]);
        }

        self.len = self.len.increment(bytes.len());
    }

    fn finalize(mut self) -> R {
        self.handle_final_blocks();
        self.consumer.finalize()
    }

    fn finalize_reset(&mut self) -> R {
        self.handle_final_blocks();
        self.consumer.finalize_reset()
    }

    fn handle_final_blocks(&mut self) {
        let buffer_len = self.len.bitwise_and(64 - 1);
        let mut it = Some(self.len.pad_final_block(&self.buffer[0..buffer_len]));

        while it.next(&mut self.buffer) {
            self.consumer.handle(&self.buffer);
        }
    }
}

/*


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
            Chunks(&'a [u8]),
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

            fn next(&mut self, buffer: &mut [u8; $bits / 8]) -> bool {
                use $name::{Chunks, Prepend};

                let (more, next) = match *self {
                    Prepend(prefix, len, bytes) => {
                        if len + bytes.len() < $bits / 8 {
                            (false, Prepend(prefix, len, bytes))
                        } else {
                            buffer[0..prefix.len()].copy_from_slice(&prefix[0..len]);
                            buffer[prefix.len()..$bits / 8]
                                .copy_from_slice(&bytes[0..$bits / 8 - prefix.len()]);
                            (true, Chunks(&bytes[$bits / 8 - prefix.len()..]))
                        }
                    }

                    Chunks(bytes) => {
                        if bytes.len() < $bits / 8 {
                            (false, Chunks(bytes))
                        } else {
                            buffer[0..$bits / 8].copy_from_slice(&bytes[0..$bits / 8]);
                            (true, Chunks(&bytes[$bits / 8..]))
                        }
                    }
                };

                *self = next;
                more
            }
        }
    };
}

macro_rules! streaming_padder_impl {
    ($name:ident, $bits:literal, $counter:ty, $block_iter:ident) => {
        pub struct $name {
            buffer: [u8; $bits / 8],
            len: $counter,
        }

        impl $name {
            fn feed<'a>(&mut self, bytes: &'a [u8]) -> $block_iter<'a> {
                let buffer_len = self.len.mask(($bits / 8) - 1);

                let it = if buffer_len + bytes.len() < $bits / 8 {
                    self.buffer[buffer_len..buffer_len + bytes.len()].copy_from_slice(bytes);
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

            fn chain<'a>(mut self, bytes: &'a [u8]) -> (Self, $block_iter<'a>) {
                let it = self.feed(bytes);
                (self, it)
            }

            fn finalize(mut self) -> $block_iter {


            }
        }
    };
}

block_iterator_impl!(BlockIterator512, 512);
streaming_padder_impl!(StreamingPadder512, 512, u64, BlockIterator512);

*/
