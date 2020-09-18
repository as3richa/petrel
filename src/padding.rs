use core::marker::PhantomData;
use core::mem::size_of;
use core::ops::{Add, Rem};

macro_rules! counter_impl {
    ($name:ident, $underlying_type:ty) => {
        #[derive(Default, Clone, Copy)]
        struct $name {
            value: $underlying_type,
        }

        impl From<usize> for $name {
            fn from(value: usize) -> Self {
                Self {
                    value: value as $underlying_type,
                }
            }
        }

        impl Into<usize> for $name {
            fn into(self) -> usize {
                self.value as usize
            }
        }

        impl Add<usize> for $name {
            type Output = Self;

            fn add(self, u: usize) -> Self {
                Self {
                    value: self.value + (u as $underlying_type),
                }
            }
        }

        impl Rem<usize> for $name {
            type Output = Self;

            fn rem(self, u: usize) -> Self {
                Self {
                    value: self.value % (u as $underlying_type),
                }
            }
        }

        impl $name {
            fn to_bytes(self) -> [u8; size_of::<$underlying_type>()] {
                self.value.to_be_bytes()
            }
        }
    };
}

counter_impl!(Counter64, u64);
counter_impl!(Counter128, u128);

macro_rules! consumer_trait {
    ($name:ident, $block_bytes:literal) => {
        pub trait $name<Res> {
            fn handle(&mut self, block: &[u8; $block_bytes]);
            fn finalize(self) -> Res;
            fn finalize_reset(&mut self) -> Res;
        }
    };
}

consumer_trait!(BlockConsumer512, 64);
consumer_trait!(BlockConsumer1024, 128);

macro_rules! padding_fn {
    ($name:ident, $block_bytes:literal, $counter_type:ty, $consumer_trait:ident) => {
        pub fn $name<Res, Consumer: $consumer_trait<Res>>(consumer: &mut Consumer, bytes: &[u8]) {
            let mut buffer = [0u8; $block_bytes];

            for block in bytes.chunks(64) {
                if block.len() < 64 {
                    break;
                }
                buffer[0..$block_bytes].copy_from_slice(block);
                consumer.handle(&buffer);
            }

            let tail = &bytes[bytes.len() - bytes.len() % $block_bytes..];
            assert!(tail.len() < $block_bytes);

            buffer[0..tail.len()].copy_from_slice(&tail);
            buffer[tail.len()] = 0x80u8;

            let counter_bytes = <$counter_type>::from(bytes.len()).to_bytes();

            if tail.len() + 1 + counter_bytes.len() > $block_bytes {
                consumer.handle(&buffer);
                for byte in buffer[0..tail.len() + 1].iter_mut() {
                    *byte = 0;
                }
            }

            let counter_pos = $block_bytes - counter_bytes.len();
            buffer[counter_pos..].copy_from_slice(&counter_bytes);
        }
    };
}

padding_fn!(pad_bytes_512, 64, Counter64, BlockConsumer512);
padding_fn!(pad_bytes_1024, 128, Counter128, BlockConsumer1024);

macro_rules! padder_impl {
    ($name:ident, $block_bytes:literal, $counter_type:ty, $consumer_trait:ident, $pad_fn:ident) => {
        pub struct $name<Res, Consumer: $consumer_trait<Res>> {
            buffer: [u8; $block_bytes],
            len: $counter_type,
            consumer: Consumer,
            res: PhantomData<Res>,
        }

        impl<Res, Consumer: $consumer_trait<Res>> $name<Res, Consumer> {
            pub fn new(consumer: Consumer) -> Self {
                Self {
                    buffer: [0u8; $block_bytes],
                    len: <$counter_type>::default(),
                    consumer,
                    res: PhantomData,
                }
            }

            pub fn feed(&mut self, bytes: &[u8]) {
                let buffer_len = self.buffer_len();

                if buffer_len + bytes.len() < $block_bytes {
                    self.buffer[buffer_len..buffer_len + bytes.len()].copy_from_slice(bytes);
                } else {
                    self.buffer[buffer_len..$block_bytes]
                        .copy_from_slice(&bytes[0..$block_bytes - buffer_len]);
                    self.consumer.handle(&self.buffer);

                    for block in bytes[$block_bytes - buffer_len..].chunks($block_bytes) {
                        if block.len() == $block_bytes {
                            self.buffer[0..$block_bytes].copy_from_slice(block);
                            self.consumer.handle(&self.buffer);
                        } else {
                            self.buffer[0..block.len()].copy_from_slice(block);
                        }
                    }
                }

                self.len = self.len + bytes.len();
            }

            pub fn chain(mut self, bytes: &[u8]) -> Self {
                self.feed(bytes);
                self
            }

            pub fn finalize(mut self) -> Res {
                let buffer_len = self.buffer_len();
                $pad_fn(&mut self.consumer, &self.buffer[0..buffer_len]);
                self.consumer.finalize()
            }

            pub fn finalize_reset(&mut self) -> Res {
                let buffer_len = self.buffer_len();
                $pad_fn(&mut self.consumer, &self.buffer[0..buffer_len]);
                self.len = <$counter_type>::default();
                self.consumer.finalize_reset()
            }

            fn buffer_len(&self) -> usize {
                (self.len % $block_bytes).into()
            }
        }
    };
}

padder_impl!(Padder512, 64, Counter64, BlockConsumer512, pad_bytes_512);
padder_impl!(
    Padder1024,
    128,
    Counter128,
    BlockConsumer1024,
    pad_bytes_1024
);
