use core::marker::PhantomData;

macro_rules! padding_enum_impl {
    ($name:ident, $block_bytes:literal, $counter_bytes:literal) => {
        enum $name {
            PenultimateBlock([u8; $block_bytes], [u8; $counter_bytes]),
            FinalBlock([u8; $block_bytes]),
            Done,
        }

        impl $name {
            fn new(buffer: &[u8], counter: [u8; $counter_bytes]) -> Self {
                assert!(buffer.len() < $block_bytes);

                let mut block = [0u8; $block_bytes];
                block[0..buffer.len()].copy_from_slice(buffer);
                block[buffer.len()] = 0x80u8;

                if buffer.len() + 1 + $counter_bytes <= $block_bytes {
                    for (i, &x) in
                        (($block_bytes - $counter_bytes)..$block_bytes).zip(counter.iter())
                    {
                        block[i] = x;
                    }
                    $name::FinalBlock(block)
                } else {
                    $name::PenultimateBlock(block, counter)
                }
            }

            fn next(&mut self, buffer: &mut [u8; $block_bytes]) -> bool {
                let (more, next) = match self {
                    $name::PenultimateBlock(mut block, counter) => {
                        for (dest, &src) in buffer.iter_mut().zip(block.iter()) {
                            *dest = src;
                        }
                        for b in block[0..$block_bytes - $counter_bytes].iter_mut() {
                            *b = 0;
                        }
                        for (dest, &src) in block[$block_bytes - $counter_bytes..]
                            .iter_mut()
                            .zip(counter.iter())
                        {
                            *dest = src;
                        }
                        (true, $name::FinalBlock(block))
                    }
                    $name::FinalBlock(block) => {
                        for (dest, &src) in buffer.iter_mut().zip(block.iter()) {
                            *dest = src;
                        }
                        (true, $name::Done)
                    }
                    $name::Done => (false, $name::Done),
                };
                *self = next;
                more
            }
        }
    };
}

macro_rules! block_consumer_trait {
    ($name:ident, $block_bytes:literal) => {
        pub trait $name<R> {
            fn handle(&mut self, block: &[u8; $block_bytes]);
            fn finalize(self) -> R;
            fn finalize_reset(&mut self) -> R;
        }
    };
}

macro_rules! streaming_padder_impl {
    ($name:ident, $block_bytes:literal, $bc_trait:ident, $counter_type:ty, $padding_type:ty) => {
        pub struct $name<R, BC: $bc_trait<R>> {
            buffer: [u8; $block_bytes],
            len: $counter_type,
            consumer: BC,
            result_marker: PhantomData<R>,
        }

        impl<R, BC: $bc_trait<R>> $name<R, BC> {
            pub fn new(consumer: BC) -> Self {
                Self {
                    buffer: [0u8; $block_bytes],
                    len: 0 as $counter_type,
                    consumer,
                    result_marker: PhantomData,
                }
            }

            pub fn feed(&mut self, bytes: &[u8]) {
                let buffer_len = (self.len & ($block_bytes - 1)) as usize;

                if buffer_len + bytes.len() < $block_bytes {
                    self.buffer[buffer_len..buffer_len + bytes.len()].copy_from_slice(bytes);
                } else {
                    self.buffer[buffer_len..$block_bytes]
                        .copy_from_slice(&bytes[0..$block_bytes - buffer_len]);
                    self.consumer.handle(&self.buffer);

                    let tail = &bytes[$block_bytes - buffer_len..];
                    for block_start in (0..)
                        .map(|i| $block_bytes * i)
                        .take_while(|i| i + $block_bytes <= tail.len())
                    {
                        self.buffer[0..$block_bytes]
                            .copy_from_slice(&tail[block_start..block_start + $block_bytes]);
                        self.consumer.handle(&self.buffer);
                    }

                    self.buffer[0..tail.len() % $block_bytes]
                        .copy_from_slice(&tail[tail.len() - tail.len() % $block_bytes..]);
                }

                self.len += bytes.len() as $counter_type;
            }

            pub fn chain(mut self, bytes: &[u8]) -> Self {
                self.feed(bytes);
                self
            }

            pub fn finalize(mut self) -> R {
                self.handle_final_blocks();
                self.consumer.finalize()
            }

            pub fn finalize_reset(&mut self) -> R {
                self.handle_final_blocks();
                self.len = 0;
                self.consumer.finalize_reset()
            }

            fn handle_final_blocks(&mut self) {
                let buffer_len = (self.len & ($block_bytes - 1)) as usize;
                let mut it =
                    <$padding_type>::new(&self.buffer[0..buffer_len], (8 * self.len).to_be_bytes());

                while it.next(&mut self.buffer) {
                    self.consumer.handle(&self.buffer);
                }
            }
        }
    };
}

macro_rules! padding_fn {
    ($name:ident, $block_bytes:literal, $bc_trait:ident, $counter_type:ty, $padding_type:ty) => {
        pub fn $name<R, BC: $bc_trait<R>>(consumer: &mut BC, bytes: &[u8]) {
            let mut buffer = [0u8; $block_bytes];

            for block_start in (0..)
                .map(|i| i * $block_bytes)
                .take_while(|i| i + $block_bytes <= bytes.len())
            {
                buffer[0..$block_bytes]
                    .copy_from_slice(&bytes[block_start..block_start + $block_bytes]);
                consumer.handle(&buffer);
            }

            let tail = &bytes[bytes.len() - bytes.len() % $block_bytes..];
            let mut it =
                <$padding_type>::new(tail, ((8 * bytes.len()) as $counter_type).to_be_bytes());

            while it.next(&mut buffer) {
                consumer.handle(&buffer);
            }
        }
    };
}

padding_enum_impl!(Padding512, 64, 8);
block_consumer_trait!(BlockConsumer512, 64);
streaming_padder_impl!(StreamingPadder512, 64, BlockConsumer512, u64, Padding512);
padding_fn!(pad_bytes_512, 64, BlockConsumer512, u64, Padding512);

padding_enum_impl!(Padding1024, 128, 16);
block_consumer_trait!(BlockConsumer1024, 128);
streaming_padder_impl!(
    StreamingPadder1024,
    128,
    BlockConsumer1024,
    u128,
    Padding1024
);
padding_fn!(pad_bytes_1024, 128, BlockConsumer1024, u128, Padding1024);
