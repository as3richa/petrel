use crate::padding;
use core::marker::PhantomData;

pub trait Digest<R>: Sized {
    fn new() -> Self;
    fn hash(bytes: impl AsRef<[u8]>) -> R;
    fn update(&mut self, bytes: impl AsRef<[u8]>);
    fn chain(self, bytes: impl AsRef<[u8]>) -> Self;
    fn finalize(self) -> R;
    fn finalize_reset(&mut self) -> R;
}

pub trait HashState<R, T>: Clone {
    fn new() -> Self;
    fn step(&self, tuple: T) -> Self;
    fn merge(&self, other: &Self) -> Self;
    fn to_bytes(&self) -> R;
}

macro_rules! schedule_trait {
    ($name:ident, $block_bytes:literal) => {
        pub trait $name: Iterator {
            fn new(block: &[u8; $block_bytes]) -> Self;
        }
    };
}

macro_rules! hash_block_consumer_impl {
    ($name:ident, $schedule_trait:ident, $block_bytes:literal) => {
        struct $name<R, Sch: $schedule_trait, St: HashState<R, Sch::Item>> {
            state: St,
            result: PhantomData<R>,
            schedule: PhantomData<Sch>,
        }

        impl<R, Sch: $schedule_trait, St: HashState<R, Sch::Item>> $name<R, Sch, St> {
            fn new() -> Self {
                Self {
                    state: St::new(),
                    result: PhantomData,
                    schedule: PhantomData,
                }
            }
        }

        impl<R, Sch: $schedule_trait, St: HashState<R, Sch::Item>> padding::BlockConsumer512<R>
            for $name<R, Sch, St>
        {
            fn handle(&mut self, block: &[u8; $block_bytes]) {
                let step =
                    Sch::new(block).fold(self.state.clone(), |state, tuple| state.step(tuple));
                self.state = self.state.merge(&step);
            }

            fn finalize(self) -> R {
                self.state.to_bytes()
            }

            fn finalize_reset(&mut self) -> R {
                let bytes = self.state.to_bytes();
                self.state = St::new();
                bytes
            }
        }
    };
}

schedule_trait!(Schedule512, 64);
hash_block_consumer_impl!(HashBlockConsumer512, Schedule512, 64);

pub struct Digest512<R, Sch: Schedule512, St: HashState<R, Sch::Item>> {
    padder: padding::StreamingPadder512<R, HashBlockConsumer512<R, Sch, St>>,
}

impl<R, Sch: Schedule512, St: HashState<R, Sch::Item>> Digest<R> for Digest512<R, Sch, St> {
    fn new() -> Self {
        Self {
            padder: padding::StreamingPadder512::new(HashBlockConsumer512::<R, Sch, St>::new()),
        }
    }

    fn hash(bytes: impl AsRef<[u8]>) -> R {
        let mut consumer = HashBlockConsumer512::<R, Sch, St>::new();
        padding::pad_bytes_512(&mut consumer, bytes.as_ref());
        consumer.state.to_bytes()
    }

    fn update(&mut self, bytes: impl AsRef<[u8]>) {
        self.padder.feed(bytes.as_ref());
    }

    fn chain(self, bytes: impl AsRef<[u8]>) -> Self {
        Self {
            padder: self.padder.chain(bytes.as_ref()),
        }
    }

    fn finalize(self) -> R {
        self.padder.finalize()
    }

    fn finalize_reset(&mut self) -> R {
        self.padder.finalize_reset()
    }
}
