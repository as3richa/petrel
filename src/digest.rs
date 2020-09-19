use crate::padding::{
    pad_bytes_1024, pad_bytes_512, BlockConsumer1024, BlockConsumer512, Padder1024, Padder512,
};
use core::marker::PhantomData;

pub trait Digest<Res> {
    fn new() -> Self;
    fn hash(bytes: impl AsRef<[u8]>) -> Res;
    fn update(&mut self, bytes: impl AsRef<[u8]>);
    fn chain(self, bytes: impl AsRef<[u8]>) -> Self;
    fn finalize(self) -> Res;
    fn finalize_reset(&mut self) -> Res;
}

pub trait HashState<Res, ScheduleTuple>: Clone {
    fn new() -> Self;
    fn step(&self, tuple: ScheduleTuple) -> Self;
    fn merge(&self, other: &Self) -> Self;
    fn to_bytes(&self) -> Res;
}

macro_rules! schedule_trait {
    ($name:ident, $block_bytes:literal) => {
        pub trait $name: Iterator {
            fn new(block: &[u8; $block_bytes]) -> Self;
        }
    };
}

schedule_trait!(Schedule512, 64);
schedule_trait!(Schedule1024, 128);

macro_rules! hash_block_consumer_impl {
    ($name:ident, $block_consumer_trait:ident, $schedule_trait:ident, $block_bytes:literal) => {
        struct $name<Res, Schedule: $schedule_trait, St: HashState<Res, Schedule::Item>> {
            state: St,
            result: PhantomData<Res>,
            schedule: PhantomData<Schedule>,
        }

        impl<Res, Schedule: $schedule_trait, State: HashState<Res, Schedule::Item>>
            $name<Res, Schedule, State>
        {
            fn new() -> Self {
                Self {
                    state: State::new(),
                    result: PhantomData,
                    schedule: PhantomData,
                }
            }
        }

        impl<Res, Schedule: $schedule_trait, State: HashState<Res, Schedule::Item>>
            $block_consumer_trait<Res> for $name<Res, Schedule, State>
        {
            fn handle(&mut self, block: &[u8; $block_bytes]) {
                let step =
                    Schedule::new(block).fold(self.state.clone(), |state, tuple| state.step(tuple));
                self.state = self.state.merge(&step);
            }

            fn finalize(self) -> Res {
                self.state.to_bytes()
            }

            fn finalize_reset(&mut self) -> Res {
                let bytes = self.state.to_bytes();
                self.state = State::new();
                bytes
            }
        }
    };
}

hash_block_consumer_impl!(HashBlockConsumer512, BlockConsumer512, Schedule512, 64);
hash_block_consumer_impl!(HashBlockConsumer1024, BlockConsumer1024, Schedule1024, 128);

macro_rules! digest_impl {
    ($name:ident, $schedule_trait:ident, $padder_type:ident, $consumer_type:ident, $pad_bytes_fn:ident) => {
        pub struct $name<Res, Schedule: $schedule_trait, State: HashState<Res, Schedule::Item>> {
            padder: $padder_type<Res, $consumer_type<Res, Schedule, State>>,
        }

        impl<Res, Schedule: $schedule_trait, State: HashState<Res, Schedule::Item>> Digest<Res>
            for $name<Res, Schedule, State>
        {
            fn new() -> Self {
                Self {
                    padder: $padder_type::new($consumer_type::<Res, Schedule, State>::new()),
                }
            }

            fn hash(bytes: impl AsRef<[u8]>) -> Res {
                let mut consumer = $consumer_type::<Res, Schedule, State>::new();
                $pad_bytes_fn(&mut consumer, bytes.as_ref());
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

            fn finalize(self) -> Res {
                self.padder.finalize()
            }

            fn finalize_reset(&mut self) -> Res {
                self.padder.finalize_reset()
            }
        }
    };
}

digest_impl!(
    Digest512,
    Schedule512,
    Padder512,
    HashBlockConsumer512,
    pad_bytes_512
);
digest_impl!(
    Digest1024,
    Schedule1024,
    Padder1024,
    HashBlockConsumer1024,
    pad_bytes_1024
);
