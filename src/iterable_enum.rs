pub trait IterableEnum {
    fn items() -> Vec<Self>
    where
        Self: Sized;
}
