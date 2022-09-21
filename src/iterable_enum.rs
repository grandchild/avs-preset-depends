//! Add the ability to simple `enum`s to iterate over their variants.

/// An Enum whose variants can be iterated over. This only works for simple Enums whose
/// variants don't have variants themselves, i.e. no enum Foo{ Var(int),  }
pub trait IterableEnum {
    /// Return a vector of all the variants of this enum.
    fn items() -> Vec<Self>
    where
        Self: Sized;
}
