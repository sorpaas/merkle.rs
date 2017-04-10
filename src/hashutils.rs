use crypto::sha3::Sha3;
use crypto::digest::Digest;

/// The type of values stored in a `MerkleTree` must implement
/// this trait, in order for them to be able to be fed
/// to a Ring `Context` when computing the hash of a leaf.
///
/// A default instance for types that already implements
/// `AsRef<[u8]>` is provided.
///
/// ## Example
///
/// Here is an example of how to implement `Hashable` for a type
/// that does not (or cannot) implement `AsRef<[u8]>`:
///
/// ```ignore
/// impl Hashable for PublicKey {
///     fn update_context(&self, context: &mut Context) {
///         let bytes: Vec<u8> = self.to_bytes();
///         context.update(&bytes);
///     }
/// }
/// ```
pub trait Hashable {

    /// Update the given `context` with `self`.
    ///
    /// See `ring::digest::Context::update` for more information.
    fn update_context(&self, context: &mut Sha3);

}

impl <T: AsRef<[u8]>> Hashable for T {

    fn update_context(&self, context: &mut Sha3) {
        context.input(self.as_ref());
    }
}

/// The sole purpose of this trait is to extend the standard
/// `ring::algo::Algorithm` type with a couple utility functions.
pub trait HashUtils<U: AsRef<[u8]>> {

    /// Compute the hash of the empty string
    fn hash_empty(self) -> U;

    /// Compute the hash of the given leaf
    fn hash_leaf<T>(self, bytes: &T) -> U where T: Hashable;

    /// Compute the hash of the concatenation of `left` and `right`.
    // XXX: This is overly generic temporarily to make refactoring easier.
    // TODO: Give `left` and `right` type &Digest.
    fn hash_nodes<T>(self, left: &T, right: &T) -> U where T: Hashable;
}

impl<H: From<[u8; 32]> + AsRef<[u8]>> HashUtils<H> for Sha3 {
    fn hash_empty(mut self) -> H {
        let mut r: [u8; 32] = [0u8; 32];
        self.reset();
        self.input(&[]);
        self.result(&mut r);
        r.into()
    }

    fn hash_leaf<T>(mut self, bytes: &T) -> H where T: Hashable {
        let mut r: [u8; 32] = [0u8; 32];
        self.reset();
        bytes.update_context(&mut self);
        self.result(&mut r);
        r.into()
    }

    fn hash_nodes<T>(mut self, left: &T, right: &T) -> H where T: Hashable {
        let mut r: [u8; 32] = [0u8; 32];
        self.reset();
        left.update_context(&mut self);
        right.update_context(&mut self);
        self.result(&mut r);
        r.into()
    }
}
