use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};

pub mod prove;
pub mod verify;

pub const PUZZLE_DESCRIPTION: &str = r#"
The U.S. Department of Defense has run into a serious problem: they have a list of numbers (finite field elements) and they need to know the inverse of each number.  They refuse to explain
why, but they have posted a bounty of 1 trillion USD that can be claimed by anyone able to compute those missing inverses.  Lucky for you, you know about the arkworks library -- an open source
project full of useful algorithms for finite field arithmetic, polynomial algebra, and other useful cryptographic math.  So you call up the DoD and tell them that you have the numbers they 
need and will deliver them as soon as you receive 1 trillion dollars worth of ETH.  They don't believe you, though; they say they want to see the numbers first and they'll pay you after.  Classic
standoff.  What can we do?  Well it turns out that even though the DoD doesn't know how to do basic finite field arithmetic, they do know about SNARKS.  So they agree that if you can send a
cryptographic proof that you solved the problem then they will pay you half the bounty after the proof verifies and the other half after they receive the numbers.  You suspect that they may break
their promise to pay the second half of the bounty, but you figure that even 500 billion USD ain't bad for an afternoon's work.  You agree to their terms.

So here's the challenge: you have been provided with a list of finite field elements.  You must submit a proof that you know the inverses of each of these numbers.  The proving scheme you will
use is described in detail on the Manta Docs webpage -- essentially it's a collection of scalars and elliptic curve points that you could only come up with if you really do know all the inverses.
You will submit this proof to Manta (a blockchain that both you and the DoD know and love for its excellent anonymity and security guarantees) and if it verifies then you will be entered in a 
lottery to determine the winner of the bounty (which, sadly, is considerably less than 1 trillion USD).
"#;

pub trait ConvertBytes {
    fn as_bytes(&self) -> Vec<u8>
    where
        Self: CanonicalSerialize,
    {
        let mut bytes = Vec::new();
        self.serialize(&mut bytes)
            .expect("Vec never fails to accept bytes.");
        bytes
    }

    fn from_bytes(mut bytes: &[u8]) -> Result<Self, SerializationError>
    where
        Self: CanonicalDeserialize,
    {
        Self::deserialize(&mut bytes)
    }
}

impl<T> ConvertBytes for T {}
