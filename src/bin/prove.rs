use anyhow::Result;
use ark_serialize::CanonicalDeserialize;
use std::fs::File;
use zk_summit_challenge::prove::create_proof;
use zk_summit_challenge::prove::Setup;
use zk_summit_challenge::ConvertBytes;

fn main() -> Result<()> {
    let setup = Setup::deserialize(File::open("setup.dat")?)?;
    let proof = create_proof(&setup).as_bytes();
    let hash = blake3::hash(&proof).to_hex();
    println!("hash: {}\nproof: {}", hash, hex::encode(proof));
    Ok(())
}
