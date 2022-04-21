use anyhow::Result;
use ark_serialize::CanonicalSerialize;
use std::fs::File;
use zk_summit_challenge::prove::setup;

fn main() -> Result<()> {
    setup(100).serialize(File::create("setup.dat")?)?;
    Ok(())
}
