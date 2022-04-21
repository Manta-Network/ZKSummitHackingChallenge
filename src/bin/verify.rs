use anyhow::Result;
use ark_serialize::CanonicalDeserialize;
use clap::Parser;
use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf;
use zk_summit_challenge::prove::Setup;
use zk_summit_challenge::verify::check_solution;

/// Verify ZKP
#[derive(Debug, Parser)]
struct Args {
    /// Path to CSV Data File
    #[clap(long)]
    submissions: PathBuf,
}

#[derive(Deserialize, Debug)]
struct Record {
    proof_hash: String,
    serialized_proof: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let setup = Setup::deserialize(File::open("setup.dat")?)?;
    let mut rdr = csv::Reader::from_reader(File::open(args.submissions)?);
    for result in rdr.deserialize() {
        let record: Record = result?;
        let hash = blake3::Hash::from_hex(&record.proof_hash)?;
        let proof = hex::decode(&record.serialized_proof)?;
        println!("{:?}: {:?}", record, blake3::hash(&proof) == hash && check_solution(&proof, &setup));
    }
    Ok(())
}
