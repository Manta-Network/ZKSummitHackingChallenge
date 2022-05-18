use anyhow::Result;
use ark_ff::{BigInteger256, BigInteger};
use ark_ff::FromBytes;
use ark_serialize::CanonicalDeserialize;
use clap::Parser;
use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf;
use zk_summit_challenge::prove::Setup;
use zk_summit_challenge::verify::check_solution;
// use ark_std::vec::Vec;

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
    eth_address: String,
}

fn main() -> Result<()> {
    // The hash we'll compare all others to is the blake3 hash of "MantaNetworkZKSummit"
    let reference_hash = blake3::hash(b"MantaNetworkZKSummit").as_bytes().to_vec();
    let reference_hash_integer: BigInteger256 = FromBytes::read(reference_hash.as_slice())?;
    // These keep track of whose hash is closest to the reference hash.
    // We will choose the winner to be whoever's total hash is closest (in absolute value) to the
    // reference hash.
    // The total hash is computed by hashing together each part of the Record.
    let mut winner_address = vec![0u8];
    let mut least_difference = BigInteger256([u64::MAX; 4]);

    let args = Args::parse();
    let setup = Setup::deserialize(File::open("setup.dat")?)?;
    let mut rdr = csv::Reader::from_reader(File::open(args.submissions)?);
    for result in rdr.deserialize() {
        let record: Record = result?;

        // This hasher is for the lottery
        let mut hasher = blake3::Hasher::new();

        let hash = blake3::Hash::from_hex(&record.proof_hash)?;
        // add the proof hash to hasher
        hasher.update(&hex::decode(&record.proof_hash).unwrap());

        let proof = hex::decode(&record.serialized_proof)?;
        // add the serialized proof to hasher
        hasher.update(&proof);

        let address = hex::decode(&record.eth_address)?;
        // add the eth address to hasher
        hasher.update(&address);

        // Check the solution's validity
        println!(
            "{:?}: {:?}",
            record,
            blake3::hash(&proof) == hash && check_solution(&proof, &setup)
        );
        
        // Compute the total hash, then convert to a BigInteger
        let total_hash = hasher.finalize().as_bytes().to_vec();
        let total_hash_integer: BigInteger256 = FromBytes::read(total_hash.as_slice())?;

        // Check if this total hash is closer to the reference than the previous ones:
        let diff = big_integer_metric(&total_hash_integer, &reference_hash_integer);
        if diff < least_difference {
            winner_address = hex::decode(record.eth_address)?;
            least_difference = diff;
        }
    }

    println!("The winning address is {:?}", hex::encode(winner_address));

    Ok(())
}

/// A function to compute |a-b| for big integers 
pub fn big_integer_metric(a: &BigInteger256, b: &BigInteger256) -> BigInteger256 {
    let mut tmp = *a;
    // if a larger than b, compute a-b
    if !tmp.sub_noborrow(b) {
        tmp
    } else {
        // in this case b is larger than a. 
        let mut tmp = *b;
        tmp.sub_noborrow(a);
        tmp
    }
}

#[test]
pub fn big_integer_metric_test() {
    let four = BigInteger256::from(4u64);
    let ten = BigInteger256::from(10u64);
    let six = BigInteger256::from(6u64);
    assert_eq!(big_integer_metric(&four, &ten), six);
    assert_eq!(big_integer_metric(&ten, &four), six);
}