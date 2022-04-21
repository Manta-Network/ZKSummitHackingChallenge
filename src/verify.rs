use crate::prove::*;
use crate::ConvertBytes;
use ark_bls12_381::{Fr, G1Affine};
use ark_poly::EvaluationDomain;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_serialize::{Read, SerializationError, Write};

/// The type of an a*b = c proof.
#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct ABCProof {
    pub comm_a: G1Affine,
    pub comm_b: G1Affine,
    pub comm_c: G1Affine,
    pub comm_q: G1Affine,
    pub eval_a: Fr,
    pub eval_b: Fr,
    pub eval_c: Fr,
    pub eval_q: Fr,
    pub open_a: G1Affine,
    pub open_b: G1Affine,
    pub open_c: G1Affine,
    pub open_q: G1Affine,
}

impl ABCProof {
    /// Function used by Verifier to check the validity of
    /// an a*b = c proof.  
    pub fn verify(&self, setup: &Setup) -> bool {
        // Get challenge point
        let transcript = [
            self.comm_a.as_bytes().as_slice(),
            self.comm_q.as_bytes().as_slice(),
        ]
        .concat();
        let eval_point = get_challenge_point(&transcript);
        // Evaluate vanishing polynomial
        let eval_z = setup.domain.evaluate_vanishing_polynomial(eval_point);
        // Do verification checks
        verify(setup, &self.comm_a, &eval_point, &self.eval_a, &self.open_a)
            && verify(setup, &self.comm_b, &eval_point, &self.eval_b, &self.open_b)
            && verify(setup, &self.comm_c, &eval_point, &self.eval_c, &self.open_c)
            && verify(setup, &self.comm_q, &eval_point, &self.eval_q, &self.open_q)
            && (self.eval_a * self.eval_b - self.eval_c == self.eval_q * eval_z)
    }
}

/// This just deserializes a proof submitted on-chain and
/// verifies it.
pub fn check_solution(serialized_proof: &[u8], setup: &Setup) -> bool {
    let proof = match ABCProof::from_bytes(serialized_proof) {
        Ok(proof) => proof,
        _ => return false,
    };
    proof.verify(setup)
}

// You can use this test to check whether the body of your `create_proof` function
// works correctly.  
#[test]
pub fn verify_proof() {
    use std::fs::File;

    let setup = Setup::deserialize(File::open("setup.dat").expect("")).expect("");
    assert!(check_solution(&create_proof(&setup).as_bytes(), &setup), "")
}