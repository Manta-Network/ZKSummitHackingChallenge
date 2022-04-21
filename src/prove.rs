#![allow(dead_code, unused_imports)]

use crate::verify;
use crate::verify::ABCProof;
use crate::ConvertBytes;
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::*;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial,
    UVPolynomial,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_serialize::{Read, SerializationError, Write};
use std::ops::{Div, Mul, Neg};

#[derive(CanonicalDeserialize, CanonicalSerialize, Clone)]
pub struct ChallengeData {
    // `b` contains a list of field elements you must prove you
    // know the inverses of.
    b: Vec<Fr>,
}

/// A struct that holds all the constants that
/// are needed for polynomial commitment and
/// the domain used for polynomial interpolation.
#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct Setup {
    pub g1_powers: Vec<G1Affine>,
    pub h: G2Affine,
    pub beta_h: G2Affine,
    pub domain: GeneralEvaluationDomain<Fr>,
    pub challenge_data: ChallengeData,
}

/// Produces constants that are needed for polynomial
/// commitment protocol.  
/// Produces a "domain" which is used for polynomial
/// interpolation. (You should NOT use this function,
/// we used it already to prepare the `setup.dat` file.
/// We're just including it here so you can see how the
/// setup was generated.)
pub fn setup(len: usize) -> Setup {
    let domain: GeneralEvaluationDomain<Fr> = GeneralEvaluationDomain::new(len + 2).unwrap();
    let mut rng = rand::thread_rng();
    let secret_scalar = Fr::rand(&mut rng);
    let secret_powers: Vec<Fr> = (0..domain.size() as u64)
        .map(|p| secret_scalar.pow(&[p, 0, 0, 0]))
        .collect();
    let generator = G1Projective::prime_subgroup_generator();
    let h = G2Projective::prime_subgroup_generator();
    let beta_h = h.mul(secret_scalar.into_repr());
    let kzg_setup: Vec<G1Affine> = secret_powers
        .iter()
        .map(|s| (generator.mul(s.into_repr())).into_affine())
        .collect();
    let challenge_data = ChallengeData {
        b: core::iter::from_fn(|| Some(Fr::rand(&mut rng)))
            .take(len)
            .collect(),
    };
    Setup {
        g1_powers: kzg_setup,
        h: h.into_affine(),
        beta_h: beta_h.into_affine(),
        domain,
        challenge_data,
    }
}

/// Conversion from integer to finite field element
pub fn scalar(n: u64) -> Fr {
    Fr::from(n)
}

/// Given a polynomial and the setup constants, computes
/// the KZG commitment to that polynomial.  This commitment
/// is encoded in a single elliptic curve point.
pub fn commit(p: &DensePolynomial<Fr>, setup: &Setup) -> G1Affine {
    let powers = &setup.g1_powers;
    p.coeffs()
        .iter()
        .zip(powers)
        .map(|(c, p)| p.into_projective().mul(c.into_repr()))
        .sum::<G1Projective>()
        .into_affine()
}

/// Given a vector of finite field elements, computes the
/// interpolation polynomial.  Recall this is the polynomial
/// whose first n values are precisely the elements in the
/// values vector.
pub fn interpolate(values: &[Fr], setup: &Setup) -> DensePolynomial<Fr> {
    let domain = setup.domain;
    DensePolynomial::from_coefficients_vec(domain.ifft(values))
}

/// Evaluate polynomial at given point
pub fn evaluate(poly: &DensePolynomial<Fr>, eval_point: &Fr) -> Fr {
    poly.evaluate(eval_point)
}

/// Produces evidence of `poly` evaluation at `eval_point`
pub fn open(poly: &DensePolynomial<Fr>, eval_point: &Fr, setup: &Setup) -> G1Affine {
    // Compute witness poly
    let divisor = DensePolynomial::from_coefficients_vec(vec![eval_point.neg(), Fr::one()]);
    let value = DensePolynomial::from_coefficients_vec(vec![evaluate(poly, eval_point)]);
    let witness_poly = (poly.clone() + value.neg()).div(&divisor);

    // Compute opening
    commit(&witness_poly, setup)
}

/// Verification of a polynomial commitment and evaluation.
/// (Do not confuse with verification of full proof of
/// knowledge -- that function is called `check_proof`)
pub fn verify(
    setup: &Setup,
    commitment: &G1Affine,
    eval_point: &Fr,
    value: &Fr,
    opening: &G1Affine,
) -> bool {
    let Setup {
        g1_powers,
        h,
        beta_h,
        domain: _,
        ..
    } = setup;
    let g1 = g1_powers[0];
    let inner = commitment.into_projective() - g1.mul(value.into_repr());
    let lhs = Bls12_381::pairing(inner, *h);
    let inner = beta_h.into_projective() - h.mul(eval_point.into_repr());
    let rhs = Bls12_381::pairing(*opening, inner);
    lhs == rhs
}

/// The challenge is to fill in the body of this function in
/// such a way that `check_solution` returns TRUE
pub fn create_proof(setup: &Setup) -> ABCProof {
    todo!("Fill out the challenge solution here!")
}

/// This simulates the Verifier choosing a random
/// challenge point
pub fn get_challenge_point(transcript: &[u8]) -> Fr {
    transcript.iter().map(|p| Fr::from(*p)).sum()
}

/// Prepares your proof to be submitted on-chain by serializing
/// it into bytes.  (You don't need to use this function, it's
/// for the `prove` binary)
pub fn prepare_for_submission(proof: &ABCProof) -> Vec<u8> {
    proof.as_bytes()
}
