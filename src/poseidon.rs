use std::cmp::min;

use ark_crypto_primitives::crh::poseidon::constraints::{
    CRHGadget, CRHParametersVar, TwoToOneCRHGadget,
};
use ark_crypto_primitives::crh::poseidon::{TwoToOneCRH, CRH};
use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget};
use ark_crypto_primitives::crh::{TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::{
    fields::fp::{AllocatedFp, FpVar},
    R1CSVar,
};
use ark_relations::r1cs::ConstraintSystem;

pub fn mk_poseidon_config<F: PrimeField>(n: usize) -> PoseidonConfig<F> {
    let mut test_rng = ark_std::test_rng();

    let full_rounds = 8; //usize,
    let partial_rounds = 24; //usize,
    let alpha = 31; //u64,
                    // let mds = x; // Vec<Vec<F>>,
                    // let ark = x; // Vec<Vec<F>>,
    let rate = min(4, n - 1); //usize,
    let capacity = n - rate; //usize,

    // assert_eq!(ark.len(), full_rounds + partial_rounds);
    // for item in &ark { assert_eq!(item.len(), rate + capacity); }
    // assert_eq!(mds.len(), rate + capacity);
    // for item in &mds { assert_eq!(item.len(), rate + capacity); }

    let mut mds = vec![vec![]; n];
    // The following way of generating the MDS matrix is incorrect
    // and is only for test purposes.
    for i in 0..n {
        for _ in 0..n {
            mds[i].push(F::rand(&mut test_rng));
        }
    }

    let mut ark = vec![vec![]; full_rounds + 24];
    for i in 0..full_rounds + partial_rounds {
        for _ in 0..n {
            ark[i].push(F::rand(&mut test_rng));
        }
    }
    let params =
        PoseidonConfig::<F>::new(full_rounds, partial_rounds, alpha, mds, ark, rate, capacity);
    params
}

pub fn test_consistency<F: PrimeField + Absorb>(params: PoseidonConfig<F>, n: usize) {
    let mut test_rng = ark_std::test_rng();
    let mut test_a = Vec::new();
    let mut test_b = Vec::new();
    for _ in 0..n {
        test_a.push(F::rand(&mut test_rng));
        test_b.push(F::rand(&mut test_rng));
    }

    let crh_a = CRH::<F>::evaluate(&params, test_a.clone()).unwrap();
    let crh_b = CRH::<F>::evaluate(&params, test_b.clone()).unwrap();
    let crh = TwoToOneCRH::<F>::compress(&params, crh_a, crh_b).unwrap();

    let cs = ConstraintSystem::<F>::new_ref();

    let mut test_a_g = Vec::new();
    let mut test_b_g = Vec::new();

    for elem in test_a.iter() {
        test_a_g.push(FpVar::Var(
            AllocatedFp::<F>::new_witness(cs.clone(), || Ok(elem)).unwrap(),
        ));
    }
    for elem in test_b.iter() {
        test_b_g.push(FpVar::Var(
            AllocatedFp::<F>::new_witness(cs.clone(), || Ok(elem)).unwrap(),
        ));
    }

    let params_g = CRHParametersVar::<F>::new_witness(cs, || Ok(params)).unwrap();
    let crh_a_g = CRHGadget::<F>::evaluate(&params_g, &test_a_g).unwrap();
    let crh_b_g = CRHGadget::<F>::evaluate(&params_g, &test_b_g).unwrap();
    let crh_g = TwoToOneCRHGadget::<F>::compress(&params_g, &crh_a_g, &crh_b_g).unwrap();

    assert_eq!(crh_a, crh_a_g.value().unwrap());
    assert_eq!(crh_b, crh_b_g.value().unwrap());
    assert_eq!(crh, crh_g.value().unwrap());
}

pub fn hash_vec<F: PrimeField + Absorb>(params: PoseidonConfig<F>, v: Vec<F>) {
    let cs = ConstraintSystem::<F>::new_ref();
    let crh_a = CRH::<F>::evaluate(&params, v.clone()).unwrap();
    let mut test_a_g = Vec::new();
    for elem in v.iter() {
        test_a_g.push(FpVar::Var(
            AllocatedFp::<F>::new_witness(cs.clone(), || Ok(elem)).unwrap(),
        ));
    }
    let params_g = CRHParametersVar::<F>::new_witness(cs, || Ok(params)).unwrap();
    let crh_a_g = CRHGadget::<F>::evaluate(&params_g, &test_a_g).unwrap();

    assert_eq!(crh_a, crh_a_g.value().unwrap());
}
