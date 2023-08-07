use std::convert::TryInto;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter};

use ark_crypto_primitives::crh::poseidon::constraints::{CRHGadget, CRHParametersVar};
use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::fields::fp::{AllocatedFp, FpVar};
use ark_r1cs_std::{R1CSVar, ToConstraintFieldGadget};
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef};
use ark_relations::r1cs::{ConstraintSystem, SynthesisError};

use ark_crypto_primitives::crh::poseidon::{TwoToOneCRH, CRH};
use ark_r1cs_std::{
    prelude::{AllocVar, Boolean, EqGadget},
    uint8::UInt8,
};
use ark_serialize::{CanonicalSerialize, Compress, SerializationError};
use ark_std::{
    rand::{RngCore, SeedableRng},
    test_rng,
};
use serde::Serialize;

mod alloc;
mod cmp;
mod poseidon;
mod ss_serde;

use crate::cmp::CmpGadget;

type Grid<const N: usize> = [[u8; N]; N];

type GridVar<const N: usize, F> = [[UInt8<F>; N]; N];

#[derive(Clone, Copy, Debug)]
pub struct Puzzle<const N: usize>(pub Grid<N>);

pub fn read_grid<const N: usize>(fp: &str) -> Grid<N> {
    fs::read_to_string(fp)
        .unwrap()
        .split("\n")
        .filter(|row| row.len() > 2)
        .into_iter()
        .map(|row| {
            row.split_whitespace()
                .into_iter()
                .map(|x| x.parse::<u8>().unwrap())
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap_or_else(|v| {
                    println!("wrong size : {:?}", v);
                    panic!("ooops")
                })
        })
        .collect::<Vec<[u8; N]>>()
        .try_into()
        .unwrap_or_else(|v| {
            println!("wrong size : {:?}", v);
            panic!("ooops")
        })
}

pub fn write_grid<const N: usize>(fp: &str, grid: Grid<N>) -> Result<(), std::io::Error> {
    let s = grid
        .into_iter()
        .map(|row| {
            row.into_iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>()
                .join(" ")
        })
        .collect::<Vec<String>>()
        .join("\n");
    fs::write(fp, format!("{}\n", s))
}

#[derive(Clone, Copy, Debug)]
pub struct Solution<const N: usize>(pub Grid<N>);

pub struct PuzzleVar<const N: usize, F: PrimeField>(pub GridVar<N, F>);
pub struct SolutionVar<const N: usize, F: PrimeField>(pub GridVar<N, F>);

#[derive(Clone, Debug)]
pub struct Sudoku<const N: usize, F: PrimeField> {
    pub poseidon_config: PoseidonConfig<F>,
    pub hash: Option<F>,
    pub puzzle: Option<Puzzle<N>>,
    pub solution: Option<Solution<N>>,
}

pub struct PuzSol<const N: usize> {
    pub puzzle: Puzzle<N>,
    pub solution: Solution<N>,
}

impl<const N: usize, F: PrimeField + Absorb> ConstraintSynthesizer<F> for Sudoku<N, F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let puzzle_grid: Grid<N> = self.puzzle.unwrap_or(Puzzle([[0_u8; N]; N])).0;
        let puzzle_var: PuzzleVar<N, F> =
            PuzzleVar::<N, F>::new_witness(cs.clone(), || Ok(puzzle_grid)).unwrap();
        let solution_grid: Grid<N> = self.solution.unwrap_or(Solution([[0_u8; N]; N])).0;
        let solution_var: SolutionVar<N, F> =
            SolutionVar::<N, F>::new_witness(cs.clone(), || Ok(solution_grid)).unwrap();

        // Solution agrees with problem
        for (p_row, s_row) in puzzle_var.0.iter().zip(&solution_var.0) {
            for (p, s) in p_row.iter().zip(s_row) {
                s.is_leq(&UInt8::constant(N as u8))?
                    .and(&s.is_geq(&UInt8::constant(1))?)?
                    .enforce_equal(&Boolean::TRUE)?;
                (p.is_eq(s)?.or(&p.is_eq(&UInt8::constant(0))?)?).enforce_equal(&Boolean::TRUE)?;
            }
        }
        // Solution rows are distinct
        for row in &solution_var.0 {
            for (j, cell) in row.iter().enumerate() {
                for prior_cell in &row[0..j] {
                    cell.is_neq(&prior_cell)?.enforce_equal(&Boolean::TRUE)?;
                }
            }
        }
        // TODO: Add additional constraints

        // Hash puzzle agrees with hash
        let x = puzzle_var
            .0
            .into_iter()
            .flatten()
            .collect::<Vec<UInt8<F>>>()
            .to_constraint_field()?;
        let params_g =
            CRHParametersVar::<F>::new_witness(cs.clone(), || Ok(&self.poseidon_config)).unwrap();
        let hash_gadget = CRHGadget::<F>::evaluate(&params_g, &x).unwrap();

        let hash_var =
            cs.new_input_variable(|| self.hash.ok_or(SynthesisError::AssignmentMissing))?;

        let hash_fp = FpVar::Var(AllocatedFp::new(self.hash, hash_var, cs.clone()));
        let _u = hash_gadget.is_eq(&hash_fp);

        Ok(())
    }
}

pub fn setup<const N: usize, E>(
    poseidon_config: &PoseidonConfig<E::ScalarField>,
) -> (ProvingKey<E>, VerifyingKey<E>)
where
    E: Pairing,
    E::ScalarField: Absorb,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64() + 1);

    Groth16::<E>::setup(
        Sudoku::<N, E::ScalarField> {
            poseidon_config: poseidon_config.clone(),
            hash: None,
            puzzle: None,
            solution: None,
        },
        &mut rng,
    )
    .unwrap()
}

pub fn test_prove_and_verify<E>(poseidon_config: PoseidonConfig<E::ScalarField>)
where
    E: Pairing,
    E::ScalarField: Absorb,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let (pk, vk) = Groth16::<E>::setup(
        Sudoku::<2, E::ScalarField> {
            poseidon_config: poseidon_config.clone(),
            hash: None,
            puzzle: None,
            solution: None,
        },
        &mut rng,
    )
    .unwrap();

    let pvk = prepare_verifying_key::<E>(&vk);

    let puzzle = Puzzle([[1, 0], [0, 2]]);
    let hash = hash_puzzle(&poseidon_config, &puzzle);

    let solution = Solution([[1, 2], [1, 2]]);
    let sudoku = Sudoku {
        poseidon_config: poseidon_config.clone(),
        hash: Some(hash.clone()),
        puzzle: Some(Puzzle(puzzle.0.clone())),
        solution: Some(solution),
    };
    let proof = Groth16::<E>::prove(&pk, sudoku, &mut rng).unwrap();
    // let x = puzzle.0.into_iter().flatten().map(|x| x.into()).collect();
    // hash_vec(poseidon_config.clone(), x);

    assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[hash], &proof).unwrap());
    // assert!(!Groth16::<E>::verify_with_processed_vk(&pvk, &puzzle, &proof).unwrap());
}

pub fn mk_proof<const N: usize, E>(
    pk: &ProvingKey<E>,
    sudoku: &Sudoku<N, E::ScalarField>,
) -> Proof<E>
where
    E: Pairing,
    E::ScalarField: PrimeField + Absorb,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    Groth16::<E>::prove(pk, sudoku.clone(), &mut rng).unwrap()
}

pub fn check_proof<E>(vk: &VerifyingKey<E>, hash: &E::ScalarField, proof: &Proof<E>)
where
    E: Pairing,
    E::ScalarField: Absorb,
{
    let pvk = prepare_verifying_key::<E>(&vk);
    assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[hash.clone()], &proof).unwrap());
}

pub fn mk_sudoku<const N: usize, E>(
    poseidon_config: &PoseidonConfig<E::ScalarField>,
    example: &PuzSol<N>,
) -> Sudoku<N, E::ScalarField>
where
    E: Pairing,
    E::ScalarField: Absorb,
{
    let hash = hash_puzzle(poseidon_config, &example.puzzle);
    Sudoku {
        poseidon_config: poseidon_config.clone(),
        hash: Some(hash.clone()),
        puzzle: Some(example.puzzle.clone()),
        solution: Some(example.solution.clone()),
    }
}

pub fn example_2() -> PuzSol<2> {
    let fp = "tmp.txt";
    let mut puzzle = Puzzle([[1, 0], [0, 2]]);
    write_grid(&fp, puzzle.0).unwrap();
    puzzle = Puzzle(read_grid::<2>(&fp));
    let solution = Solution([[1, 2], [1, 2]]);
    return PuzSol { puzzle, solution };
}

pub fn hash_puzzle<const N: usize, F: PrimeField + Absorb>(
    poseidon_config: &PoseidonConfig<F>,
    puzzle: &Puzzle<N>,
) -> F {
    let puzzle_flat = puzzle
        .0
        .clone()
        .into_iter()
        .flatten()
        .map(|x| x.into())
        .collect::<Vec<F>>();
    CRH::<F>::evaluate(poseidon_config, puzzle_flat).unwrap()
}
