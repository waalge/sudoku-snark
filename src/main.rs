use std::fs;

use ark_bls12_381::Bls12_381 as E;
use ark_crypto_primitives::sponge::{poseidon::PoseidonConfig, Absorb};
use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

mod poseidon;
mod ss_serde;
// TODO: Sort this org out
use crate::poseidon::mk_poseidon_config;
use crate::ss_serde::ProofHexed;
use crate::ss_serde::VkHexed;
use crate::ss_serde::{PoseidonConfigDef, PubInputs};
use sudoku_snark::hash_puzzle;
use sudoku_snark::{check_proof, mk_proof, mk_sudoku, read_grid, setup, PuzSol, Puzzle, Solution};

use clap::{Parser, Subcommand};

type F = <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField;

// WARNING:: Damn. This dimension has to be set at compile time
// We could compile for multiple values, but for now just mod this
const DIM: usize = 2;

#[derive(Parser, Debug)]
#[clap(author = "waalge", version, about)]
/// Generate setups and proofs
struct Arguments {
    #[clap(subcommand)]
    cmd: SubCommand,
}

#[derive(Subcommand, Debug)]
enum SubCommand {
    /// Generate the proof and verifier keys for a given size
    Init {
        /// Determines where keys are output
        keys: String,
    },
    // Generate the public inputs?
    Set {
        /// which keys
        keys: String,
        /// which puzzle
        puzzle: String,
    },
    /// Create proof
    Prove {
        /// which keys
        keys: String,
        /// which puzzle
        sudoku: String,
    },
}

fn main() {
    let args = Arguments::parse();
    match args.cmd {
        SubCommand::Init { keys } => {
            let _ = fs::create_dir_all(keys_path(&keys, ""));
            init::<DIM>(&keys).unwrap();
            println!("Init {}", keys)
        }
        SubCommand::Set { keys, puzzle } => {
            let _ = fs::create_dir_all(results_path(&keys, &puzzle, ""));
            let _ = set::<DIM>(&keys, &puzzle);
            println!("set")
        }
        SubCommand::Prove { keys, sudoku } => {
            let _ = fs::create_dir_all(results_path(&keys, &sudoku, ""));
            let _ = prove::<DIM>(&keys, &sudoku);
            println!("prove")
        }
    }
}

fn init<const N: usize>(name: &str) -> Result<(), serde_json::Error> {
    // Write poseidon config
    write_poseidon_config::<F>(name, N);
    let poseidon_config = read_poseidon_config::<F>(name);

    // Setup
    let (pk, vk) = setup::<N, E>(&poseidon_config);

    // write pk
    let mut v_pk = Vec::new();
    pk.serialize_compressed(&mut v_pk).unwrap();
    fs::write(pk_path(name), v_pk).unwrap();

    // write vk
    let mut v_vk = Vec::new();
    vk.serialize_compressed(&mut v_vk).unwrap();
    fs::write(vk_path(name), v_vk).unwrap();

    // write vk_hexed
    let vk_hexed = VkHexed::from(vk.clone());
    fs::write(
        vk_hexed_path(name),
        serde_json::to_string_pretty(&vk_hexed).unwrap(),
    )
    .unwrap();

    Ok(())
}

fn set<const N: usize>(keys: &str, sud_path: &str) -> Result<(), serde_json::Error> {
    let poseidon_config = read_poseidon_config::<F>(keys);
    let pk_bin: Vec<u8> = fs::read(&pk_path(keys)).unwrap();
    let pk = ProvingKey::<E>::deserialize_with_mode(
        &pk_bin[..],
        ark_serialize::Compress::Yes,
        ark_serialize::Validate::Yes,
    )
    .unwrap();

    // Propose problem (here with solution)
    // Solver solves it (not here) and creates proof
    let puzzle = Puzzle(read_grid::<N>(&sudoku_puzzle_path(&sud_path)));
    let hash = hash_puzzle(&poseidon_config, &puzzle);
    let pub_inputs = PubInputs {
        pub1: format!("{}", hash),
    };
    fs::write(
        pub_inputs_path(keys, sud_path),
        serde_json::to_string_pretty(&pub_inputs).unwrap(),
    )
    .unwrap();
    Ok(())
}

fn prove<const N: usize>(keys: &str, sud_path: &str) -> Result<(), serde_json::Error> {
    let poseidon_config = read_poseidon_config::<F>(keys);
    let pk_bin: Vec<u8> = fs::read(&pk_path(keys)).unwrap();
    let pk = ProvingKey::<E>::deserialize_with_mode(
        &pk_bin[..],
        ark_serialize::Compress::Yes,
        ark_serialize::Validate::Yes,
    )
    .unwrap();

    // Propose problem (here with solution)
    // Solver solves it (not here) and creates proof
    let puzzle = Puzzle(read_grid::<N>(&sudoku_puzzle_path(&sud_path)));
    let solution = Solution(read_grid::<N>(&sudoku_solution_path(&sud_path)));
    let sudoku = mk_sudoku::<N, E>(&poseidon_config, &PuzSol { puzzle, solution });

    let proof = mk_proof(&pk, &sudoku);
    let proof_hexed = ProofHexed::from(proof.clone());
    fs::write(
        proof_hexed_path(keys, sud_path),
        serde_json::to_string_pretty(&proof_hexed).unwrap(),
    )
    .unwrap();

    let vk_bin: Vec<u8> = fs::read(&vk_path(keys)).unwrap();
    let vk = VerifyingKey::<E>::deserialize_with_mode(
        &vk_bin[..],
        ark_serialize::Compress::Yes,
        ark_serialize::Validate::Yes,
    )
    .unwrap();

    check_proof::<E>(&vk, &sudoku.hash.unwrap(), &proof);
    Ok(())
}

// TODO : Move these somewhere

fn out_root() -> String {
    format!("./out")
}
fn keys_path(name: &str, file: &str) -> String {
    format!("{}/keys/{}/{}", out_root(), name, file)
}

fn poseidon_config_path(name: &str) -> String {
    keys_path(name, "poseidon_config.json")
}
fn pk_path(name: &str) -> String {
    keys_path(name, "pk.bin")
}
fn vk_path(name: &str) -> String {
    keys_path(name, "vk.bin")
}
fn vk_hexed_path(name: &str) -> String {
    keys_path(name, "params.json")
}
fn sudoku_path(name: &str, file: &str) -> String {
    format!("{}/sudokus/{}/{}", out_root(), name, file)
}
fn sudoku_puzzle_path(name: &str) -> String {
    sudoku_path(name, "puzzle.ssv")
}
fn sudoku_solution_path(name: &str) -> String {
    sudoku_path(name, "solution.ssv")
}
fn results_path(keys: &str, sudoku: &str, file: &str) -> String {
    format!("{}/results/{}_{}/{}", out_root(), keys, sudoku, file)
}
fn proof_hexed_path(keys: &str, sudoku: &str) -> String {
    results_path(keys, sudoku, "redeemer.json")
}
fn pub_inputs_path(keys: &str, sudoku: &str) -> String {
    results_path(keys, sudoku, "datum.json")
}

fn write_poseidon_config<F: PrimeField + Absorb>(name: &str, n: usize) {
    let poseidon_config = mk_poseidon_config::<F>(n);
    let pcd = PoseidonConfigDef::from(poseidon_config);
    let toj = serde_json::to_string_pretty(&pcd).unwrap();
    fs::write(poseidon_config_path(name), toj).unwrap();
}

fn read_poseidon_config<F: PrimeField + Absorb>(name: &str) -> PoseidonConfig<F> {
    let toj = fs::read_to_string(poseidon_config_path(name)).expect("Unable to read file");
    let froj: PoseidonConfigDef = serde_json::from_str::<PoseidonConfigDef>(&toj).unwrap();
    let pc: PoseidonConfig<F> = froj.into();
    pc
}
