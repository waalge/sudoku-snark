use ark_ec::pairing::Pairing;
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::{CanonicalSerialize, Compress};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;

use ark_ff::PrimeField;

#[derive(Serialize, Deserialize, Debug)]
pub struct VkHexed {
    alpha1: String,
    beta2: String,
    gamma2: String,
    delta2: String,
    abc11: String,
    abc12: String,
}

impl<E> From<VerifyingKey<E>> for VkHexed
where
    E: Pairing,
{
    fn from(vk: VerifyingKey<E>) -> VkHexed {
        let mut alpha_1 = Vec::new();
        let mut beta_2 = Vec::new();
        let mut gamma_2 = Vec::new();
        let mut delta_2 = Vec::new();
        let mut gamma_abc_1_1 = Vec::new();
        let mut gamma_abc_1_2 = Vec::new();

        vk.alpha_g1
            .serialize_with_mode(&mut alpha_1, Compress::Yes)
            .unwrap();
        vk.beta_g2
            .serialize_with_mode(&mut beta_2, Compress::Yes)
            .unwrap();
        vk.gamma_g2
            .serialize_with_mode(&mut gamma_2, Compress::Yes)
            .unwrap();
        vk.delta_g2
            .serialize_with_mode(&mut delta_2, Compress::Yes)
            .unwrap();
        vk.gamma_abc_g1[0]
            .serialize_with_mode(&mut gamma_abc_1_1, Compress::Yes)
            .unwrap();
        vk.gamma_abc_g1[1]
            .serialize_with_mode(&mut gamma_abc_1_2, Compress::Yes)
            .unwrap();

        VkHexed {
            alpha1: hex_vec(&alpha_1),
            beta2: hex_vec(&beta_2),
            gamma2: hex_vec(&gamma_2),
            delta2: hex_vec(&delta_2),
            abc11: hex_vec(&gamma_abc_1_1),
            abc12: hex_vec(&gamma_abc_1_2),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProofHexed {
    a: String,
    b: String,
    c: String,
}

impl<E> From<Proof<E>> for ProofHexed
where
    E: Pairing,
{
    fn from(proof: Proof<E>) -> ProofHexed {
        let mut a = Vec::new();
        let mut b = Vec::new();
        let mut c = Vec::new();

        proof.a.serialize_with_mode(&mut a, Compress::Yes).unwrap();
        proof.b.serialize_with_mode(&mut b, Compress::Yes).unwrap();
        proof.c.serialize_with_mode(&mut c, Compress::Yes).unwrap();

        ProofHexed {
            a: hex_vec(&a),
            b: hex_vec(&b),
            c: hex_vec(&c),
        }
    }
}

fn hex_vec(v: &Vec<u8>) -> String {
    v.into_iter()
        .map(|x| format!("{:02x}", x))
        .collect::<Vec<String>>()
        .join("")
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PoseidonConfigDef {
    pub alpha: u64,
    pub ark: Vec<Vec<BigUint>>,
    pub capacity: usize,
    pub full_rounds: usize,
    pub mds: Vec<Vec<BigUint>>,
    pub partial_rounds: usize,
    pub rate: usize,
}

impl<F: PrimeField> Into<PoseidonConfig<F>> for PoseidonConfigDef {
    fn into(self) -> PoseidonConfig<F> {
        PoseidonConfig::<F>::new(
            self.full_rounds,
            self.partial_rounds,
            self.alpha,
            self.mds
                .into_iter()
                .map(|row| row.into_iter().map(|x| x.into()).collect())
                .collect(),
            self.ark
                .into_iter()
                .map(|row| row.into_iter().map(|x| x.into()).collect())
                .collect(),
            self.rate,
            self.capacity,
        )
    }
}

impl<F: PrimeField> From<PoseidonConfig<F>> for PoseidonConfigDef {
    fn from(def: PoseidonConfig<F>) -> PoseidonConfigDef {
        PoseidonConfigDef {
            full_rounds: def.full_rounds,
            partial_rounds: def.partial_rounds,
            alpha: def.alpha,
            mds: def
                .mds
                .into_iter()
                .map(|row| row.into_iter().map(|x| x.into()).collect())
                .collect(),
            ark: def
                .ark
                .into_iter()
                .map(|row| row.into_iter().map(|x| x.into()).collect())
                .collect(),
            rate: def.rate,
            capacity: def.capacity,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PubInputs {
    pub pub1: String,
}
