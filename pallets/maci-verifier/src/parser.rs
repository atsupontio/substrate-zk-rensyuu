use super::{ProofStr, VkeyStr};
use bellman_verifier::{Proof, VerifyingKey};
use pairing_ce::bls12_381::{G1Affine, G2Affine, G1Uncompressed, G2Uncompressed};
use pairing_ce::{Engine, EncodedPoint, CurveProjective};
use sp_std::vec::Vec;
// use bls12_381::{G1Affine as bellman_G1, G2Affine as bellman_G2};

pub fn parse_proof<E>(pof: ProofStr) -> Proof<E>
where
	E: Engine<G1Affine = G1Affine, G2Affine = G2Affine>,
{
	let pi_a = pof.pi_a;
	let pi_b = pof.pi_b;
	let pi_c = pof.pi_c;

	let mut a_arr: [u8; 96] = [0; 96];
	let mut b_arr: [u8; 192] = [0; 192];
	let mut c_arr: [u8; 96] = [0; 96];

	for i in 0..pi_a.len() {
		a_arr[i] = pi_a[i];
	}

	for i in 0..pi_b.len() {
		b_arr[i] = pi_b[i];
	}

	for i in 0..pi_c.len() {
		c_arr[i] = pi_c[i];
	}

	let a:G1Uncompressed = G1Uncompressed(a_arr);
	let b:G2Uncompressed = G2Uncompressed(b_arr);
	let c:G1Uncompressed = G1Uncompressed(c_arr);

	let pia_affine = a.into_affine().unwrap();
	let pib_affine = b.into_affine().unwrap();
	let pic_affine = c.into_affine().unwrap();

	Proof { a: pia_affine, b: pib_affine, c: pic_affine }
}

pub fn parse_vkey<E>(vk: VkeyStr) -> VerifyingKey<E>
where
	E: Engine<G1Affine = G1Affine, G2Affine = G2Affine>,
{
	let vk_alpha_1 = vk.alpha_1;
	let vk_beta_1 = vk.beta_1;
	let vk_beta_2 = vk.beta_2;
	let vk_gamma_2 = vk.gamma_2;
	let vk_delta_1 = vk.delta_1;
	let vk_delta_2 = vk.delta_2;
	let vk_ic = vk.ic;

	let mut alpha1: [u8; 96] = [0; 96];
	let mut beta1: [u8; 96] = [0; 96];
	let mut beta2: [u8; 192] = [0; 192];
	let mut gamma2: [u8; 192] = [0; 192];
	let mut delta1: [u8; 96] = [0; 96];
	let mut delta2: [u8; 192] = [0; 192];
	let mut ic_0: [u8; 96] = [0; 96];
	let mut ic_1: [u8; 96] = [0; 96];
	let mut ic = Vec::new();

	for i in 0..vk_alpha_1.len() {
		alpha1[i] = vk_alpha_1[i];
	}

	for i in 0..vk_beta_1.len() {
		beta1[i] = vk_beta_1[i];
	}

	for i in 0..vk_beta_2.len() {
		beta2[i] = vk_beta_2[i];
	}

	for i in 0..vk_gamma_2.len() {
		gamma2[i] = vk_gamma_2[i];
	}

	for i in 0..vk_delta_1.len() {
		delta1[i] = vk_delta_1[i];
	}

	for i in 0..vk_delta_2.len() {
		delta2[i] = vk_delta_2[i];
	}

	for i in 0..vk_ic[0].len() {
		ic_0[i] = vk_ic[0][i];
	}

	for i in 0..vk_ic[1].len() {
		ic_1[i] = vk_ic[1][i];
	}

	let alpha1:G1Uncompressed = G1Uncompressed(alpha1);
	let beta1:G1Uncompressed = G1Uncompressed(beta1);
	let beta2:G2Uncompressed = G2Uncompressed(beta2);
	let gamma2:G2Uncompressed = G2Uncompressed(gamma2);
	let delta1:G1Uncompressed = G1Uncompressed(delta1);
	let delta2:G2Uncompressed = G2Uncompressed(delta2);
	let ic0:G1Uncompressed = G1Uncompressed(ic_0);
	let ic1:G1Uncompressed = G1Uncompressed(ic_1);

	let alpha1_affine = alpha1.into_affine().unwrap();
	let beta1_affine = beta1.into_affine().unwrap();
	let beta2_affine = beta2.into_affine().unwrap();
	let gamma2_affine = gamma2.into_affine().unwrap();
	let delta1_affine = delta1.into_affine().unwrap();
	let delta2_affine = delta2.into_affine().unwrap();
	let ic0_affine = ic0.into_affine().unwrap();
	let ic1_affine = ic1.into_affine().unwrap();
	ic.push(ic0_affine);
	ic.push(ic1_affine);

	VerifyingKey {
		alpha_g1: alpha1_affine,
		beta_g1: beta1_affine,
		beta_g2: beta2_affine,
		gamma_g2: gamma2_affine,
		delta_g1: delta1_affine,
		delta_g2: delta2_affine,
		ic,
	}
}
