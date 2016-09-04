use std::cmp::max;
use rand::Rng;
use tiny_keccak::Keccak;
use ::param::{ N, NZ1, NZ2 };


#[inline]
pub fn vecabsmax(v: &[i32]) -> i32 {
    v.iter()
        .fold(0, |sum, next| max(sum, next.abs()))
}

#[inline]
pub fn vecscalar(t: &[i32], u: &[i32]) -> i32 {
    t.iter()
        .zip(u)
        .map(|(ti, &ui)| ti * ui)
        .sum()
}

pub fn uniform_poly(v: &mut [i32], rng: &mut Rng) {
    let mut i = 0;
    while i < NZ1 {
        let x = rng.next_u64();
        let j = (x >> 1) as usize % N;
        if v[j] == 0 {
            v[j] = if x & 1 != 0 { 1 } else { -1 };
            i += 1;
        }
    }

    let mut i = 0;
    while i < NZ2 {
        let x = rng.next_u64();
        let j = (x >> 1) as usize % N;
        if v[j] == 0 {
            v[j] = if x & 1 != 0 { 2 } else { -2 };
            i += 1;
        }
    }
}

pub fn generate_c(c_idx: &mut [i32], hash: &[u8]) {
    let mut fl = [0; N];
    for r in 0..65536 {
        Keccak::new_sha3_256();
        unimplemented!()
    }
}
