use std::cmp::max;
use rand::Rng;


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

pub fn uniform_poly(v: &mut [i32], nz1: i16, nz2: i16, rng: &mut Rng) {
    let n = v.len();
    let mut i = 0;
    while i < nz1 {
        let x = rng.next_u64();
        let j = (x >> 1) as usize % n;
        if v[j] == 0 {
            v[j] = if x & 1 != 0 { 1 } else { -1 };
            i += 1;
        }
    }

    let mut i = 0;
    while i < nz2 {
        let x = rng.next_u64();
        let j = (x >> 1) as usize % n;
        if v[j] == 0 {
            v[j] = if x & 1 != 0 { 2 } else { -2 };
            i += 1;
        }
    }
}

pub fn generate_c(c_idx: &mut [i32], kappa: i16, hash: &[u8], w: &[i32]) {
    let mut fl = vec![0; 0];
    unimplemented!()
}
