use std::cmp::max;
use rand::Rng;
use tiny_keccak::Keccak;
use byteorder::{ BigEndian, ByteOrder };
use ::param::{ N, NZ1, NZ2, KAPPA };


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

pub fn c_oracle(c_idx: &mut [usize], hash: &[u8], w: &[i32]) -> bool {
    let mut fl = [0; N];
    let mut idx_i = 0;
    for r in 0..::std::u16::MAX {
        let mut sha3 = Keccak::new_sha3_512();
        sha3.update(hash);

        let mut output = [0; 64];
        let mut t = [0; 2];
        for i in 0..N {
            BigEndian::write_u16(&mut t, w[i] as u16);
            sha3.update(&t);
        }
        BigEndian::write_u16(&mut t, r);
        sha3.update(&t);
        sha3.finalize(&mut output);

        for i in (0..64).step_by(2) {
            let idx = BigEndian::read_u16(&output[i..]) as usize % N;
            if fl[idx] == 0 {
                c_idx[idx_i] = idx;
                idx_i += 1;
                if idx_i == KAPPA {
                    return true;
                }
                fl[idx] = 1;
            }
        }
    }

    false
}

pub fn greedy_sc(f: &[i32], g: &[i32], c_idx: &[usize], x: &mut [i32], y: &mut [i32]) {
    for i in c_idx {
        let mut sgn = 0;

        for j in 0..(N - i) {
            sgn += f[j] * x[i + j] + g[j] * y[i + j];
        }
        for j in (N - i)..N {
            sgn -= f[j] * x[i + j - N] + g[j] * y[i + j - N];
        }

        if sgn > 0 {
            for j in 0..(N - i) {
                x[i + j] -= f[j];
                y[i + j] -= g[j];
            }
            for j in (N - i)..N {
                x[i + j - N] += f[j];
                x[i + j - N] += g[j];
            }
        } else {
            for j in 0..(N - i) {
                x[i + j] += f[j];
                y[i + j] += g[j];
            }
            for j in (N - i)..N {
                x[i + j - N] -= f[j];
                x[i + j - N] -= g[j];
            }
        }
    }
}
