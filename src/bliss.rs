use std::io;
use rand::{ Rng, OsRng, ChaChaRng };
use rand::distributions::{ Normal, Sample };
use ::ntt::{ fft, flp, xmu, cmu, pwr };
use ::param::{
    Q, N, D, P, KAPPA, B_INF, B_L2, SIGMA, M,
    W, R
};
use ::utils::{
    uniform_poly, c_oracle, greedy_sc,
    vecabsmax, vecscalar
};


pub struct PrivateKey {
    f: [i32; N],
    g: [i32; N],
    a: [i32; N]
}

pub struct PublicKey {
    a: [i32; N]
}

pub struct Signature {
    t: [i32; N],
    z: [i32; N],
    c_idx: [usize; KAPPA]
}

impl PrivateKey {
    pub fn new() -> io::Result<PrivateKey> {
        let mut rng = OsRng::new()?.gen::<ChaChaRng>();
        let (mut t, mut u, mut a) = ([0; N], [0; N], [0; N]);
        let mut privkey = PrivateKey {
            f: [0; N],
            g: [0; N],
            a: [0; N]
        };

        uniform_poly(&mut privkey.g, &mut rng);
        for i in 0..N {
            privkey.g[i] *= 2;
        }
        privkey.g[0] -= 1;
        t.clone_from_slice(&privkey.g);
        xmu(&mut t, &privkey.g, &W);
        fft(&mut t);

        'f : for _ in 0..99999 {
            uniform_poly(&mut privkey.f, &mut rng);
            u.clone_from_slice(&privkey.f);
            xmu(&mut u, &privkey.f, &W);
            fft(&mut u);

            for i in 0..N {
                let x = u[i] % Q;
                if x == 0 { continue 'f };
                u[i] = pwr(x, Q - 2, Q);
            }

            xmu(&mut privkey.a, &t, &u);
            fft(&mut privkey.a);
            a.clone_from_slice(&privkey.a);
            xmu(&mut privkey.a, &a, &R);

            a.clone_from_slice(&privkey.a);
            cmu(&mut privkey.a, &a, -1);
            flp(&mut privkey.a);
            a.clone_from_slice(&privkey.a);
            xmu(&mut privkey.a, &a, &W);
            fft(&mut privkey.a);

            for i in 0..N {
                let x = privkey.a[i] % Q;
                privkey.a[i] = if x < 0 { x + Q } else { x };
            }

            return Ok(privkey);
        }

        Err(io::Error::new(io::ErrorKind::Other, "Unable to generate the correct private key."))
    }

    pub fn public(&self) -> PublicKey {
        let mut pubkey = PublicKey {
            a: [0; N]
        };
        pubkey.a.clone_from_slice(&self.a);
        pubkey
    }

    pub fn signature(&self, hash: &[u8]) -> io::Result<Signature> {
        let mut sign = Signature {
            t: [0; N],
            z: [0; N],
            c_idx: [0; KAPPA]
        };
        let mut rng = OsRng::new()?.gen::<ChaChaRng>();
        let mut sample = Normal::new(0.0, SIGMA);
        let mut u = [0; N];
        let (mut v, mut vv) = ([0; N], [0; N]);
        let (mut x, mut y) = ([0; N], [0; N]);

        macro_rules! gauss_sample {
            () => { sample.sample(&mut rng) as i32 }
        }

        for _ in 0..99999 {
            for i in 0..N {
                sign.t[i] = gauss_sample!();
                u[i] = gauss_sample!();
            }

            v.clone_from_slice(&sign.t);
            xmu(&mut v, &sign.t, &W);
            fft(&mut v);
            vv.clone_from_slice(&v);
            xmu(&mut v, &vv, &self.a);
            fft(&mut v);
            vv.clone_from_slice(&v);
            xmu(&mut v, &vv, &R);
            flp(&mut v);

            for i in 0..N {
                let mut tmp = v[i];
                if tmp & 1 != 0 { tmp += Q };
                tmp = (tmp + u[i]) % (2 * Q);
                if tmp < 0 { tmp += 2 * Q };
                v[i] = tmp;
                sign.z[i] = ((tmp + (1 << (D - 1))) >> D) % P;
            }

            if !c_oracle(&mut sign.c_idx, hash, &v) {
                Err(io::Error::new(io::ErrorKind::Other, "Unable to generate the correct oracle c."))?;
            }
            greedy_sc(&self.f, &self.g, &sign.c_idx, &mut x, &mut y);

            let mut d = 1.0 / (SIGMA * SIGMA);
            d = 1.0 / (
                M *
                (-0.5 * d * (vecscalar(&x, &x) + vecscalar(&y, &y)) as f64).exp() *
                (d * (vecscalar(&sign.t, &x) + vecscalar(&u, &y)) as f64).cosh()
            );

            if rng.gen::<f64>() > d { continue };

            for i in 0..N {
                let mut tmp = v[i] - u[i];
                if tmp < 0 { tmp += 2 * Q };
                if tmp >= 2 * Q { tmp -= 2 * Q };

                tmp = ((tmp + (1 << (D - 1))) >> D) % P;

                tmp = sign.z[i] - tmp;
                if tmp < -P / 2 { tmp += P };
                if tmp > P / 2 { tmp -= P };
                sign.z[i] = tmp;
            }

            return Ok(sign);
        }

        Err(io::Error::new(io::ErrorKind::Other, "Unable to generate the correct signature."))
    }
}


impl PublicKey {
    pub fn verify(&self, sign: &Signature, hash: &[u8]) -> io::Result<bool> {
        if vecabsmax(&sign.t) > B_INF || (vecabsmax(&sign.z) << D) > B_INF {
            return Ok(false);
        }
        if vecscalar(&sign.t, &sign.t) + (vecscalar(&sign.z, &sign.z) << (2 * D)) > B_L2 {
            return Ok(false);
        }

        let (mut v, mut vv) = ([0; N], [0; N]);
        let mut my_idx = [0; KAPPA];
        v.clone_from_slice(&sign.t);

        xmu(&mut v, &sign.t, &W);
        fft(&mut v);
        vv.clone_from_slice(&v);
        xmu(&mut v, &vv, &self.a);
        fft(&mut v);
        vv.clone_from_slice(&v);
        xmu(&mut v, &vv, &R);
        flp(&mut v);

        for i in 0..N {
            if v[i] & 1 != 0 {
                v[i] += Q;
            }
        }

        for &i in sign.c_idx.iter() {
            v[i] = (v[i] + Q) % (2 * Q);
        }

        for i in 0..N {
            let tmp = (((v[i] + (1 << (D - 1))) >> D) + sign.z[i]) % P;
            v[i] = if tmp < 0 { tmp + P } else { tmp };
        }

        c_oracle(&mut my_idx, hash, &v);

        let mut d = 0;
        for i in 0..KAPPA {
            d |= my_idx[i] ^ sign.c_idx[i];
        }
        Ok(d == 0)
    }
}
