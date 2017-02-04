use std::io;
use rand::{ Rand, Rng, OsRng };
use rand::distributions::{ Normal, Sample };
use bitpack::BitPack;
use ::ntt::{ fft, flp, xmu, cmu, pwr };
use ::param::*;
use ::utils::{
    uniform_poly, c_oracle, greedy_sc,
    vecabsmax, vecscalar
};


pub struct PrivateKey {
    pub f: [i32; N],
    pub g: [i32; N],
    pub a: [i32; N]
}

pub struct PublicKey {
    pub a: [i32; N]
}

pub struct Signature {
    pub t: [i32; N],
    pub z: [i32; N],
    pub c_idx: [usize; KAPPA]
}

impl PrivateKey {
    pub fn new<R: Rand + Rng>() -> io::Result<PrivateKey> {
        let mut rng = OsRng::new()?.gen::<R>();
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
        xmu(&mut t, &privkey.g, &W);
        fft(&mut t);

        'f : for _ in 0..1024 {
            uniform_poly(&mut privkey.f, &mut rng);
            xmu(&mut u, &privkey.f, &W);
            fft(&mut u);

            for i in 0..N {
                let x = u[i] % Q;
                if x == 0 { continue 'f };
                u[i] = pwr(x, Q - 2, Q);
            }

            xmu(&mut a, &t, &u);
            fft(&mut a);
            xmu(&mut privkey.a, &a, &R);

            cmu(&mut a, &privkey.a, -1);
            flp(&mut a);
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
        pubkey.a.copy_from_slice(&self.a);
        pubkey
    }

    pub fn signature<R: Rand + Rng>(&self, hash: &[u8]) -> io::Result<Signature> {
        let mut u = [0; N];
        let (mut v, mut vv) = ([0; N], [0; N]);
        let (mut x, mut y) = ([0; N], [0; N]);
        let mut sign = Signature {
            t: [0; N],
            z: [0; N],
            c_idx: [0; KAPPA]
        };
        let mut rng = OsRng::new()?.gen::<R>();
        let mut sample = Normal::new(0.0, SIGMA);

        macro_rules! gauss_sample {
            () => { sample.sample(&mut rng) as i32 }
        }

        for _ in 0..1024 {
            for i in 0..N {
                sign.t[i] = gauss_sample!();
                u[i] = gauss_sample!();
            }

            xmu(&mut v, &sign.t, &W);
            fft(&mut v);
            xmu(&mut vv, &v, &self.a);
            fft(&mut vv);
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

            if !c_oracle(&mut sign.c_idx, hash, &sign.z) { continue };
            greedy_sc(&self.f, &self.g, &sign.c_idx, &mut x, &mut y);

            if rng.gen() {
                for i in 0..N {
                    sign.t[i] -= x[i];
                    u[i] -= y[i];
                }
            } else {
                for i in 0..N {
                    sign.t[i] += x[i];
                    u[i] += y[i];
                }
            }

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

    pub fn export(&self) -> Result<[u8; PRIVATEKEY_LENGTH], ()> {
        let mut output = [0; PRIVATEKEY_LENGTH];

        {
            let mut bitpack = BitPack::<&mut [u8]>::new(&mut output);
            for i in 0..N {
                bitpack.write((self.f[i] + 2i32.pow(F_BITS as u32 - 1)) as u32, F_BITS)?;
                bitpack.write((self.g[i] + 2i32.pow(G_BITS as u32 - 1)) as u32, G_BITS)?;
                bitpack.write(self.a[i] as u32, A_BITS)?;
            }
            bitpack.flush();
        }

        Ok(output)
    }

    pub fn import(input: &[u8; PRIVATEKEY_LENGTH]) -> Result<PrivateKey, ()> {
        let mut privkey = PrivateKey {
            f: [0; N],
            g: [0; N],
            a: [0; N]
        };

        {
            let mut bitpack = BitPack::<&[u8]>::new(input);
            for i in 0..N {
                privkey.f[i] = bitpack.read(F_BITS)? as i32 - 2i32.pow(F_BITS as u32 - 1);
                privkey.g[i] = bitpack.read(G_BITS)? as i32 - 2i32.pow(G_BITS as u32 - 1);
                privkey.a[i] = bitpack.read(A_BITS)? as i32;
            }
        }

        Ok(privkey)
    }
}


impl PublicKey {
    pub fn verify(&self, sign: &Signature, hash: &[u8]) -> bool {
        if vecabsmax(&sign.t) > B_INF || (vecabsmax(&sign.z) << D) > B_INF {
            return false;
        }
        if vecscalar(&sign.t, &sign.t) + (vecscalar(&sign.z, &sign.z) << (2 * D)) > B_L2 {
            return false;
        }

        let (mut v, mut vv) = ([0; N], [0; N]);
        let mut my_idx = [0; KAPPA];

        xmu(&mut v, &sign.t, &W);
        fft(&mut v);
        xmu(&mut vv, &v, &self.a);
        fft(&mut vv);
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

        if !c_oracle(&mut my_idx, hash, &v) {
            return false;
        }

        let mut d = 0;
        for i in 0..KAPPA {
            d |= my_idx[i] ^ sign.c_idx[i];
        }
        d == 0
    }

    pub fn export(&self) -> Result<[u8; PUBLICKEY_LENGTH], ()> {
        let mut output = [0; PUBLICKEY_LENGTH];

        {
            let mut bitpack = BitPack::<&mut [u8]>::new(&mut output);
            for &b in &self.a[..] {
                bitpack.write(b as u32, A_BITS)?;
            }
            bitpack.flush();
        }

        Ok(output)
    }

    pub fn import(input: &[u8; PUBLICKEY_LENGTH]) -> Result<PublicKey, ()> {
        let mut pubkey = PublicKey {
            a: [0; N]
        };

        {
            let mut bitpack = BitPack::<&[u8]>::new(input);
            for i in 0..N {
                pubkey.a[i] = bitpack.read(A_BITS)? as i32;
            }
        }

        Ok(pubkey)
    }
}

impl Signature {
    pub fn export(&self) -> Result<[u8; SIGNATURE_LENGTH], ()> {
        let mut output = [0; SIGNATURE_LENGTH];

        {
            let mut bitpack = BitPack::<&mut [u8]>::new(&mut output);
            for i in 0..N {
                bitpack.write((self.t[i] + 2i32.pow(T_BITS as u32 - 1)) as u32, T_BITS)?;
                bitpack.write((self.z[i] + 2i32.pow(Z_BITS as u32 - 1)) as u32, Z_BITS)?;
            }
            for i in 0..KAPPA {
                bitpack.write(self.c_idx[i] as u32, CIDX_BITS)?;
            }
            bitpack.flush();
        }

        Ok(output)
    }

    pub fn import(input: &[u8]) -> Result<Signature, ()> {
        let mut sign = Signature {
            t: [0; N],
            z: [0; N],
            c_idx: [0; KAPPA]
        };

        {
            let mut bitpack = BitPack::<&[u8]>::new(input);
            for i in 0..N {
                sign.t[i] = bitpack.read(T_BITS)? as i32 - 2i32.pow(T_BITS as u32 - 1);
                sign.z[i] = bitpack.read(Z_BITS)? as i32 - 2i32.pow(Z_BITS as u32 - 1);
            }
            for i in 0..KAPPA {
                sign.c_idx[i] = bitpack.read(CIDX_BITS)? as usize;
            }
        }

        Ok(sign)
    }
}
