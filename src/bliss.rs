use std::io;
use rand::{ Rng, OsRng, ChaChaRng };
use ::param::{ N, KAPPA, Q, W, R };
use ::ntt::{ fft, flp, xmu, cmu, pwr };
use ::poly::{
    uniform_poly,
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

        'f : for _ in 0..(10 * N) {
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

            return Ok(privkey)
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
}
