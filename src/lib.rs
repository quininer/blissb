#![feature(step_by)]

extern crate rand;
extern crate tiny_keccak;
extern crate byteorder;
extern crate bitpack;

mod utils;
mod ntt;
mod bliss;
pub mod param;

pub use bliss::{ PrivateKey, PublicKey, Signature };


#[test]
fn test_sign() {
    use rand::ChaChaRng;
    use tiny_keccak::Keccak;

    let mut hash = [0; 64];
    let mut sha3 = Keccak::new_sha3_512();
    sha3.update(b"Hello blissb.");
    sha3.finalize(&mut hash);

    for _ in 0..1024 {
        let sk = PrivateKey::new::<ChaChaRng>().unwrap();
        let pk = sk.public();
        let sign = sk.signature::<ChaChaRng>(&hash).unwrap();
        assert!(pk.verify(&sign, &hash));
        assert!(!pk.verify(&sign, &[0; 64]));
    }
}

#[test]
fn test_export_import() {
    use rand::ChaChaRng;
    use tiny_keccak::Keccak;

    let mut hash = [0; 64];
    let mut sha3 = Keccak::new_sha3_512();
    sha3.update(b"Hello blissb.");
    sha3.finalize(&mut hash);

    for _ in 0..1024 {
        let sk = PrivateKey::new::<ChaChaRng>().unwrap();
        let pk = sk.public();
        let sign = sk.signature::<ChaChaRng>(&hash).unwrap();
        let sk_bytes = sk.export().unwrap();
        let pk_bytes = pk.export().unwrap();

        let sk2 = PrivateKey::import(&sk_bytes).unwrap();
        let pk2 = PublicKey::import(&pk_bytes).unwrap();

        assert!(pk2.verify(&sign, &hash));

        let sign = sk2.signature::<ChaChaRng>(&hash).unwrap();
        let sign_bytes = sign.export().unwrap();
        let sign2 = Signature::import(&sign_bytes).unwrap();

        assert!(pk.verify(&sign2, &hash));
    }
}
