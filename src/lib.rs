#![feature(step_by, question_mark)]

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
    use tiny_keccak::Keccak;

    let mut hash = [0; 64];
    let mut sha3 = Keccak::new_sha3_512();
    sha3.update(b"Hello blissb.");
    sha3.finalize(&mut hash);

    for _ in 0..1024 {
        let sk = PrivateKey::new().unwrap();
        let pk = sk.public();
        let sign = sk.signature(&hash).unwrap();
        assert!(pk.verify(&sign, &hash));
    }
}

#[test]
fn test_export_import() {
    use tiny_keccak::Keccak;

    let mut hash = [0; 64];
    let mut sha3 = Keccak::new_sha3_512();
    sha3.update(b"Hello blissb.");
    sha3.finalize(&mut hash);

    let sk = PrivateKey::new().unwrap();
    let pk = sk.public();
    let sign = sk.signature(&hash).unwrap();
    let sk_bytes = sk.export().unwrap();
    let pk_bytes = pk.export().unwrap();

    let sk = PrivateKey::import(&sk_bytes).unwrap();
    let pk = PublicKey::import(&pk_bytes).unwrap();

    assert!(pk.verify(&sign, &hash));
}
