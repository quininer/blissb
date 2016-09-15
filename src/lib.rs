#![feature(step_by, question_mark)]

extern crate rand;
extern crate tiny_keccak;
extern crate byteorder;

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
        let result = pk.verify(&sign, &hash);
        assert!(result);
    }
}
