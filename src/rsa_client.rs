use core::f64;
use std::borrow::Borrow;

use cbc::cipher::consts::{U1024, U2048};
use modpow::*;
use num::{integer::{lcm}, FromPrimitive};
use num_bigint::{BigInt, BigUint, ModInverse, RandBigInt, RandomBits, ToBigInt, ToBigUint};
use num_traits::{Inv, One, Pow};
use rand::{random, thread_rng, Rng};

use crate::phi;
use num_traits::Num;

use num_traits::Zero;
use num_integer::Integer;

/* #region Keys */
pub struct PublicKey {
    pub n: BigUint,
    pub e: BigUint,
}

impl PublicKey {
    pub fn new(n: BigUint, e: BigUint) -> PublicKey {
        PublicKey { n, e }
    }

    pub fn none() -> PublicKey {
        PublicKey {
            e: BigUint::one(),
            n: BigUint::one(),
        }
    }
}

pub struct PrivateKey {
    pub d: BigUint,
    pub e: BigUint,
}

impl PrivateKey {
    pub fn new(d: BigUint, e: BigUint) -> PrivateKey {
        PrivateKey { d, e }
    }

    pub fn none() -> PrivateKey {
        PrivateKey {
            e: BigUint::one(),
            d: BigUint::one(),
        }
    }
}
/* #endregion */

pub struct RsaClient {
    pub key_size: u64,
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
}

impl RsaClient {
    pub fn new(key_size: u64) -> RsaClient {
        let mut c = RsaClient {
            private_key: PrivateKey::none(),
            public_key: PublicKey::none(), // n, e,
            key_size,
        };
        c.generate_keys();
        c
    }

    pub fn from(private_key: PrivateKey, public_key: PublicKey) -> RsaClient {
        RsaClient {
            private_key: private_key,
            public_key: public_key,
            key_size: 1024,
        }
    }

    pub fn generate_keys(&mut self) {
        let safety = 60;

        let mut p = Self::get_random_prime(self.key_size / 2, safety);
        // let mut p = BigUint::from_u8(61).unwrap();
        // also use test_for_first_primes

        println!("p: {}", p.to_str_radix(10));
        println!();

        let mut q = Self::get_random_prime(self.key_size / 2, safety);
        // let mut q = BigUint::from_u8(53).unwrap();

        println!("q: {}", q.to_str_radix(10));
        println!();

        let n = &q * &p;

        println!("n: {}", n.to_str_radix(10));
        println!();


        let phi = (&p - 1u8) * (&q - 1u8);

        println!("phi: {}", phi.to_str_radix(10));
        println!();

        let lambda = carmichael_lambda(&p, &q);

        println!("lambda: {}", lambda.to_str_radix(10));
        println!();

        
        // let e = random_prime_between( &BigUint::from_u8(2).unwrap(), &phi, safety);
        let e = BigUint::from_u32(65537u32).unwrap();

        println!("e: {}", e.to_str_radix(10));
        println!();
        
        let d: BigUint = e.borrow().mod_inverse(&lambda).unwrap().to_biguint().unwrap();
        
        println!("d: {}", d.to_str_radix(10));
        println!();


        self.private_key = PrivateKey::new(d, e.clone());
        self.public_key = PublicKey::new(n, e);

        // print d as hex
    }

    pub fn encrypt(&self, m: &BigUint) -> BigUint {
        let e = &self.public_key.e;
        let n = &self.public_key.n;

        m.modpow(&e, &n)
    }

    pub fn encrypt_bytes(&self, m: &Vec<u8>) -> BigUint {
        let m = BigUint::from_bytes_le(m);
        self.encrypt(&m)
    }


    pub fn decrypt(&self, c: &BigUint) -> BigUint {
        let d = &self.private_key.d;
        let n = &self.public_key.n;

        c.modpow(&d, &n)
    }

    pub fn decrypt_bytes(&self, c: &Vec<u8>) -> BigUint {
        let c = BigUint::from_bytes_le(c);
        self.decrypt(&c)
    }

    fn gen_random_1024_bits() -> BigUint {
        BigUint::from_u8(23).unwrap()
    }

    fn get_random_prime(bits: u64, safety: u64) -> BigUint {
        loop {
            let mut rng = thread_rng();
            let mut n = rng.gen_biguint(bits as usize);
            n |= BigUint::one() << bits as usize;
            if is_prime(&n, safety) {
                return n;
            }
        }
    }
}

pub fn is_prime(n: &BigUint, k: u64) -> bool {
    let one: BigUint = One::one();
    let mut d: BigUint = n - &one;
    let mut s = 0;

    // check if d is evene
    while &d % 2u8 != one {
        d /= 2u8;
        s += 1;
    }

    for _ in 0..k {
        let a = thread_rng().gen_biguint_range(&2.to_biguint().unwrap(), &(n - 2u8));
        let mut x = a.modpow(&d, &n);

        let mut y = x.modpow(&2.to_biguint().unwrap(), &n);
        for _ in 0..s {
            y = x.modpow(&2.to_biguint().unwrap(), &n);
            if y == 1.to_biguint().unwrap() && x != 1.to_biguint().unwrap() && x != n - 1u8 {
                return false;
            }
            x = y;
        }
        if x != 1.to_biguint().unwrap() {
            return false;
        }
    }

    true
}

pub fn carmichael_lambda(p: &BigUint, q: &BigUint) -> BigUint {
    let one: BigUint = One::one();
    let p_minus_one = p - &one;
    let q_minus_one = q - &one;

    let lambda = lcm(p_minus_one, q_minus_one);

    lambda
}

fn is_one_of_first_primes(n: &BigUint) -> bool {
    let first_primes: Vec<u32> = vec![
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
        97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
        191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
        283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
    ];

    for i in 0..first_primes.len() {
        if n == &first_primes[i].to_biguint().unwrap() {
            return true;
        }
    }

    true
}


fn random_prime_between(p: &BigUint, q: &BigUint, precision: u64 ) -> BigUint {
    let mut rng = thread_rng();
    let mut n = rng.gen_biguint_range(p, q);

    while !is_prime(&n, precision) {
        n = rng.gen_biguint_range(p, q);
    }

    n
}
