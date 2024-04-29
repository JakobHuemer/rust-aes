use modpow::*;
use num::{integer::lcm, FromPrimitive};
use num_bigint::{BigInt, BigUint, RandBigInt, RandomBits, ToBigInt, ToBigUint};
use num_traits::{Inv, One};
use rand::{thread_rng, Rng};

pub struct RsaClient {
    pub private_key: BigUint,
    pub public_key: (BigUint, BigUint),
}

impl RsaClient {
    pub fn new() -> RsaClient {
        let mut c = RsaClient {
            private_key: One::one(),
            public_key: (One::one(), One::one()) // n, e,
        };
        c.generate_keys();
        c
    }

    pub fn from(d: BigUint, n: BigUint, e: BigUint ) -> RsaClient {
        RsaClient {
            private_key: d,
            public_key: (n, e),
        }
    }

    pub fn generate_keys(&mut self) {
        let safety = 60;

        let mut p = Self::gen_random_1024_bits();
        // also use test_for_first_primes
        while !is_one_of_first_primes(&p) || !is_prime(&p, safety) {
            p = Self::gen_random_1024_bits()
        }

        let mut q = Self::gen_random_1024_bits();
        while !is_one_of_first_primes(&q) || !is_prime(&q, safety) {
            q = Self::gen_random_1024_bits()
        }

        let n = &q * &p;

        let lambda = carmichael_lambda(&p, &q);

        let e: f64 = 65_537.0;

        let d = e.to_biguint().unwrap().modpow(&(&lambda - 1u8), &lambda);
        self.private_key = d;
        self.public_key = (n, e.to_biguint().unwrap());
        // print d as hex
    }

    pub fn encrypt(&self, m: &BigUint) -> BigUint {
        let n = &self.public_key.0;
        let e = &self.public_key.1;
        let c = m.modpow(&e, &n);
        c
    }

    pub fn decrypt(&self, c: &BigUint) -> BigUint {
        let n = &self.public_key.0;
        let d = &self.private_key;
        let m = c.modpow(&d, &n);
        m
    }

    fn gen_random_1024_bits() -> BigUint {
        thread_rng().gen_biguint(1024)
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
