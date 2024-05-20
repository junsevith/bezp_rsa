use num_bigint::{BigUint, RandBigInt};
use num_integer::{Integer, lcm};
use num_prime::nt_funcs::is_prime;
use num_prime::RandPrime;
use rand::thread_rng;

fn main() {}

fn rsa_gen_keys(p: BigUint, q: BigUint) -> Result<(BigUint, BigUint, BigUint), String> {
    return if !is_prime(&p, None).probably() || !is_prime(&q, None).probably() {
        Err("p and q must be prime".to_string())
    } else {
        let n = &p * &q;
        let phi = (p - 1u32) * (q - 1u32);
        // let phi = lcm(&p - 1u32, &q - 1u32);
        // let e = BigUint::from(65537u32);
        // let e: BigUint = thread_rng().gen_prime((n.bits() - 1) as usize, None);
        let e = rand_coprime(&phi);
        let d = e.modinv(&phi).ok_or("e and phi must be coprime")?;
        Ok((n, e, d))
    };
}

fn rsa_gen_keys_usize(p: usize, q: usize) -> Result<(BigUint, BigUint, BigUint), String> {
    rsa_gen_keys(BigUint::from(p), BigUint::from(q))
}

fn rsa_get_pq(n: BigUint, pubk: BigUint, privk: BigUint) -> (BigUint, BigUint) {
    // println!("n: {:?}, pubk: {:?}, privk: {:?}", n, pubk, privk);
    let mut t = privk * pubk - 1u32;
    let kphi = t.clone();
    // println!("kphi: {:?}", kphi);
    while t.is_even() {
        t >>= 1;
    }
    let one = &BigUint::from(1usize);
    let two = &BigUint::from(2usize);

    let mut a = two.clone();

    loop {
        // println!("a: {:?}", a);
        let mut k = t.clone();
        while k < kphi {
            // println!("k: {:?}", k);
            let x = a.modpow(&k, &n);
            if &x != one &&
                x != &n - 1u32 &&
                x.modpow(two,&n) == *one
            {
                println!("a: {:?}, k: {:?}, x: {:?}", a, k, x);
                let r = n.gcd(&(x - 1u32));
                return (&n / &r, r);
            }
            k *= two;
        }
        a += 2u32;
    }
}

fn rand_coprime(n: &BigUint) -> BigUint {
    let mut rng = thread_rng();
    let one = BigUint::from(1usize);
    loop {
        let e = rng.gen_biguint(n.bits());
        if e.gcd(&n) == one {
            return e;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_test() {
        let mut rng = thread_rng();
        let primesize = 50;
        let p = rng.gen_prime(primesize, None);
        let q = rng.gen_prime(primesize, None);
        let (rmod, rpub, rpriv) = rsa_gen_keys(p, q).unwrap();
        let msg = "pies pajak";
        let msg = BigUint::from_bytes_be(msg.as_bytes());
        println!("Converted: {:?}", msg);
        println!("Conversion check: {:?}", String::from_utf8(msg.to_bytes_be()).unwrap());
        let encrypted = msg.modpow(&rpub, &rmod);
        println!("Encrypted: {:?}", encrypted);
        let decrypted = encrypted.modpow(&rpriv, &rmod);
        println!("Decrypted: {:?}", decrypted);
        let decrypted = decrypted.to_bytes_be();
        let decrypted = String::from_utf8(decrypted).unwrap();
        println!("Message: {:?}", decrypted);
    }

    #[test]
    fn rsa_crack_test() {
        let mut rng = thread_rng();
        let primesize = 1024;
        let p: BigUint = rng.gen_prime(primesize, None);
        let q: BigUint = rng.gen_prime(primesize, None);
        println!("Primes: {:?}, {:?}", p, q);
        let a = rsa_gen_keys(p.clone(), q.clone()).unwrap();
        println!("Generated a: {:?}", a);
        let b = rsa_gen_keys(p, q).unwrap();
        println!("Generated b: {:?}", b);
        let res = rsa_get_pq(a.0, a.1, a.2);
        println!("Cracked: {:?}", res);
        let phi = (res.0 - 1u32) * (res.1 - 1u32);
        let d = b.1.modinv(&phi).unwrap();
        println!("Private key b: {:?}", d);
    }
}