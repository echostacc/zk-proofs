pub struct SchnorrParams {
    pub p: u64, // prime modulus
    pub g: u64, // generator
}

impl SchnorrParams {
    pub fn new() -> Self {
        let p = 2305843009213693951u64; // 2^61 - 1
        let g = 2u64;

        SchnorrParams { p, g }
    }

    pub fn mod_pow(&self, base: u64, exp: u64) -> u64 {
        if exp == 0 {
            return 1;
        }

        let mut result = 1u128;
        let mut base = base as u128 % self.p as u128;
        let mut exp = exp;
        let p = self.p as u128;

        while exp > 0 {
            if exp % 2 == 1 {
                result = (result * base) % p;
            }
            exp >>= 1;
            base = (base * base) % p;
        }

        result as u64
    }
}

pub struct SchnorrKeypair {
    pub secret_key: u64,
    pub public_key: u64,
}

impl SchnorrKeypair {
    pub fn generate(params: &SchnorrParams) -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let secret_key = rng.gen_range(1..(params.p - 1)); // x - random in range [1, p-2]
        let public_key = params.mod_pow(params.g, secret_key); // y = g^x mod p

        SchnorrKeypair {
            secret_key,
            public_key,
        }
    }
}

pub struct SchnorrProof {
    pub commitment: u64, // t = g^r mod p
    pub challenge: u64,  // c - random number from verifier
    pub response: u64,   // s = r + c * x mod (p - 1)
}

impl SchnorrProof {
    // Commitment - prover creates t = g^r mod p
    pub fn create_commitment(params: &SchnorrParams) -> (u64, u64) {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let r = rng.gen_range(1..(params.p - 1)); // random value in range [1, p-2]
        let commitment = params.mod_pow(params.g, r); // t = g^r mod p
        (commitment, r)
    }

    // Response - prover computes s = r + c * x mod (p - 1)
    pub fn create_response(r: u64, challenge: u64, secret_key: u64, p: u64) -> u64 {
        // s = r + c * x mod (p - 1)
        let cx = (challenge as u128 * secret_key as u128) % (p - 1) as u128;
        let s = (r as u128 + cx) % (p - 1) as u128;
        s as u64
    }

    // Verification - verifier checks if g^s == t * y^c mod p
    pub fn verify(&self, params: &SchnorrParams, public_key: u64) -> bool {
        let left = params.mod_pow(params.g, self.response); // g^s mod p
        let right_part = params.mod_pow(public_key, self.challenge); // y^c mod p
        let right = ((self.commitment as u128 * right_part as u128) % params.p as u128) as u64; // t * y^c mod p

        left == right
    }
}
