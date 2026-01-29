package mldsa.core;

import mldsa.encode.ByteCodec;
import mldsa.hash.Shake;
import mldsa.hints.Power2Round;
import mldsa.ntt.NTT;
import mldsa.params.Parameters;
import mldsa.poly.Polynomial;
import mldsa.poly.PolyOps;
import mldsa.poly.PolynomialVector;
import mldsa.sampling.ExpandA;
import mldsa.sampling.Sampler;

import java.security.SecureRandom;

/**
 * ML-DSA Key Generation (Algorithm 1 in FIPS 204).
 * Generates a public/private key pair from a random seed.
 */
public final class KeyGen {

    private KeyGen() {
        // Utility class
    }

    /** Seed length in bytes */
    private static final int SEED_BYTES = 32;

    /**
     * Generates a key pair using a cryptographically secure random seed.
     *
     * @param params the parameter set
     * @return array [publicKey, privateKey] as byte arrays
     */
    public static byte[][] generate(Parameters params) {
        byte[] seed = new byte[SEED_BYTES];
        new SecureRandom().nextBytes(seed);
        return generate(params, seed);
    }

    /**
     * Generates a key pair from a specific seed (for deterministic testing).
     *
     * @param params the parameter set
     * @param seed the 32-byte seed
     * @return array [publicKey, privateKey] as byte arrays
     */
    public static byte[][] generate(Parameters params, byte[] seed) {
        if (seed.length != SEED_BYTES) {
            throw new IllegalArgumentException("Seed must be " + SEED_BYTES + " bytes");
        }

        int k = params.k();
        int l = params.l();

        // Step 1-2: Expand seed using SHAKE256 to get rho, rho', K
        // FIPS 204 Algorithm 6: H(ξ || k || l, 128) with domain separator
        // H(seed || k || l) = rho || rho' || K (32 + 64 + 32 = 128 bytes)
        byte[] seedWithDomainSep = new byte[seed.length + 2];
        System.arraycopy(seed, 0, seedWithDomainSep, 0, seed.length);
        seedWithDomainSep[seed.length] = (byte) k;
        seedWithDomainSep[seed.length + 1] = (byte) l;
        byte[] expanded = Shake.shake256(seedWithDomainSep, 128);

        byte[] rho = new byte[32];      // Seed for matrix A
        byte[] rhoPrime = new byte[64]; // Seed for secret vectors
        byte[] K = new byte[32];        // Signing key

        System.arraycopy(expanded, 0, rho, 0, 32);
        System.arraycopy(expanded, 32, rhoPrime, 0, 64);
        System.arraycopy(expanded, 96, K, 0, 32);

        // Step 3: Expand A from rho
        Polynomial[][] A = ExpandA.expandNTT(params, rho);

        // Step 4: Sample s1 and s2 from centered binomial distribution
        PolynomialVector s1 = Sampler.sampleCBD(params, rhoPrime, 0, l);
        PolynomialVector s2 = Sampler.sampleCBD(params, rhoPrime, l, k);

        // Step 5: Compute t = A * NTT(s1) + s2
        // First, transform s1 to NTT domain
        PolynomialVector s1Ntt = s1.copy();
        PolyOps.nttVector(s1Ntt);

        // Compute A * s1_ntt
        PolynomialVector t = matrixVectorMultiply(A, s1Ntt, k);

        // Transform back from NTT domain
        PolyOps.invNttVector(t);
        reduceVector(t);  // Reduce to [0, Q) after inverse NTT

        // Add s2
        t = PolyOps.add(t, s2);
        reduceVector(t);  // Reduce to [0, Q) before Power2Round

        // Step 6: Power2Round to get t1 (high bits) and t0 (low bits)
        PolynomialVector[] tParts = Power2Round.round(t);
        PolynomialVector t1 = tParts[0];
        PolynomialVector t0 = tParts[1];

        // Step 7: Encode public key
        byte[] publicKey = ByteCodec.encodePublicKey(rho, t1, params);

        // Step 8: Compute tr = H(pk)
        byte[] tr = Shake.shake256(publicKey, 64);

        // Step 9: Encode private key
        byte[] privateKey = ByteCodec.encodePrivateKey(rho, K, tr, s1, s2, t0, params);

        return new byte[][] { publicKey, privateKey };
    }

    /**
     * Computes matrix-vector multiplication A * v in NTT domain.
     * A is k x l, v is l x 1, result is k x 1.
     *
     * @param A the matrix (each element in NTT domain)
     * @param v the vector (each element in NTT domain)
     * @param k number of rows in result
     * @return A * v (each element in NTT domain)
     */
    public static PolynomialVector matrixVectorMultiply(Polynomial[][] A, PolynomialVector v, int k) {
        Polynomial[] result = new Polynomial[k];

        for (int i = 0; i < k; i++) {
            result[i] = new Polynomial();
            for (int j = 0; j < v.dimension(); j++) {
                PolyOps.pointwiseMultiplyAccumulate(result[i], A[i][j], v.get(j));
            }
        }

        return new PolynomialVector(result);
    }

    /**
     * Reduces all polynomials in a vector to [0, Q).
     */
    private static void reduceVector(PolynomialVector v) {
        for (Polynomial p : v.polynomials()) {
            PolyOps.reduce(p);
        }
    }
}
