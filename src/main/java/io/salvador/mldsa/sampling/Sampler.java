package io.salvador.mldsa.sampling;

import io.salvador.mldsa.ct.ConstantTime;
import io.salvador.mldsa.hash.Shake;
import io.salvador.mldsa.params.Parameters;
import io.salvador.mldsa.poly.Polynomial;
import io.salvador.mldsa.poly.PolynomialVector;

/**
 * Sampling operations for ML-DSA.
 * Includes centered binomial distribution for secrets and challenge polynomial generation.
 */
public final class Sampler {

    private Sampler() {
        // Utility class
    }

    /**
     * Samples a polynomial vector from the centered binomial distribution.
     * Coefficients are in [-eta, eta].
     *
     * @param params the parameter set (determines eta)
     * @param seed the seed for sampling
     * @param nonce starting nonce value
     * @param dimension the vector dimension (k or l)
     * @return a polynomial vector with coefficients in [-eta, eta] reduced mod q
     */
    public static PolynomialVector sampleCBD(Parameters params, byte[] seed, int nonce, int dimension) {
        Polynomial[] polys = new Polynomial[dimension];
        for (int i = 0; i < dimension; i++) {
            polys[i] = sampleCBDPolynomial(params, seed, nonce + i);
        }
        return new PolynomialVector(polys);
    }

    /**
     * Samples a single polynomial from the centered binomial distribution.
     *
     * @param params the parameter set (determines eta)
     * @param seed the seed
     * @param nonce the nonce value
     * @return a polynomial with coefficients in [-eta, eta] reduced mod q
     */
    public static Polynomial sampleCBDPolynomial(Parameters params, byte[] seed, int nonce) {
        int eta = params.eta();

        // Create input: seed || nonce (as 2-byte little-endian)
        byte[] input = new byte[seed.length + 2];
        System.arraycopy(seed, 0, input, 0, seed.length);
        input[seed.length] = (byte) (nonce & 0xFF);
        input[seed.length + 1] = (byte) ((nonce >> 8) & 0xFF);

        // Number of bytes needed: eta * n / 4
        int bytesNeeded = eta * Parameters.N / 4;
        byte[] stream = Shake.shake256(input, bytesNeeded);

        int[] coeffs = new int[Parameters.N];

        if (eta == 2) {
            sampleCBD2(coeffs, stream);
        } else if (eta == 4) {
            sampleCBD4(coeffs, stream);
        } else {
            throw new IllegalArgumentException("Unsupported eta value: " + eta);
        }

        return new Polynomial(coeffs);
    }

    /**
     * CBD sampling for eta = 2.
     * Uses 4 bits per coefficient (2 bits for each sum).
     */
    private static void sampleCBD2(int[] coeffs, byte[] stream) {
        int coeffIndex = 0;
        for (int i = 0; i < stream.length && coeffIndex < Parameters.N; i++) {
            int b = stream[i] & 0xFF;

            // Extract 4 coefficients from each byte
            // Each coefficient uses 2 bits (sum of 2 bits - sum of 2 bits)
            for (int j = 0; j < 4 && coeffIndex < Parameters.N; j++) {
                int bits = (b >> (2 * j)) & 0x03;
                int a = bits & 1;
                int bb = (bits >> 1) & 1;
                int coeff = a - bb;
                // Convert to [0, q): if negative, add q
                coeffs[coeffIndex++] = coeff < 0 ? coeff + Parameters.Q : coeff;
            }
        }
    }

    /**
     * CBD sampling for eta = 4.
     * Uses 8 bits per coefficient (4 bits for each sum).
     */
    private static void sampleCBD4(int[] coeffs, byte[] stream) {
        int coeffIndex = 0;
        for (int i = 0; i < stream.length && coeffIndex < Parameters.N; i++) {
            int b = stream[i] & 0xFF;

            // Extract 2 coefficients from each byte
            // Each coefficient uses 4 bits
            for (int j = 0; j < 2 && coeffIndex < Parameters.N; j++) {
                int bits = (b >> (4 * j)) & 0x0F;
                // Count bits: sum of lower 2 bits - sum of upper 2 bits
                int a = (bits & 1) + ((bits >> 1) & 1);
                int bb = ((bits >> 2) & 1) + ((bits >> 3) & 1);
                int coeff = a - bb;
                // Convert to [0, q): if negative, add q
                coeffs[coeffIndex++] = coeff < 0 ? coeff + Parameters.Q : coeff;
            }
        }
    }

    /**
     * Samples the challenge polynomial c with exactly tau coefficients being +/- 1.
     * This implements SampleInBall from FIPS 204.
     *
     * @param params the parameter set (determines tau)
     * @param seed the challenge seed (c_tilde)
     * @return a polynomial with tau coefficients +/- 1 and the rest 0
     */
    public static Polynomial sampleInBall(Parameters params, byte[] seed) {
        int tau = params.tau();
        int[] coeffs = new int[Parameters.N];

        // Use SHAKE256 to generate random bytes
        // Need enough bytes for tau position selections and tau sign bits
        // Each position needs up to 8 bits, plus tau sign bits
        byte[] stream = Shake.shake256(seed, 8 + tau + 256);

        // First 8 bytes are used for sign bits
        long signs = 0;
        for (int i = 0; i < 8; i++) {
            signs |= ((long) (stream[i] & 0xFF)) << (8 * i);
        }

        int streamIndex = 8;

        // Sample tau positions using rejection sampling
        // Algorithm from FIPS 204 Section 8.4
        for (int i = Parameters.N - tau; i < Parameters.N; i++) {
            // Sample j uniformly in [0, i]
            int j;
            while (true) {
                if (streamIndex >= stream.length) {
                    // Extend stream (shouldn't normally happen)
                    stream = Shake.shake256(seed, stream.length + 256);
                }
                j = stream[streamIndex++] & 0xFF;
                if (j <= i) {
                    break;
                }
            }

            // Swap c[i] and c[j], then set c[i] to +/- 1
            coeffs[i] = coeffs[j];

            // Sign bit determines +1 or -1
            int signBit = (int) ((signs >> (i - (Parameters.N - tau))) & 1);
            coeffs[j] = signBit == 0 ? 1 : Parameters.Q - 1; // -1 mod q
        }

        return new Polynomial(coeffs);
    }

    /**
     * Samples the masking vector y with coefficients in [-gamma1+1, gamma1].
     *
     * @param params the parameter set (determines gamma1)
     * @param seed the expanded seed K || rnd || mu
     * @param nonce the nonce (kappa value)
     * @return a polynomial vector with coefficients bounded by gamma1
     */
    public static PolynomialVector sampleMask(Parameters params, byte[] seed, int nonce) {
        int l = params.l();
        int gamma1 = params.gamma1();
        int gamma1Bits = params.gamma1Bits();

        Polynomial[] polys = new Polynomial[l];

        for (int i = 0; i < l; i++) {
            polys[i] = sampleMaskPolynomial(gamma1, gamma1Bits, seed, nonce + i);
        }

        return new PolynomialVector(polys);
    }

    /**
     * Samples a single masking polynomial.
     * Implements ExpandMask from FIPS 204 / Dilithium reference (polyz_unpack).
     * Coefficients are in the range [-(gamma1-1), gamma1].
     *
     * @param gamma1 the bound (2^17 or 2^19)
     * @param gamma1Bits number of bits per coefficient (18 or 20)
     * @param seed the seed
     * @param nonce the nonce
     * @return a polynomial with coefficients in [-(gamma1-1), gamma1]
     */
    private static Polynomial sampleMaskPolynomial(int gamma1, int gamma1Bits, byte[] seed, int nonce) {
        // Create input: seed || nonce (as 2-byte little-endian)
        byte[] input = new byte[seed.length + 2];
        System.arraycopy(seed, 0, input, 0, seed.length);
        input[seed.length] = (byte) (nonce & 0xFF);
        input[seed.length + 1] = (byte) ((nonce >> 8) & 0xFF);

        // Generate stream using SHAKE256
        // For gamma1 = 2^17 (ML-DSA-44): 18 bits per coeff, 256 coeffs = 576 bytes
        // For gamma1 = 2^19 (ML-DSA-65/87): 20 bits per coeff, 256 coeffs = 640 bytes
        int bytesNeeded = (gamma1Bits * Parameters.N + 7) / 8;
        byte[] stream = Shake.shake256(input, bytesNeeded);

        int[] coeffs = new int[Parameters.N];

        if (gamma1Bits == 18) {
            // ML-DSA-44: 4 coefficients from 9 bytes (4 * 18 = 72 bits = 9 bytes)
            unpackGamma1_18bit(stream, coeffs, gamma1);
        } else {
            // ML-DSA-65/87: 2 coefficients from 5 bytes (2 * 20 = 40 bits = 5 bytes)
            unpackGamma1_20bit(stream, coeffs, gamma1);
        }

        return new Polynomial(coeffs);
    }

    /**
     * Unpacks 18-bit gamma1 coefficients from byte stream.
     * Matches pq-crystals/dilithium polyz_unpack for GAMMA1 = 2^17.
     */
    private static void unpackGamma1_18bit(byte[] stream, int[] coeffs, int gamma1) {
        for (int i = 0; i < Parameters.N / 4; i++) {
            int off = 9 * i;

            // Extract 4 coefficients from 9 bytes
            int c0 = (stream[off] & 0xFF)
                   | ((stream[off + 1] & 0xFF) << 8)
                   | ((stream[off + 2] & 0xFF) << 16);
            c0 &= 0x3FFFF; // 18 bits

            int c1 = ((stream[off + 2] & 0xFF) >> 2)
                   | ((stream[off + 3] & 0xFF) << 6)
                   | ((stream[off + 4] & 0xFF) << 14);
            c1 &= 0x3FFFF;

            int c2 = ((stream[off + 4] & 0xFF) >> 4)
                   | ((stream[off + 5] & 0xFF) << 4)
                   | ((stream[off + 6] & 0xFF) << 12);
            c2 &= 0x3FFFF;

            int c3 = ((stream[off + 6] & 0xFF) >> 6)
                   | ((stream[off + 7] & 0xFF) << 2)
                   | ((stream[off + 8] & 0xFF) << 10);
            c3 &= 0x3FFFF;

            // Transform: coeff = gamma1 - value, then reduce to [0, q)
            coeffs[4 * i + 0] = reduceGamma1Coeff(gamma1 - c0);
            coeffs[4 * i + 1] = reduceGamma1Coeff(gamma1 - c1);
            coeffs[4 * i + 2] = reduceGamma1Coeff(gamma1 - c2);
            coeffs[4 * i + 3] = reduceGamma1Coeff(gamma1 - c3);

        }
    }

    /**
     * Unpacks 20-bit gamma1 coefficients from byte stream.
     * Matches pq-crystals/dilithium polyz_unpack for GAMMA1 = 2^19.
     */
    private static void unpackGamma1_20bit(byte[] stream, int[] coeffs, int gamma1) {
        for (int i = 0; i < Parameters.N / 2; i++) {
            int off = 5 * i;

            // Extract 2 coefficients from 5 bytes
            int c0 = (stream[off] & 0xFF)
                   | ((stream[off + 1] & 0xFF) << 8)
                   | ((stream[off + 2] & 0xFF) << 16);
            c0 &= 0xFFFFF; // 20 bits

            int c1 = ((stream[off + 2] & 0xFF) >> 4)
                   | ((stream[off + 3] & 0xFF) << 4)
                   | ((stream[off + 4] & 0xFF) << 12);
            c1 &= 0xFFFFF;

            // Transform: coeff = gamma1 - value, then reduce to [0, q)
            coeffs[2 * i + 0] = reduceGamma1Coeff(gamma1 - c0);
            coeffs[2 * i + 1] = reduceGamma1Coeff(gamma1 - c1);
        }
    }

    /**
     * Reduces a gamma1 coefficient to [0, q).
     * Input is in range [-(gamma1-1), gamma1].
     */
    private static int reduceGamma1Coeff(int coeff) {
        return coeff < 0 ? coeff + Parameters.Q : coeff;
    }
}
