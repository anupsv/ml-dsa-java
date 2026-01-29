package mldsa.sampling;

import mldsa.ct.ConstantTime;
import mldsa.hash.Shake;
import mldsa.params.Parameters;
import mldsa.poly.Polynomial;
import mldsa.poly.PolynomialVector;

/**
 * Sampling operations for ML-DSA.
 * Includes bounded rejection sampling for secrets and challenge polynomial generation.
 */
public final class Sampler {

    private Sampler() {
        // Utility class
    }

    /**
     * Samples a polynomial vector with coefficients in [-eta, eta].
     * Uses rejection sampling per FIPS 204 (ExpandS / RejBoundedPoly).
     *
     * @param params the parameter set (determines eta)
     * @param seed the seed for sampling (rho')
     * @param nonce starting nonce value
     * @param dimension the vector dimension (k or l)
     * @return a polynomial vector with coefficients in [-eta, eta] reduced mod q
     */
    public static PolynomialVector sampleBounded(Parameters params, byte[] seed, int nonce, int dimension) {
        Polynomial[] polys = new Polynomial[dimension];
        for (int i = 0; i < dimension; i++) {
            polys[i] = sampleBoundedPolynomial(params, seed, nonce + i);
        }
        return new PolynomialVector(polys);
    }

    /**
     * Backwards-compatible name; this is not CBD in ML-DSA (FIPS 204).
     *
     * @deprecated Use {@link #sampleBounded(Parameters, byte[], int, int)}.
     */
    @Deprecated
    public static PolynomialVector sampleCBD(Parameters params, byte[] seed, int nonce, int dimension) {
        return sampleBounded(params, seed, nonce, dimension);
    }

    /**
     * Samples a single polynomial with coefficients in [-eta, eta] using rejection sampling.
     *
     * @param params the parameter set (determines eta)
     * @param seed the seed
     * @param nonce the nonce value
     * @return a polynomial with coefficients in [-eta, eta] reduced mod q
     */
    public static Polynomial sampleBoundedPolynomial(Parameters params, byte[] seed, int nonce) {
        int eta = params.eta();
        int[] coeffs = new int[Parameters.N];
        int coeffIndex = 0;

        Shake.ShakeDigest xof = Shake.newShake256();
        xof.update(seed);
        xof.update((byte) (nonce & 0xFF));
        xof.update((byte) ((nonce >> 8) & 0xFF));

        // SHAKE256 has a 136-byte rate; squeeze in blocks to avoid per-byte allocations.
        byte[] stream = new byte[136];
        int streamIndex = stream.length;

        while (coeffIndex < Parameters.N) {
            if (streamIndex == stream.length) {
                xof.digest(stream, 0, stream.length);
                streamIndex = 0;
            }
            byte b = stream[streamIndex++];
            int low = b & 0x0F;
            int high = (b >>> 4) & 0x0F;

            int coeff = coeffFromHalfByte(low, eta);
            if (coeff != REJECT) {
                coeffs[coeffIndex++] = toModQ(coeff);
                if (coeffIndex == Parameters.N) {
                    break;
                }
            }

            coeff = coeffFromHalfByte(high, eta);
            if (coeff != REJECT) {
                coeffs[coeffIndex++] = toModQ(coeff);
            }
        }

        return new Polynomial(coeffs);
    }

    private static final int REJECT = Integer.MIN_VALUE;

    private static int coeffFromHalfByte(int b, int eta) {
        if (eta == 2) {
            if (b >= 15) {
                return REJECT;
            }
            int mapped = (b < 5) ? b : (b < 10) ? (b - 5) : (b - 10);
            return mapped <= 2 ? 2 - mapped : -(mapped - 2);
        }
        if (eta == 4) {
            if (b >= 9) {
                return REJECT;
            }
            return b <= 4 ? 4 - b : -(b - 4);
        }
        throw new IllegalArgumentException("Unsupported eta value: " + eta);
    }

    private static int toModQ(int coeff) {
        return coeff < 0 ? coeff + Parameters.Q : coeff;
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
