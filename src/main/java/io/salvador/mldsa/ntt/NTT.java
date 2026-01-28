package io.salvador.mldsa.ntt;

import io.salvador.mldsa.params.Parameters;
import io.salvador.mldsa.poly.Polynomial;

/**
 * Number Theoretic Transform (NTT) for polynomial multiplication.
 * Implements the Cooley-Tukey algorithm for forward NTT and
 * Gentleman-Sande algorithm for inverse NTT.
 *
 * <p>Based on the CRYSTALS-Dilithium reference implementation.</p>
 */
public final class NTT {

    private NTT() {
        // Utility class
    }

    /**
     * Computes the forward NTT of a polynomial in place.
     * Uses the Cooley-Tukey decimation-in-time algorithm.
     *
     * <p>Input coefficients should be in [0, q).
     * Output coefficients are in (-q, q).</p>
     *
     * @param p the polynomial to transform (modified in place)
     */
    public static void forward(Polynomial p) {
        int[] a = p.coefficients();
        int k = 0;

        // len goes: 128, 64, 32, 16, 8, 4, 2, 1
        for (int len = 128; len >= 1; len >>= 1) {
            for (int start = 0; start < Parameters.N; start += 2 * len) {
                int zeta = NTTTables.ZETAS[++k];
                for (int j = start; j < start + len; j++) {
                    int t = Montgomery.multiply(zeta, a[j + len]);
                    a[j + len] = a[j] - t;
                    a[j] = a[j] + t;
                }
            }
        }
    }

    /**
     * Computes the inverse NTT of a polynomial in place (invntt_tomont).
     * Uses the Gentleman-Sande decimation-in-frequency algorithm.
     *
     * <p>After this operation, the polynomial coefficients are in Montgomery form
     * (multiplied by R = 2^32). To get back to standard form, call
     * {@link #fromMontgomery(Polynomial)} on the result.</p>
     *
     * @param p the polynomial to transform (modified in place)
     */
    public static void inverse(Polynomial p) {
        int[] a = p.coefficients();
        int k = 256;

        // len goes: 1, 2, 4, 8, 16, 32, 64, 128
        for (int len = 1; len < Parameters.N; len <<= 1) {
            for (int start = 0; start < Parameters.N; start += 2 * len) {
                int zeta = -NTTTables.ZETAS[--k];
                for (int j = start; j < start + len; j++) {
                    int t = a[j];
                    a[j] = t + a[j + len];
                    a[j + len] = t - a[j + len];
                    a[j + len] = Montgomery.multiply(zeta, a[j + len]);
                }
            }
        }

        // Scale by f = mont^2/256 and leave result in Montgomery form
        int f = NTTTables.F;
        for (int i = 0; i < Parameters.N; i++) {
            a[i] = Montgomery.multiply(f, a[i]);
        }
    }

    /**
     * Reduces all coefficients to [0, q).
     *
     * @param p the polynomial to reduce (modified in place)
     */
    public static void reduce(Polynomial p) {
        int[] a = p.coefficients();
        for (int i = 0; i < Parameters.N; i++) {
            a[i] = Montgomery.freeze(a[i]);
        }
    }

    /**
     * Converts a polynomial to Montgomery form (each coefficient * R mod q).
     * Used when preparing polynomials for NTT multiplication.
     *
     * @param p the polynomial to convert (modified in place)
     */
    public static void toMontgomery(Polynomial p) {
        int[] a = p.coefficients();
        for (int i = 0; i < Parameters.N; i++) {
            a[i] = Montgomery.toMontgomery(a[i]);
        }
    }

    /**
     * Converts a polynomial from Montgomery form (each coefficient * R^{-1} mod q).
     * Used when extracting results after NTT multiplication.
     *
     * @param p the polynomial to convert (modified in place)
     */
    public static void fromMontgomery(Polynomial p) {
        int[] a = p.coefficients();
        for (int i = 0; i < Parameters.N; i++) {
            a[i] = Montgomery.fromMontgomery(a[i]);
        }
    }
}
