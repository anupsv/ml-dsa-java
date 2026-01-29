package mldsa.poly;

import mldsa.ct.ConstantTime;
import mldsa.params.Parameters;

import java.util.Arrays;

/**
 * Represents a polynomial in the ring R_q = Z_q[X]/(X^n + 1) where n = 256 and q = 8380417.
 * Coefficients are stored as an array of n integers.
 *
 * <p>This class is mutable for performance in NTT operations.
 * Use {@link #copy()} when immutability is needed.</p>
 */
public final class Polynomial {

    /** The polynomial coefficients */
    private final int[] coeffs;

    /**
     * Creates a zero polynomial.
     */
    public Polynomial() {
        this.coeffs = new int[Parameters.N];
    }

    /**
     * Creates a polynomial with the given coefficients.
     * The array is copied to ensure immutability from external modifications.
     *
     * @param coefficients array of n coefficients
     * @throws IllegalArgumentException if the array length is not n
     */
    public Polynomial(int[] coefficients) {
        if (coefficients.length != Parameters.N) {
            throw new IllegalArgumentException(
                    "Polynomial must have " + Parameters.N + " coefficients, got " + coefficients.length);
        }
        this.coeffs = coefficients.clone();
    }

    /**
     * Creates a polynomial with a copy of another polynomial's coefficients.
     *
     * @param other the polynomial to copy
     */
    public Polynomial(Polynomial other) {
        this.coeffs = other.coeffs.clone();
    }

    /**
     * Gets a coefficient at the specified index.
     *
     * @param i the index (0 to n-1)
     * @return the coefficient value
     */
    public int get(int i) {
        return coeffs[i];
    }

    /**
     * Sets a coefficient at the specified index.
     *
     * @param i the index (0 to n-1)
     * @param value the coefficient value
     */
    public void set(int i, int value) {
        coeffs[i] = value;
    }

    /**
     * Returns the internal coefficient array.
     * Direct access for performance-critical operations like NTT.
     *
     * <p>WARNING: Modifications to this array will modify the polynomial.</p>
     *
     * @return the coefficient array (not a copy)
     */
    public int[] coefficients() {
        return coeffs;
    }

    /**
     * Creates a copy of this polynomial.
     *
     * @return a new Polynomial with copied coefficients
     */
    public Polynomial copy() {
        return new Polynomial(this);
    }

    /**
     * Sets all coefficients to zero.
     */
    public void clear() {
        Arrays.fill(coeffs, 0);
    }

    /**
     * Securely zeros all coefficients.
     * Uses memory fence to prevent compiler optimization from removing the zeroing.
     * Call this method when the polynomial contains secret material that should be erased.
     */
    public void destroy() {
        ConstantTime.zero(coeffs);
    }

    /**
     * Computes the infinity norm (maximum absolute coefficient value).
     * Uses centered reduction so coefficients are in [-(q-1)/2, (q-1)/2].
     * Constant-time implementation using branchless arithmetic.
     *
     * @return the infinity norm
     */
    public int infinityNorm() {
        int max = 0;
        int halfQ = (Parameters.Q - 1) / 2;
        for (int c : coeffs) {
            // Branchless center reduction: if c > halfQ, compute c - Q
            int overHalf = (halfQ - c) >> 31;  // -1 if c > halfQ, 0 otherwise
            int centered = c + (overHalf & (-Parameters.Q));

            // Branchless absolute value
            int sign = centered >> 31;  // -1 if negative, 0 otherwise
            int abs = (centered ^ sign) - sign;

            // Branchless max: update max if abs > max
            int isGreater = (max - abs) >> 31;  // -1 if abs > max, 0 otherwise
            max = (isGreater & abs) | (~isGreater & max);
        }
        return max;
    }

    /**
     * Checks if all coefficients are within the bound [-bound, bound] (centered).
     * Constant-time implementation using branchless arithmetic to prevent timing leaks.
     *
     * @param bound the bound to check against
     * @return true if all coefficients satisfy |coefficient| <= bound
     */
    public boolean checkNorm(int bound) {
        int halfQ = (Parameters.Q - 1) / 2;
        int exceeded = 0;
        for (int c : coeffs) {
            // Branchless center reduction
            int overHalf = (halfQ - c) >> 31;  // -1 if c > halfQ, 0 otherwise
            int centered = c + (overHalf & (-Parameters.Q));

            // Branchless absolute value
            int sign = centered >> 31;  // -1 if negative, 0 otherwise
            int abs = (centered ^ sign) - sign;

            // Set bit if exceeded (constant-time OR accumulation)
            exceeded |= (bound - abs) >> 31;
        }
        return exceeded == 0;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof Polynomial other)) return false;
        return Arrays.equals(this.coeffs, other.coeffs);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(coeffs);
    }

    @Override
    public String toString() {
        return "Polynomial" + Arrays.toString(Arrays.copyOf(coeffs, Math.min(8, coeffs.length))) + "...";
    }
}
