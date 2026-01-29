package mldsa.ntt;

import mldsa.params.Parameters;

/**
 * Montgomery arithmetic for modular operations in Z_q where q = 8380417.
 *
 * <p>Following the CRYSTALS-Dilithium reference implementation.</p>
 */
public final class Montgomery {

    private Montgomery() {
        // Utility class
    }

    /** The prime modulus q = 2^23 - 2^13 + 1 = 8380417 */
    public static final int Q = Parameters.Q;

    /**
     * Montgomery constant: -q^{-1} mod 2^32 = 58728449
     * This satisfies: Q_INV * Q ≡ -1 (mod 2^32)
     */
    public static final long Q_INV = 58728449L;

    /**
     * R^2 mod Q where R = 2^32
     * Used for converting to Montgomery form.
     */
    public static final int R2_MOD_Q = 2365951;

    /**
     * Montgomery reduction: given a with |a| < 2^31 * Q,
     * computes a * 2^{-32} mod Q.
     *
     * Output is in range (-Q, Q).
     *
     * @param a the value to reduce
     * @return a * 2^{-32} mod Q
     */
    public static int reduce(long a) {
        // Compute t = a * Q_INV mod 2^32
        // Since we're in Java, int arithmetic naturally gives us mod 2^32
        int t = (int) (a * Q_INV);

        // Compute (a - t * Q) / 2^32
        // Note: a - t * Q ≡ 0 (mod 2^32), so the division is exact
        return (int) ((a - (long) t * Q) >> 32);
    }

    /**
     * Montgomery multiplication: computes a * b * 2^{-32} mod Q.
     *
     * Output is in range (-Q, Q).
     *
     * @param a first operand
     * @param b second operand
     * @return a * b * 2^{-32} mod Q
     */
    public static int multiply(int a, int b) {
        return reduce((long) a * b);
    }

    /**
     * Converts a value to Montgomery form: computes a * 2^32 mod Q.
     *
     * @param a the value to convert (in [0, Q))
     * @return a * 2^32 mod Q (Montgomery form)
     */
    public static int toMontgomery(int a) {
        return reduce((long) a * R2_MOD_Q);
    }

    /**
     * Converts a value from Montgomery form: computes a * 2^{-32} mod Q.
     *
     * @param a the value in Montgomery form
     * @return a * 2^{-32} mod Q (standard form, in [0, Q))
     */
    public static int fromMontgomery(int a) {
        int t = reduce(a);
        // Reduce to [0, Q)
        t += (t >> 31) & Q;
        return t;
    }

    /**
     * Freeze: reduces coefficient to standard representative in [0, Q).
     * Input must be in range (-2Q, 2Q).
     *
     * @param a the value to freeze
     * @return a mod Q in [0, Q)
     */
    public static int freeze(int a) {
        a += (a >> 31) & Q;  // if negative, add Q
        a -= Q;
        a += (a >> 31) & Q;  // if negative (was < Q), add Q back
        return a;
    }

    /**
     * Modular addition: computes (a + b) mod Q.
     * Inputs should be in (-Q, Q).
     *
     * @param a first operand
     * @param b second operand
     * @return (a + b) mod Q, may be in (-Q, Q)
     */
    public static int add(int a, int b) {
        return a + b;
    }

    /**
     * Modular subtraction: computes (a - b) mod Q.
     * Inputs should be in (-Q, Q).
     *
     * @param a first operand
     * @param b second operand
     * @return (a - b) mod Q, may be in (-Q, Q)
     */
    public static int subtract(int a, int b) {
        return a - b;
    }

    /**
     * Reduces a signed value to [0, Q).
     *
     * @param a the value to reduce
     * @return a mod Q in [0, Q)
     */
    public static int reduce32(int a) {
        return freeze(a);
    }

    /**
     * Computes the centered representative of a mod Q in [-(Q-1)/2, (Q-1)/2].
     *
     * @param a value in [0, Q)
     * @return centered representative
     */
    public static int centerReduce(int a) {
        // If a > Q/2, return a - Q (negative), otherwise return a
        // Branchless: subtract Q, then add Q back if result was negative before subtraction
        int t = a - (Q + 1) / 2;  // t < 0 iff a <= Q/2
        t += (t >> 31) & Q;       // if t < 0, add Q
        return t - (Q - 1) / 2;   // shift range to centered
    }
}
