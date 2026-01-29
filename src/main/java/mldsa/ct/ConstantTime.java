package mldsa.ct;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;

/**
 * Constant-time utility functions for cryptographic operations.
 * All operations are designed to execute in constant time regardless of input values,
 * preventing timing side-channel attacks.
 *
 * <p>These functions avoid branching on secret values and use only arithmetic
 * and bitwise operations.</p>
 */
public final class ConstantTime {

    private ConstantTime() {
        // Utility class
    }

    /**
     * Constant-time equality comparison.
     * Returns 0xFFFFFFFF (-1) if a == b, 0 otherwise.
     *
     * @param a first value
     * @param b second value
     * @return -1 if equal, 0 otherwise
     */
    public static int equals(int a, int b) {
        int diff = a ^ b;
        // If diff == 0: (diff - 1) is 0xFFFFFFFF, and ~diff is 0xFFFFFFFF
        // So (diff - 1) & ~diff has high bit set
        // If diff != 0: (diff - 1) may or may not have high bit, but diff has at least one bit
        // ~diff clears that bit, so (diff - 1) & ~diff doesn't have the pattern
        return ((diff - 1) & ~diff) >> 31;
    }

    /**
     * Constant-time not-equal comparison.
     * Returns 0xFFFFFFFF (-1) if a != b, 0 otherwise.
     *
     * @param a first value
     * @param b second value
     * @return -1 if not equal, 0 otherwise
     */
    public static int notEquals(int a, int b) {
        return ~equals(a, b);
    }

    /**
     * Constant-time less-than comparison (unsigned).
     * Returns 0xFFFFFFFF (-1) if a < b (unsigned), 0 otherwise.
     *
     * @param a first value (treated as unsigned)
     * @param b second value (treated as unsigned)
     * @return -1 if a < b, 0 otherwise
     */
    public static int lessThanUnsigned(int a, int b) {
        // For unsigned comparison, we need to handle the sign bit carefully
        // If both have same sign bit, regular subtraction works
        // If different sign bits, the one with 0 sign bit is smaller (in unsigned)
        int diff = a - b;
        int signA = a >>> 31;
        int signB = b >>> 31;
        int signDiff = diff >>> 31;

        // If signA == signB: result is signDiff
        // If signA != signB: result is signA (because if a has sign bit, it's larger unsigned)
        int sameSign = equals(signA, signB);
        return (sameSign & -(signDiff)) | (~sameSign & -(signA ^ 1));
    }

    /**
     * Constant-time greater-than comparison (unsigned).
     * Returns 0xFFFFFFFF (-1) if a > b (unsigned), 0 otherwise.
     *
     * @param a first value (treated as unsigned)
     * @param b second value (treated as unsigned)
     * @return -1 if a > b, 0 otherwise
     */
    public static int greaterThanUnsigned(int a, int b) {
        return lessThanUnsigned(b, a);
    }

    /**
     * Constant-time less-than comparison (signed).
     * Returns 0xFFFFFFFF (-1) if a < b (signed), 0 otherwise.
     *
     * @param a first value
     * @param b second value
     * @return -1 if a < b, 0 otherwise
     */
    public static int lessThan(int a, int b) {
        int diff = a - b;
        // Overflow can occur; handle by checking signs
        int signA = a >> 31;
        int signB = b >> 31;
        int signDiff = diff >> 31;

        // If signs of a and b are the same, result is sign of diff
        // If signs differ, a < b iff a is negative
        int sameSign = equals(signA, signB);
        return (sameSign & signDiff) | (~sameSign & signA);
    }

    /**
     * Constant-time greater-than comparison (signed).
     * Returns 0xFFFFFFFF (-1) if a > b (signed), 0 otherwise.
     *
     * @param a first value
     * @param b second value
     * @return -1 if a > b, 0 otherwise
     */
    public static int greaterThan(int a, int b) {
        return lessThan(b, a);
    }

    /**
     * Constant-time conditional select.
     * Returns a if mask is 0xFFFFFFFF (-1), b if mask is 0.
     *
     * @param mask the selection mask (-1 or 0)
     * @param a value to return if mask is -1
     * @param b value to return if mask is 0
     * @return a if mask is -1, b if mask is 0
     */
    public static int select(int mask, int a, int b) {
        return (mask & a) | (~mask & b);
    }

    /**
     * Constant-time conditional select for longs.
     *
     * @param mask the selection mask (-1 or 0)
     * @param a value to return if mask is -1
     * @param b value to return if mask is 0
     * @return a if mask is -1, b if mask is 0
     */
    public static long select(int mask, long a, long b) {
        long longMask = mask; // Sign-extends to 64 bits
        return (longMask & a) | (~longMask & b);
    }

    /**
     * Constant-time byte array comparison.
     * Returns true if arrays are equal (same length and same contents), false otherwise.
     * Always examines all bytes of the shorter array regardless of when a difference is found.
     * The length comparison is also folded into the result to avoid early exit timing leak.
     *
     * @param a first array
     * @param b second array
     * @return true if arrays are equal
     */
    public static boolean arraysEqual(byte[] a, byte[] b) {
        // Fold length difference into result (non-zero if lengths differ)
        int diff = a.length ^ b.length;
        // Compare all bytes up to the minimum length
        int minLen = Math.min(a.length, b.length);
        for (int i = 0; i < minLen; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    /**
     * Constant-time conditional copy.
     * If mask is -1, copies src to dst; if mask is 0, dst is unchanged.
     *
     * @param mask the copy mask (-1 or 0)
     * @param dst destination array
     * @param src source array
     */
    public static void conditionalCopy(int mask, byte[] dst, byte[] src) {
        for (int i = 0; i < dst.length && i < src.length; i++) {
            dst[i] = (byte) select(mask, src[i], dst[i]);
        }
    }

    /**
     * Constant-time conditional copy for int arrays.
     *
     * @param mask the copy mask (-1 or 0)
     * @param dst destination array
     * @param src source array
     */
    public static void conditionalCopy(int mask, int[] dst, int[] src) {
        for (int i = 0; i < dst.length && i < src.length; i++) {
            dst[i] = select(mask, src[i], dst[i]);
        }
    }

    /**
     * Securely zeros a byte array.
     * Uses memory fence to prevent compiler optimization from removing the zeroing.
     *
     * @param array the array to zero
     */
    public static void zero(byte[] array) {
        for (int i = 0; i < array.length; i++) {
            array[i] = 0;
        }
        // Memory fence to ensure writes are not optimized away
        VarHandle.fullFence();
    }

    /**
     * Securely zeros an int array.
     *
     * @param array the array to zero
     */
    public static void zero(int[] array) {
        for (int i = 0; i < array.length; i++) {
            array[i] = 0;
        }
        VarHandle.fullFence();
    }

    /**
     * Converts a boolean condition to a mask.
     * Returns -1 if condition is true, 0 if false.
     *
     * @param condition the condition
     * @return -1 if true, 0 if false
     */
    public static int boolToMask(boolean condition) {
        // Convert boolean to 0 or 1, then to 0 or -1
        return -(condition ? 1 : 0);
    }

    /**
     * Constant-time swap of two values in an array.
     *
     * @param array the array
     * @param i first index
     * @param j second index
     * @param doSwap swap mask (-1 to swap, 0 to not swap)
     */
    public static void swap(int[] array, int i, int j, int doSwap) {
        int diff = doSwap & (array[i] ^ array[j]);
        array[i] ^= diff;
        array[j] ^= diff;
    }

    /**
     * Constant-time absolute value.
     * Uses bit manipulation to avoid conditional branches.
     *
     * @param x the input value
     * @return |x|
     */
    public static int abs(int x) {
        int sign = x >> 31;  // -1 if negative, 0 if non-negative
        return (x ^ sign) - sign;
    }

    /**
     * Constant-time maximum of two signed values.
     *
     * @param a first value
     * @param b second value
     * @return max(a, b)
     */
    public static int max(int a, int b) {
        int gt = greaterThan(a, b);  // -1 if a > b, 0 otherwise
        return select(gt, a, b);
    }

    /**
     * Constant-time minimum of two signed values.
     *
     * @param a first value
     * @param b second value
     * @return min(a, b)
     */
    public static int min(int a, int b) {
        int lt = lessThan(a, b);  // -1 if a < b, 0 otherwise
        return select(lt, a, b);
    }

    /**
     * Constant-time center reduction for ML-DSA.
     * Maps a value in [0, q) to centered form in [-(q-1)/2, (q-1)/2].
     * Uses branchless arithmetic to avoid timing side-channels.
     *
     * @param x value in [0, q)
     * @param q the modulus
     * @return centered value
     */
    public static int centerReduce(int x, int q) {
        int halfQ = (q - 1) / 2;
        // overHalf is -1 if x > halfQ, 0 otherwise
        int overHalf = (halfQ - x) >> 31;
        // If x > halfQ, return x - q; otherwise return x
        return x + (overHalf & (-q));
    }
}
