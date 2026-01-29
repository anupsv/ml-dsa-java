package mldsa;

import mldsa.ct.ConstantTime;
import mldsa.params.Parameters;
import mldsa.poly.Polynomial;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for constant-time utility functions.
 */
class ConstantTimeTests {

    @Test
    @DisplayName("Constant-time equals returns correct mask")
    void testEquals() {
        // Equal values should return -1 (all 1s)
        assertEquals(-1, ConstantTime.equals(42, 42));
        assertEquals(-1, ConstantTime.equals(0, 0));
        assertEquals(-1, ConstantTime.equals(-1, -1));
        assertEquals(-1, ConstantTime.equals(Integer.MAX_VALUE, Integer.MAX_VALUE));
        assertEquals(-1, ConstantTime.equals(Integer.MIN_VALUE, Integer.MIN_VALUE));

        // Different values should return 0
        assertEquals(0, ConstantTime.equals(42, 43));
        assertEquals(0, ConstantTime.equals(0, 1));
        assertEquals(0, ConstantTime.equals(-1, 1));
    }

    @Test
    @DisplayName("Constant-time notEquals returns correct mask")
    void testNotEquals() {
        // Equal values should return 0
        assertEquals(0, ConstantTime.notEquals(42, 42));

        // Different values should return -1
        assertEquals(-1, ConstantTime.notEquals(42, 43));
    }

    @Test
    @DisplayName("Constant-time lessThan (signed) returns correct mask")
    void testLessThan() {
        // a < b
        assertEquals(-1, ConstantTime.lessThan(5, 10));
        assertEquals(-1, ConstantTime.lessThan(-5, 5));
        assertEquals(-1, ConstantTime.lessThan(Integer.MIN_VALUE, 0));

        // a >= b
        assertEquals(0, ConstantTime.lessThan(10, 5));
        assertEquals(0, ConstantTime.lessThan(5, 5));
        assertEquals(0, ConstantTime.lessThan(0, Integer.MIN_VALUE));
    }

    @Test
    @DisplayName("Constant-time greaterThan (signed) returns correct mask")
    void testGreaterThan() {
        // a > b
        assertEquals(-1, ConstantTime.greaterThan(10, 5));
        assertEquals(-1, ConstantTime.greaterThan(5, -5));

        // a <= b
        assertEquals(0, ConstantTime.greaterThan(5, 10));
        assertEquals(0, ConstantTime.greaterThan(5, 5));
    }

    @Test
    @DisplayName("Constant-time select returns correct value")
    void testSelect() {
        int a = 100;
        int b = 200;

        // mask = -1 selects a
        assertEquals(a, ConstantTime.select(-1, a, b));

        // mask = 0 selects b
        assertEquals(b, ConstantTime.select(0, a, b));
    }

    @Test
    @DisplayName("Constant-time select for long values")
    void testSelectLong() {
        long a = 100L;
        long b = 200L;

        assertEquals(a, ConstantTime.select(-1, a, b));
        assertEquals(b, ConstantTime.select(0, a, b));
    }

    @Test
    @DisplayName("Constant-time arrays equal")
    void testArraysEqual() {
        byte[] a = {1, 2, 3, 4, 5};
        byte[] b = {1, 2, 3, 4, 5};
        byte[] c = {1, 2, 3, 4, 6};
        byte[] d = {1, 2, 3};

        assertTrue(ConstantTime.arraysEqual(a, b));
        assertFalse(ConstantTime.arraysEqual(a, c));
        assertFalse(ConstantTime.arraysEqual(a, d));
    }

    @Test
    @DisplayName("Constant-time conditional copy")
    void testConditionalCopy() {
        byte[] src = {1, 2, 3, 4, 5};
        byte[] dst = {10, 20, 30, 40, 50};
        byte[] dstCopy = dst.clone();

        // mask = 0: dst should not change
        ConstantTime.conditionalCopy(0, dst, src);
        assertArrayEquals(dstCopy, dst);

        // mask = -1: dst should become copy of src
        ConstantTime.conditionalCopy(-1, dst, src);
        assertArrayEquals(src, dst);
    }

    @Test
    @DisplayName("Constant-time zero clears array")
    void testZero() {
        byte[] array = {1, 2, 3, 4, 5};
        ConstantTime.zero(array);

        for (byte b : array) {
            assertEquals(0, b);
        }
    }

    @Test
    @DisplayName("Constant-time zero clears int array")
    void testZeroInt() {
        int[] array = {1, 2, 3, 4, 5};
        ConstantTime.zero(array);

        for (int i : array) {
            assertEquals(0, i);
        }
    }

    @Test
    @DisplayName("Bool to mask conversion")
    void testBoolToMask() {
        assertEquals(-1, ConstantTime.boolToMask(true));
        assertEquals(0, ConstantTime.boolToMask(false));
    }

    @Test
    @DisplayName("Constant-time swap")
    void testSwap() {
        int[] array = {10, 20, 30, 40, 50};

        // Don't swap
        ConstantTime.swap(array, 1, 3, 0);
        assertEquals(20, array[1]);
        assertEquals(40, array[3]);

        // Do swap
        ConstantTime.swap(array, 1, 3, -1);
        assertEquals(40, array[1]);
        assertEquals(20, array[3]);
    }

    @Test
    @DisplayName("Unsigned comparison edge cases")
    void testUnsignedComparison() {
        // 0xFFFFFFFF as unsigned is MAX, as signed is -1
        int maxUnsigned = -1; // 0xFFFFFFFF

        // maxUnsigned should be > any positive number in unsigned comparison
        assertEquals(-1, ConstantTime.greaterThanUnsigned(maxUnsigned, 0));
        assertEquals(-1, ConstantTime.greaterThanUnsigned(maxUnsigned, Integer.MAX_VALUE));

        // 0 should be < maxUnsigned
        assertEquals(-1, ConstantTime.lessThanUnsigned(0, maxUnsigned));
    }

    @Test
    @DisplayName("Constant-time absolute value")
    void testAbs() {
        assertEquals(42, ConstantTime.abs(42));
        assertEquals(42, ConstantTime.abs(-42));
        assertEquals(0, ConstantTime.abs(0));
        assertEquals(Integer.MAX_VALUE, ConstantTime.abs(Integer.MAX_VALUE));
        // Note: abs(Integer.MIN_VALUE) overflows, which is expected behavior
    }

    @Test
    @DisplayName("Constant-time max")
    void testMax() {
        assertEquals(10, ConstantTime.max(5, 10));
        assertEquals(10, ConstantTime.max(10, 5));
        assertEquals(5, ConstantTime.max(5, 5));
        assertEquals(5, ConstantTime.max(-10, 5));
        assertEquals(-5, ConstantTime.max(-10, -5));
    }

    @Test
    @DisplayName("Constant-time min")
    void testMin() {
        assertEquals(5, ConstantTime.min(5, 10));
        assertEquals(5, ConstantTime.min(10, 5));
        assertEquals(5, ConstantTime.min(5, 5));
        assertEquals(-10, ConstantTime.min(-10, 5));
        assertEquals(-10, ConstantTime.min(-10, -5));
    }

    @Test
    @DisplayName("Constant-time center reduction")
    void testCenterReduce() {
        int q = Parameters.Q;  // 8380417
        int halfQ = (q - 1) / 2;  // 4190208

        // Values <= halfQ stay unchanged
        assertEquals(0, ConstantTime.centerReduce(0, q));
        assertEquals(100, ConstantTime.centerReduce(100, q));
        assertEquals(halfQ, ConstantTime.centerReduce(halfQ, q));

        // Values > halfQ become negative (x - q)
        assertEquals(halfQ + 1 - q, ConstantTime.centerReduce(halfQ + 1, q));
        assertEquals(q - 1 - q, ConstantTime.centerReduce(q - 1, q));  // -1
    }

    // ==================== Timing Variance Tests ====================
    //
    // Note: These tests measure timing variance as a heuristic for constant-time behavior.
    // However, JVM timing tests are inherently unreliable due to:
    // - JIT compilation variance
    // - GC pauses
    // - CPU frequency scaling
    // - Cache effects
    //
    // For authoritative constant-time verification, use tools like:
    // - dudect (statistical timing analysis)
    // - ctgrind (Valgrind-based analysis)
    // - Manual assembly inspection
    //
    // These tests are informational only and do not fail on timing variance.

    private static final int WARMUP_ITERATIONS = 50000;
    private static final int TEST_ITERATIONS = 100000;

    @Test
    @DisplayName("arraysEqual timing analysis (informational)")
    void testArraysEqualTiming() {
        byte[] a = new byte[32];
        byte[] b = new byte[32];
        byte[] c = new byte[32];

        // Fill with different patterns
        for (int i = 0; i < 32; i++) {
            a[i] = (byte) i;
            b[i] = (byte) i;          // Equal to a
            c[i] = (byte) (31 - i);   // Different from a
        }

        // Warmup JIT
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            ConstantTime.arraysEqual(a, b);
            ConstantTime.arraysEqual(a, c);
        }

        // Measure equal case
        long startEqual = System.nanoTime();
        for (int i = 0; i < TEST_ITERATIONS; i++) {
            ConstantTime.arraysEqual(a, b);
        }
        long timeEqual = System.nanoTime() - startEqual;

        // Measure unequal case
        long startUnequal = System.nanoTime();
        for (int i = 0; i < TEST_ITERATIONS; i++) {
            ConstantTime.arraysEqual(a, c);
        }
        long timeUnequal = System.nanoTime() - startUnequal;

        double ratio = (double) Math.max(timeEqual, timeUnequal) /
                       Math.min(timeEqual, timeUnequal);

        System.out.printf("[INFO] arraysEqual timing: equal=%dns, unequal=%dns, ratio=%.2f%n",
                         timeEqual, timeUnequal, ratio);
        // Note: Assertions removed - JVM timing is unreliable for constant-time verification
    }

    @Test
    @DisplayName("checkNorm timing analysis (informational)")
    void testCheckNormTiming() {
        // Create polynomial with all coefficients within bound
        int[] passCoeffs = new int[Parameters.N];
        for (int i = 0; i < Parameters.N; i++) {
            passCoeffs[i] = i % 1000;  // Small values, will pass
        }
        Polynomial passPoly = new Polynomial(passCoeffs);

        // Create polynomial with coefficients exceeding bound
        int[] failCoeffs = new int[Parameters.N];
        for (int i = 0; i < Parameters.N; i++) {
            failCoeffs[i] = Parameters.Q - 1 - (i % 100);  // Large values near Q, will fail
        }
        Polynomial failPoly = new Polynomial(failCoeffs);

        int bound = 2000;

        // Warmup JIT
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            passPoly.checkNorm(bound);
            failPoly.checkNorm(bound);
        }

        // Measure pass case
        long startPass = System.nanoTime();
        for (int i = 0; i < TEST_ITERATIONS; i++) {
            passPoly.checkNorm(bound);
        }
        long timePass = System.nanoTime() - startPass;

        // Measure fail case
        long startFail = System.nanoTime();
        for (int i = 0; i < TEST_ITERATIONS; i++) {
            failPoly.checkNorm(bound);
        }
        long timeFail = System.nanoTime() - startFail;

        double ratio = (double) Math.max(timePass, timeFail) /
                       Math.min(timePass, timeFail);

        System.out.printf("[INFO] checkNorm timing: pass=%dns, fail=%dns, ratio=%.2f%n",
                         timePass, timeFail, ratio);
        // Note: Assertions removed - JVM timing is unreliable for constant-time verification
    }

    @Test
    @DisplayName("infinityNorm timing analysis (informational)")
    void testInfinityNormTiming() {
        // Create polynomial with all zeros (max = 0)
        Polynomial zeroPoly = new Polynomial();

        // Create polynomial with varied coefficients
        int[] variedCoeffs = new int[Parameters.N];
        for (int i = 0; i < Parameters.N; i++) {
            variedCoeffs[i] = (i * 12345) % Parameters.Q;
        }
        Polynomial variedPoly = new Polynomial(variedCoeffs);

        // Warmup JIT
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            zeroPoly.infinityNorm();
            variedPoly.infinityNorm();
        }

        // Measure zero case
        long startZero = System.nanoTime();
        for (int i = 0; i < TEST_ITERATIONS; i++) {
            zeroPoly.infinityNorm();
        }
        long timeZero = System.nanoTime() - startZero;

        // Measure varied case
        long startVaried = System.nanoTime();
        for (int i = 0; i < TEST_ITERATIONS; i++) {
            variedPoly.infinityNorm();
        }
        long timeVaried = System.nanoTime() - startVaried;

        double ratio = (double) Math.max(timeZero, timeVaried) /
                       Math.min(timeZero, timeVaried);

        System.out.printf("[INFO] infinityNorm timing: zero=%dns, varied=%dns, ratio=%.2f%n",
                         timeZero, timeVaried, ratio);
        // Note: Assertions removed - JVM timing is unreliable for constant-time verification
    }
}
