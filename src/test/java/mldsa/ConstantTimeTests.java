package mldsa;

import mldsa.ct.ConstantTime;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

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
}
