package mldsa;

import mldsa.ntt.Montgomery;
import mldsa.params.Parameters;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for Montgomery arithmetic operations.
 */
class MontgomeryTests {

    @Test
    @DisplayName("Montgomery constants are correct")
    void testConstants() {
        assertEquals(8380417, Montgomery.Q);
        assertEquals(2365951, Montgomery.R2_MOD_Q);
        assertEquals(58728449L, Montgomery.Q_INV);
    }

    @Test
    @DisplayName("Montgomery reduction produces correct results")
    void testReduce() {
        // reduce(a) = a * R^{-1} mod q
        // If a = x * R, then reduce(a) = x

        // Test with simple values
        int a = 12345;
        int aMont = Montgomery.toMontgomery(a);
        int aBack = Montgomery.fromMontgomery(aMont);
        assertEquals(a, aBack, "Round-trip through Montgomery form should preserve value");
    }

    @Test
    @DisplayName("Montgomery multiplication is correct")
    void testMultiply() {
        int a = 1234;
        int b = 5678;
        int expected = (int) (((long) a * b) % Parameters.Q);

        // Convert to Montgomery form, multiply, convert back
        int aMont = Montgomery.toMontgomery(a);
        int bMont = Montgomery.toMontgomery(b);
        int productMont = Montgomery.multiply(aMont, bMont);
        int product = Montgomery.fromMontgomery(productMont);

        assertEquals(expected, product, "Montgomery multiplication should produce correct result");
    }

    @Test
    @DisplayName("Modular addition is correct")
    void testAdd() {
        // Normal case - add just adds (doesn't reduce)
        int a = 1000;
        int b = 2000;
        assertEquals(3000, Montgomery.add(a, b));

        // For full reduction, use freeze after add
        int c = Parameters.Q - 100;
        int d = 200;
        assertEquals(100, Montgomery.freeze(Montgomery.add(c, d)));
    }

    @Test
    @DisplayName("Modular subtraction is correct")
    void testSubtract() {
        // Normal case
        int a = 3000;
        int b = 1000;
        assertEquals(2000, Montgomery.subtract(a, b));

        // For wraparound, use freeze
        int c = 100;
        int d = 200;
        assertEquals(Parameters.Q - 100, Montgomery.freeze(Montgomery.subtract(c, d)));
    }

    @Test
    @DisplayName("Freeze reduces to [0, Q)")
    void testFreeze() {
        // Positive value < q
        assertEquals(1000, Montgomery.freeze(1000));

        // Value >= q
        assertEquals(100, Montgomery.freeze(Parameters.Q + 100));

        // Negative value
        assertEquals(Parameters.Q - 100, Montgomery.freeze(-100));
    }

    @Test
    @DisplayName("Center reduction works correctly")
    void testCenterReduce() {
        // Value in lower half stays positive
        int lower = 1000;
        assertEquals(1000, Montgomery.centerReduce(lower));

        // Value in upper half becomes negative
        int upper = Parameters.Q - 1000;
        assertEquals(-1000, Montgomery.centerReduce(upper));

        // Boundary case
        // halfQ = (Q-1)/2 = 4190208
        // centerReduce maps [0, Q) to [-(Q-1)/2, (Q-1)/2]
        int halfQ = (Parameters.Q - 1) / 2;
        assertEquals(halfQ, Montgomery.centerReduce(halfQ));
        // halfQ + 1 = 4190209, which maps to 4190209 - 8380417 = -4190208
        assertEquals(-halfQ, Montgomery.centerReduce(halfQ + 1));
    }

    @Test
    @DisplayName("Montgomery form handles edge cases")
    void testEdgeCases() {
        // Zero
        assertEquals(0, Montgomery.toMontgomery(0));
        assertEquals(0, Montgomery.fromMontgomery(0));

        // q - 1
        int qMinus1 = Parameters.Q - 1;
        int mont = Montgomery.toMontgomery(qMinus1);
        assertEquals(qMinus1, Montgomery.fromMontgomery(mont));
    }

    @Test
    @DisplayName("Multiplication associativity")
    void testMultiplyAssociativity() {
        int a = 123;
        int b = 456;
        int c = 789;

        int aMont = Montgomery.toMontgomery(a);
        int bMont = Montgomery.toMontgomery(b);
        int cMont = Montgomery.toMontgomery(c);

        // (a * b) * c
        int ab = Montgomery.multiply(aMont, bMont);
        int abc1 = Montgomery.multiply(ab, cMont);

        // a * (b * c)
        int bc = Montgomery.multiply(bMont, cMont);
        int abc2 = Montgomery.multiply(aMont, bc);

        assertEquals(abc1, abc2, "Montgomery multiplication should be associative");
    }

    @Test
    @DisplayName("Multiplication commutativity")
    void testMultiplyCommutativity() {
        int a = 12345;
        int b = 67890;

        int aMont = Montgomery.toMontgomery(a);
        int bMont = Montgomery.toMontgomery(b);

        int ab = Montgomery.multiply(aMont, bMont);
        int ba = Montgomery.multiply(bMont, aMont);

        assertEquals(ab, ba, "Montgomery multiplication should be commutative");
    }
}
