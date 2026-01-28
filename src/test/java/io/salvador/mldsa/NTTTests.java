package io.salvador.mldsa;

import io.salvador.mldsa.ntt.Montgomery;
import io.salvador.mldsa.ntt.NTT;
import io.salvador.mldsa.ntt.NTTTables;
import io.salvador.mldsa.params.Parameters;
import io.salvador.mldsa.poly.Polynomial;
import io.salvador.mldsa.poly.PolyOps;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for NTT operations.
 */
class NTTTests {

    @Test
    @DisplayName("NTT tables are correctly computed")
    void testZetasComputed() {
        // Check that zetas array has correct length
        assertEquals(256, NTTTables.ZETAS.length);

        // Check that F = mont^2/256 = R^2 * n^{-1} mod q is correct
        // F = 2^64 * 256^{-1} mod 8380417 = 41978
        assertEquals(41978, NTTTables.F, "F should be mont^2/256 mod q");
    }

    @Test
    @DisplayName("NTT is invertible")
    void testNTTInvertible() {
        Random random = new Random(42);
        int[] coeffs = new int[Parameters.N];
        for (int i = 0; i < Parameters.N; i++) {
            coeffs[i] = random.nextInt(Parameters.Q);
        }

        Polynomial original = new Polynomial(coeffs.clone());
        Polynomial p = new Polynomial(coeffs);

        // Forward NTT
        NTT.forward(p);

        // Inverse NTT (produces Montgomery form)
        NTT.inverse(p);

        // Convert from Montgomery form to get back original
        NTT.fromMontgomery(p);

        // Should get back original
        assertArrayEquals(original.coefficients(), p.coefficients(),
                "NTT followed by inverse NTT should return original polynomial");
    }

    @Test
    @DisplayName("NTT multiplication matches schoolbook")
    void testNTTMultiplication() {
        Random random = new Random(123);

        // Create small random polynomials
        int[] aCoeffs = new int[Parameters.N];
        int[] bCoeffs = new int[Parameters.N];
        for (int i = 0; i < Parameters.N; i++) {
            aCoeffs[i] = random.nextInt(1000); // Keep coefficients small
            bCoeffs[i] = random.nextInt(1000);
        }

        Polynomial a = new Polynomial(aCoeffs);
        Polynomial b = new Polynomial(bCoeffs);

        // Schoolbook multiplication in R_q = Z_q[X]/(X^n + 1)
        Polynomial expected = schoolbookMultiply(a, b);

        // NTT multiplication (Dilithium style):
        // 1. NTT on standard form inputs (no toMontgomery needed - zetas are in Montgomery form)
        // 2. Pointwise multiply with Montgomery reduction
        // 3. Inverse NTT (invntt_tomont)
        // 4. Reduce to [0, Q) with freeze
        Polynomial aNtt = a.copy();
        Polynomial bNtt = b.copy();
        NTT.forward(aNtt);
        NTT.forward(bNtt);

        Polynomial productNtt = PolyOps.pointwiseMultiply(aNtt, bNtt);
        NTT.inverse(productNtt);
        NTT.reduce(productNtt);  // Reduce to [0, Q)

        // Compare
        assertArrayEquals(expected.coefficients(), productNtt.coefficients(),
                "NTT multiplication should match schoolbook multiplication");
    }

    @Test
    @DisplayName("NTT preserves zero polynomial")
    void testNTTZero() {
        Polynomial zero = new Polynomial();

        NTT.forward(zero);
        for (int i = 0; i < Parameters.N; i++) {
            assertEquals(0, zero.get(i), "NTT of zero should be zero");
        }

        NTT.inverse(zero);
        for (int i = 0; i < Parameters.N; i++) {
            assertEquals(0, zero.get(i), "Inverse NTT of zero should be zero");
        }
    }

    @Test
    @DisplayName("NTT of constant polynomial")
    void testNTTConstant() {
        int[] coeffs = new int[Parameters.N];
        coeffs[0] = 1; // Constant polynomial = 1

        Polynomial p = new Polynomial(coeffs);
        Polynomial original = p.copy();

        NTT.forward(p);
        NTT.inverse(p);
        NTT.fromMontgomery(p);

        // Should recover original
        assertArrayEquals(original.coefficients(), p.coefficients(),
                "NTT roundtrip of constant should recover original");
    }

    @Test
    @DisplayName("Multiple NTT roundtrips")
    void testMultipleRoundtrips() {
        Random random = new Random(999);
        int[] coeffs = new int[Parameters.N];
        for (int i = 0; i < Parameters.N; i++) {
            coeffs[i] = random.nextInt(Parameters.Q);
        }

        Polynomial original = new Polynomial(coeffs.clone());
        Polynomial p = new Polynomial(coeffs);

        // Multiple roundtrips
        for (int round = 0; round < 5; round++) {
            NTT.forward(p);
            NTT.inverse(p);
            NTT.fromMontgomery(p);
        }

        assertArrayEquals(original.coefficients(), p.coefficients(),
                "Multiple NTT roundtrips should preserve polynomial");
    }

    /**
     * Schoolbook polynomial multiplication in R_q = Z_q[X]/(X^n + 1).
     * O(n^2) complexity, used only for testing.
     */
    private Polynomial schoolbookMultiply(Polynomial a, Polynomial b) {
        int[] result = new int[Parameters.N];
        int[] aCoeffs = a.coefficients();
        int[] bCoeffs = b.coefficients();

        for (int i = 0; i < Parameters.N; i++) {
            for (int j = 0; j < Parameters.N; j++) {
                long product = (long) aCoeffs[i] * bCoeffs[j];
                int k = i + j;
                if (k < Parameters.N) {
                    result[k] = (int) ((result[k] + product) % Parameters.Q);
                } else {
                    // X^n = -1, so X^k = -X^{k-n} for k >= n
                    int idx = k - Parameters.N;
                    result[idx] = (int) ((result[idx] - product % Parameters.Q + Parameters.Q) % Parameters.Q);
                }
            }
        }

        // Ensure all coefficients are positive
        for (int i = 0; i < Parameters.N; i++) {
            if (result[i] < 0) {
                result[i] += Parameters.Q;
            }
        }

        return new Polynomial(result);
    }
}
