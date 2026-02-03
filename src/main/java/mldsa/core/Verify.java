package mldsa.core;

import mldsa.ct.ConstantTime;
import mldsa.encode.BitPacker;
import mldsa.encode.ByteCodec;
import mldsa.hash.Shake;
import mldsa.hints.UseHint;
import mldsa.ntt.NTT;
import mldsa.params.Parameters;
import mldsa.poly.Polynomial;
import mldsa.poly.PolyOps;
import mldsa.poly.PolynomialVector;
import mldsa.sampling.ExpandA;
import mldsa.sampling.Sampler;

/**
 * ML-DSA Verification (Algorithm 3 in FIPS 204).
 * Verifies a signature against a message and public key.
 */
public final class Verify {

    private Verify() {
        // Utility class
    }

    /**
     * Verifies a signature.
     *
     * @param params the parameter set
     * @param publicKey the encoded public key
     * @param message the signed message
     * @param signature the signature to verify
     * @return true if the signature is valid, false otherwise
     */
    public static boolean verify(Parameters params, byte[] publicKey, byte[] message, byte[] signature) {
        int k = params.k();
        int l = params.l();
        int gamma1 = params.gamma1();
        int gamma2 = params.gamma2();
        int beta = params.beta();
        int omega = params.omega();

        // Step 1: Decode public key
        Object[] pkParts = ByteCodec.decodePublicKey(publicKey, params);
        byte[] rho = (byte[]) pkParts[0];
        PolynomialVector t1 = (PolynomialVector) pkParts[1];

        // Step 2: Decode signature
        Object[] sigParts = ByteCodec.decodeSignature(signature, params);
        if (sigParts == null) {
            return false; // Invalid signature encoding
        }

        byte[] cTilde = (byte[]) sigParts[0];
        PolynomialVector z = (PolynomialVector) sigParts[1];
        PolynomialVector h = (PolynomialVector) sigParts[2];

        // Step 3: Check ||z||_inf < gamma1 - beta
        if (!z.checkNorm(gamma1 - beta - 1)) {
            return false;
        }

        // Step 4: Expand matrix A from rho
        Polynomial[][] A = ExpandA.expandNTT(params, rho);

        // Step 5: Compute tr = H(pk)
        byte[] tr = Shake.shake256(publicKey, 64);

        // Step 6: Compute mu = H(tr || M)
        byte[] mu = Shake.shake256(64, tr, message);

        // Step 7: Sample challenge c from c_tilde
        Polynomial c = Sampler.sampleInBall(params, cTilde);

        // Step 8: Compute w' = A * NTT(z) - c * NTT(t1 * 2^d)
        // First, transform z to NTT domain
        PolynomialVector zNtt = z.copy();
        PolyOps.nttVector(zNtt);

        // Compute A * z_ntt
        PolynomialVector Az = KeyGen.matrixVectorMultiply(A, zNtt, k);

        // Compute t1 * 2^d and transform to NTT
        PolynomialVector t1Scaled = scaleByPowerOf2(t1, Parameters.D);
        PolynomialVector t1ScaledNtt = t1Scaled.copy();
        PolyOps.nttVector(t1ScaledNtt);

        // Compute c * t1_scaled in NTT domain
        Polynomial cNtt = c.copy();
        NTT.forward(cNtt);

        PolynomialVector ct1 = new PolynomialVector(k);
        for (int i = 0; i < k; i++) {
            Polynomial ct1i = PolyOps.pointwiseMultiply(cNtt, t1ScaledNtt.get(i));
            ct1.set(i, ct1i);
        }

        // w'_ntt = Az - ct1
        PolynomialVector wPrimeNtt = PolyOps.subtract(Az, ct1);

        // Transform back from NTT
        PolyOps.invNttVector(wPrimeNtt);
<<<<<<< HEAD
        PolyOps.reduceVector(wPrimeNtt);  // Reduce to [0, Q) after inverse NTT
=======
        reduceVector(wPrimeNtt);  // Reduce to [0, Q) after inverse NTT
>>>>>>> origin/anupsv/security-review

        // Step 9: Use hints to recover w1
        PolynomialVector w1Prime = UseHint.useHint(h, wPrimeNtt, gamma2);

        // Step 10: Compute expected challenge c_tilde' = H(mu || w1'_encoded)
        // c_tilde length is lambda/4 bytes per FIPS 204
<<<<<<< HEAD
        byte[] w1PrimeEncoded = BitPacker.encodeW1(w1Prime, params);
=======
        byte[] w1PrimeEncoded = encodeW1(w1Prime, params);
>>>>>>> origin/anupsv/security-review
        byte[] cTildePrime = Shake.shake256(params.cTildeBytes(), mu, w1PrimeEncoded);

        // Step 11: Check c_tilde == c_tilde'
        return ConstantTime.arraysEqual(cTilde, cTildePrime);
    }

    /**
<<<<<<< HEAD
=======
     * Reduces all polynomials in a vector to [0, Q).
     */
    private static void reduceVector(PolynomialVector v) {
        for (Polynomial p : v.polynomials()) {
            PolyOps.reduce(p);
        }
    }

    /**
>>>>>>> origin/anupsv/security-review
     * Scales a polynomial vector by 2^d.
     */
    private static PolynomialVector scaleByPowerOf2(PolynomialVector v, int d) {
        Polynomial[] result = new Polynomial[v.dimension()];
        for (int i = 0; i < v.dimension(); i++) {
            result[i] = PolyOps.shiftLeft(v.get(i), d);
        }
        return new PolynomialVector(result);
    }
<<<<<<< HEAD
=======

    /**
     * Encodes w1 for hashing (same as in Sign).
     */
    private static byte[] encodeW1(PolynomialVector w1, Parameters params) {
        int gamma2 = params.gamma2();
        int w1Bits = (gamma2 == (Parameters.Q - 1) / 88) ? 6 : 4;

        int polyBytes = (Parameters.N * w1Bits + 7) / 8;
        byte[] result = new byte[w1.dimension() * polyBytes];

        int offset = 0;
        for (int i = 0; i < w1.dimension(); i++) {
            byte[] packed = BitPacker.pack(w1.get(i), w1Bits);
            System.arraycopy(packed, 0, result, offset, packed.length);
            offset += polyBytes;
        }

        return result;
    }
>>>>>>> origin/anupsv/security-review
}
