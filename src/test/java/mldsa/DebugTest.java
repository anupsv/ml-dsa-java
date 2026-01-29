package mldsa;

import mldsa.api.*;
import mldsa.params.Parameters;
import mldsa.poly.*;
import mldsa.ntt.*;
import org.junit.jupiter.api.Test;

public class DebugTest {
    @Test
    void debugSigning() {
        System.out.println("Testing ML-DSA-44 key generation...");

        // Generate a key pair
        byte[] seed = new byte[32];
        for (int i = 0; i < 32; i++) seed[i] = (byte) i;

        MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_44, seed);

        System.out.println("Key pair generated successfully");
        System.out.println("Public key size: " + keyPair.publicKey().encoded().length);
        System.out.println("Private key size: " + keyPair.privateKey().encoded().length);

        // Check some polynomial properties
        Parameters params = MLDSAParameterSet.ML_DSA_44.getParameters();
        System.out.println("\nParameters:");
        System.out.println("  k = " + params.k());
        System.out.println("  l = " + params.l());
        System.out.println("  gamma1 = " + params.gamma1());
        System.out.println("  gamma2 = " + params.gamma2());
        System.out.println("  beta = " + params.beta());
        System.out.println("  tau = " + params.tau());

        // Test NTT roundtrip
        System.out.println("\nTesting NTT roundtrip...");
        int[] coeffs = new int[256];
        for (int i = 0; i < 256; i++) coeffs[i] = i % 100;
        Polynomial p = new Polynomial(coeffs.clone());

        System.out.println("Before NTT: p[0]=" + p.get(0) + ", p[1]=" + p.get(1));

        NTT.forward(p);
        System.out.println("After forward: p[0]=" + p.get(0) + ", p[1]=" + p.get(1));

        NTT.inverse(p);
        System.out.println("After inverse: p[0]=" + p.get(0) + ", p[1]=" + p.get(1));

        // After inverse, result is in Montgomery form for pure roundtrip
        // Use fromMontgomery, not reduce
        NTT.fromMontgomery(p);
        System.out.println("After fromMontgomery: p[0]=" + p.get(0) + ", p[1]=" + p.get(1));

        boolean nttOk = true;
        for (int i = 0; i < 256; i++) {
            if (p.get(i) != coeffs[i]) {
                System.out.println("NTT roundtrip mismatch at " + i + ": expected " + coeffs[i] + ", got " + p.get(i));
                nttOk = false;
                break;
            }
        }
        if (nttOk) {
            System.out.println("NTT roundtrip OK");
        }

        // Test Montgomery
        System.out.println("\nTesting Montgomery...");
        int a = 12345;
        int aMont = Montgomery.toMontgomery(a);
        int aBack = Montgomery.fromMontgomery(aMont);
        System.out.println("  a = " + a + ", toMont(a) = " + aMont + ", fromMont(toMont(a)) = " + aBack);

        // Test PolynomialVector checkNorm
        System.out.println("\nTesting checkNorm...");
        int[] smallCoeffs = new int[256];
        for (int i = 0; i < 256; i++) smallCoeffs[i] = i % 10;
        Polynomial smallPoly = new Polynomial(smallCoeffs);
        PolynomialVector smallVec = new PolynomialVector(new Polynomial[]{smallPoly});

        // gamma1 - beta - 1 for ML-DSA-44 = 131072 - 78 - 1 = 130993
        int bound = params.gamma1() - params.beta() - 1;
        System.out.println("  bound = " + bound);
        boolean normOk = smallVec.checkNorm(bound);
        System.out.println("  checkNorm(smallVec, " + bound + ") = " + normOk);

        // Test with larger coefficients
        int[] largeCoeffs = new int[256];
        for (int i = 0; i < 256; i++) largeCoeffs[i] = params.gamma1();  // Should fail
        Polynomial largePoly = new Polynomial(largeCoeffs);
        PolynomialVector largeVec = new PolynomialVector(new Polynomial[]{largePoly});
        boolean largeNormOk = largeVec.checkNorm(bound);
        System.out.println("  checkNorm(largeVec with gamma1, " + bound + ") = " + largeNormOk + " (should be false)");

        // Test signing
        System.out.println("\nTesting signing...");
        try {
            byte[] message = "test message".getBytes();
            byte[] rnd = new byte[32];  // Deterministic randomness
            var signature = MLDSA.sign(keyPair.privateKey(), message, rnd);
            System.out.println("Signing succeeded! Signature size: " + signature.encoded().length);

            // Verify
            boolean verified = MLDSA.verify(keyPair.publicKey(), message, signature);
            System.out.println("Verification result: " + verified);
        } catch (Exception e) {
            System.out.println("Signing failed: " + e.getMessage());
        }

        // Debug: test mask sampling and z computation
        System.out.println("\nDebugging z computation step by step...");

        // Decode a fresh private key
        Object[] skParts = mldsa.encode.ByteCodec.decodePrivateKey(
            keyPair.privateKey().encoded(), params);
        byte[] rho = (byte[]) skParts[0];
        byte[] K = (byte[]) skParts[1];
        byte[] tr = (byte[]) skParts[2];
        PolynomialVector s1 = (PolynomialVector) skParts[3];
        PolynomialVector s2 = (PolynomialVector) skParts[4];
        PolynomialVector t0 = (PolynomialVector) skParts[5];

        System.out.println("s1[0] first 5 coeffs: " + s1.get(0).get(0) + ", " + s1.get(0).get(1) +
            ", " + s1.get(0).get(2) + ", " + s1.get(0).get(3) + ", " + s1.get(0).get(4));

        // Check s1 norm (should be <= eta = 2)
        System.out.println("s1.checkNorm(eta=2) = " + s1.checkNorm(2));

        // Transform s1 to NTT
        PolynomialVector s1Ntt = s1.copy();
        PolyOps.nttVector(s1Ntt);
        System.out.println("s1Ntt[0] first 5: " + s1Ntt.get(0).get(0) + ", " + s1Ntt.get(0).get(1) +
            ", " + s1Ntt.get(0).get(2) + ", " + s1Ntt.get(0).get(3) + ", " + s1Ntt.get(0).get(4));

        // Sample y
        byte[] rhoPrime = new byte[64];
        var y = mldsa.sampling.Sampler.sampleMask(params, rhoPrime, 0);
        System.out.println("\ny[0] first 5 coeffs: " + y.get(0).get(0) + ", " + y.get(0).get(1) +
            ", " + y.get(0).get(2) + ", " + y.get(0).get(3) + ", " + y.get(0).get(4));

        int gamma1 = params.gamma1();
        int beta = params.beta();
        System.out.println("gamma1 = " + gamma1 + ", beta = " + beta);
        System.out.println("y.checkNorm(gamma1) = " + y.checkNorm(gamma1));

        // Sample challenge c
        byte[] cSeed = new byte[32];
        Polynomial c = mldsa.sampling.Sampler.sampleInBall(params, cSeed);
        int cNonzeros = 0;
        for (int i = 0; i < 256; i++) {
            if (c.get(i) != 0) cNonzeros++;
        }
        System.out.println("\nc has " + cNonzeros + " nonzero coeffs (should be tau=" + params.tau() + ")");

        // Transform c to NTT
        Polynomial cNtt = c.copy();
        NTT.forward(cNtt);
        System.out.println("cNtt[0..4]: " + cNtt.get(0) + ", " + cNtt.get(1) + ", " + cNtt.get(2) +
            ", " + cNtt.get(3) + ", " + cNtt.get(4));

        // Compute c*s1[0] in NTT domain
        Polynomial cs1i = PolyOps.pointwiseMultiply(cNtt, s1Ntt.get(0));
        System.out.println("\ncs1i (NTT) first 5: " + cs1i.get(0) + ", " + cs1i.get(1) +
            ", " + cs1i.get(2) + ", " + cs1i.get(3) + ", " + cs1i.get(4));

        // Inverse NTT
        NTT.inverse(cs1i);
        System.out.println("cs1i (after invNTT) first 5: " + cs1i.get(0) + ", " + cs1i.get(1) +
            ", " + cs1i.get(2) + ", " + cs1i.get(3) + ", " + cs1i.get(4));

        // Reduce
        PolyOps.reduce(cs1i);
        System.out.println("cs1i (after reduce) first 5: " + cs1i.get(0) + ", " + cs1i.get(1) +
            ", " + cs1i.get(2) + ", " + cs1i.get(3) + ", " + cs1i.get(4));

        // Check cs1 norm - should be bounded by tau*eta
        int cs1Bound = params.tau() * params.eta();
        boolean cs1NormOk = cs1i.checkNorm(cs1Bound);
        System.out.println("cs1.checkNorm(tau*eta=" + cs1Bound + ") = " + cs1NormOk);

        // Add y[0] + cs1i
        Polynomial zi = PolyOps.add(y.get(0), cs1i);
        System.out.println("\nz[0] (y+cs1) first 5: " + zi.get(0) + ", " + zi.get(1) +
            ", " + zi.get(2) + ", " + zi.get(3) + ", " + zi.get(4));

        // Reduce z
        PolyOps.reduce(zi);
        System.out.println("z[0] (after reduce) first 5: " + zi.get(0) + ", " + zi.get(1) +
            ", " + zi.get(2) + ", " + zi.get(3) + ", " + zi.get(4));

        // Check z norm
        int zBound = gamma1 - beta - 1;
        System.out.println("\nzBound = gamma1 - beta - 1 = " + zBound);
        System.out.println("z[0].infinityNorm() = " + zi.infinityNorm());
        System.out.println("z[0].checkNorm(" + zBound + ") = " + zi.checkNorm(zBound));

        // Check if any coefficient exceeds bound
        int halfQ = (Parameters.Q - 1) / 2;
        int maxAbs = 0;
        int maxIdx = 0;
        for (int i = 0; i < 256; i++) {
            int coeff = zi.get(i);
            int centered = coeff > halfQ ? coeff - Parameters.Q : coeff;
            int absVal = centered < 0 ? -centered : centered;
            if (absVal > maxAbs) {
                maxAbs = absVal;
                maxIdx = i;
            }
        }
        System.out.println("Max |z| coefficient: " + maxAbs + " at index " + maxIdx);
        System.out.println("zBound = " + zBound + ", exceeds = " + (maxAbs > zBound));

        // Debug the specific coefficient that exceeds
        int yAtMax = y.get(0).get(maxIdx);
        int yAtMaxCentered = yAtMax > halfQ ? yAtMax - Parameters.Q : yAtMax;
        int cs1AtMax = cs1i.get(maxIdx);
        int cs1AtMaxCentered = cs1AtMax > halfQ ? cs1AtMax - Parameters.Q : cs1AtMax;
        int zAtMax = zi.get(maxIdx);
        int zAtMaxCentered = zAtMax > halfQ ? zAtMax - Parameters.Q : zAtMax;
        System.out.println("\nAt index " + maxIdx + ":");
        System.out.println("  y = " + yAtMax + " (centered: " + yAtMaxCentered + ")");
        System.out.println("  cs1 = " + cs1AtMax + " (centered: " + cs1AtMaxCentered + ")");
        System.out.println("  z = " + zAtMax + " (centered: " + zAtMaxCentered + ")");
        System.out.println("  y + cs1 (expected centered) = " + (yAtMaxCentered + cs1AtMaxCentered));

        // Analyze y distribution
        System.out.println("\n--- Analyzing y distribution ---");
        int yMaxAbs = 0;
        int yExceed = 0;
        for (int vi = 0; vi < y.dimension(); vi++) {
            for (int i = 0; i < 256; i++) {
                int yCoeff = y.get(vi).get(i);
                int yCentered = yCoeff > halfQ ? yCoeff - Parameters.Q : yCoeff;
                int yAbs = yCentered < 0 ? -yCentered : yCentered;
                if (yAbs > yMaxAbs) yMaxAbs = yAbs;
                // Count how many y coefficients are already close to gamma1 - beta
                if (yAbs > gamma1 - beta - params.eta() * params.tau()) {
                    yExceed++;
                }
            }
        }
        System.out.println("Max |y| coefficient: " + yMaxAbs + " (gamma1 = " + gamma1 + ")");
        System.out.println("y coefficients close to bound: " + yExceed + " / " + (y.dimension() * 256));

        // The y sampling maps [0, 2*gamma1) to [-gamma1+1, gamma1]
        // y = gamma1 - value where value in [0, 2*gamma1)
        // So y ranges from gamma1-0=gamma1 down to gamma1-(2*gamma1-1)=-gamma1+1
        System.out.println("\nExpected y range: [-" + (gamma1-1) + ", " + gamma1 + "]");
        System.out.println("This is WRONG! y should be in [-gamma1+1, gamma1], not [-gamma1+1, gamma1]");
        System.out.println("Checking: 2*gamma1 = " + (2*gamma1) + ", 2^gamma1Bits = " + (1 << params.gamma1Bits()));
    }
}
