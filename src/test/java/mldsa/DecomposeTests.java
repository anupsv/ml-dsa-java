package mldsa;

import mldsa.hints.Decompose;
import mldsa.params.Parameters;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DecomposeTests {

    @Test
    void decomposeWraparoundCaseProducesR0MinusOne() {
        for (Parameters params : new Parameters[] {
                mldsa.api.MLDSAParameterSet.ML_DSA_44.getParameters(),
                mldsa.api.MLDSAParameterSet.ML_DSA_65.getParameters(),
                mldsa.api.MLDSAParameterSet.ML_DSA_87.getParameters()
        }) {
            int gamma2 = params.gamma2();
            int[] parts = Decompose.decompose(Parameters.Q - 1, gamma2);
            assertEquals(0, parts[0], "Expected r1=0 for r=q-1 (gamma2=" + gamma2 + ")");
            assertEquals(-1, parts[1], "Expected r0=-1 for r=q-1 (gamma2=" + gamma2 + ")");
        }
    }
}

