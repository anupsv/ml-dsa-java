package mldsa.api;

/**
 * Exception thrown for ML-DSA cryptographic errors.
 */
public class MLDSAException extends RuntimeException {

    /**
     * Creates an exception with a message.
     *
     * @param message the error message
     */
    public MLDSAException(String message) {
        super(message);
    }

    /**
     * Creates an exception with a message and cause.
     *
     * @param message the error message
     * @param cause the underlying cause
     */
    public MLDSAException(String message, Throwable cause) {
        super(message, cause);
    }
}
