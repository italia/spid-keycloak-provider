package org.keycloak.broker.spid.exception;

/**
 * Exception for SPID-specific validation
 */
public class SpidValidationException extends Exception {

    private final int ANOMALY_ID;
    private static final String PREFIX_ERROR_CODE = "ErrorCode_nr";

    public SpidValidationException(int anomalyId) {
        super(PREFIX_ERROR_CODE + anomalyId);
        this.ANOMALY_ID = anomalyId;
    }

    public String getErrorCode() {
        return super.getMessage();
    }
}
