package it.spid.cie.oidc.exception;

public class ValidationException extends SPIDException {

	public ValidationException() {
		super();
	}

	public ValidationException(String message) {
		super(message);
	}

	public ValidationException(String message, Throwable cause) {
		super(message, cause);
	}

	public ValidationException(Throwable cause) {
		super(cause);
	}

	private static final long serialVersionUID = 4061357156399802866L;

}
