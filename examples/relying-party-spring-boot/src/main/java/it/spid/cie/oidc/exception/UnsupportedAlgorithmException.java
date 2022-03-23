package it.spid.cie.oidc.exception;

public class UnsupportedAlgorithmException extends SPIDException {

	public UnsupportedAlgorithmException() {
		super();
	}

	public UnsupportedAlgorithmException(String message) {
		super(message);
	}

	public UnsupportedAlgorithmException(String message, Throwable cause) {
		super(message, cause);
	}

	public UnsupportedAlgorithmException(Throwable cause) {
		super(cause);
	}

	private static final long serialVersionUID = -5156493052679477725L;

}
