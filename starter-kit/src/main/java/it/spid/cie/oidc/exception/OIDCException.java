package it.spid.cie.oidc.exception;

public class OIDCException extends Exception {

	private static final long serialVersionUID = -1839651152644089727L;

	public OIDCException() {
		super();
	}

	public OIDCException(String message) {
		super(message);
	}

	public OIDCException(String message, Throwable cause) {
		super(message, cause);
	}

	public OIDCException(Throwable cause) {
		super(cause);
	}

}
