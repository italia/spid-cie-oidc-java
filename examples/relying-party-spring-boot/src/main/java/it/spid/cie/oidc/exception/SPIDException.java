package it.spid.cie.oidc.exception;

public class SPIDException extends Exception {

	public SPIDException() {
		super();
	}

	public SPIDException(String message) {
		super(message);
	}

	public SPIDException(String message, Throwable cause) {
		super(message, cause);
	}

	public SPIDException(Throwable cause) {
		super(cause);
	}

	private static final long serialVersionUID = -1839651152644089727L;

}
