package it.spid.cie.oidc.exception;

public class TrustMarkException extends OIDCException {

	private static final long serialVersionUID = 4581227536946992015L;

	public TrustMarkException(String format, Object... values) {
		super(String.format(format, values));
	}

	public TrustMarkException(Throwable cause) {
		super(cause);
	}

}
