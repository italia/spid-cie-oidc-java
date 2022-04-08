package it.spid.cie.oidc.exception;

public class TrustChainBuilderException extends OIDCException {

	private static final long serialVersionUID = -6071661647891519660L;

	public TrustChainBuilderException() {
		super();
	}

	public TrustChainBuilderException(String message) {
		super(message);
	}

	public TrustChainBuilderException(String message, Throwable cause) {
		super(message, cause);
	}

	public TrustChainBuilderException(Throwable cause) {
		super(cause);
	}

}
