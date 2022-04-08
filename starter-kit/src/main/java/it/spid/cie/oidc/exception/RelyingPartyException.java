package it.spid.cie.oidc.exception;

public class RelyingPartyException extends OIDCException {

	private static final long serialVersionUID = 1391601394495769886L;

	@SuppressWarnings("serial")
	public static class Generic extends RelyingPartyException {

		public Generic(String format, Object... values) {
			super(String.format(format, values));
		}

		public Generic(Throwable cause) {
			super(cause);
		}

	}

	@SuppressWarnings("serial")
	public static class Authentication extends RelyingPartyException {

		public Authentication(String format, Object... values) {
			super(String.format(format, values));
		}

		public Authentication(Throwable cause) {
			super(cause);
		}

	}

	private RelyingPartyException(String format) {
		super(format);
	}

	private RelyingPartyException(Throwable cause) {
		super(cause);
	}

}
