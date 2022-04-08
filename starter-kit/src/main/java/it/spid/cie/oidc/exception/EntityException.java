package it.spid.cie.oidc.exception;

public class EntityException extends OIDCException {

	private static final long serialVersionUID = 9206740073587833396L;

	@SuppressWarnings("serial")
	public static class Generic extends EntityException {

		public Generic(String message) {
			super(message);
		}

		public Generic(Throwable cause) {
			super(cause);
		}

	}

	@SuppressWarnings("serial")
	public static class MissingJwksClaim extends EntityException {

		public MissingJwksClaim(String message) {
			super(message);
		}

		public MissingJwksClaim(Throwable cause) {
			super(cause);
		}

	}

	@SuppressWarnings("serial")
	public static class MissingTrustMarks extends EntityException {

		public MissingTrustMarks(String message) {
			super(message);
		}

		public MissingTrustMarks(Throwable cause) {
			super(cause);
		}

	}

	private EntityException(String message) {
		super(message);
	}

	private EntityException(Throwable cause) {
		super(cause);
	}

}
