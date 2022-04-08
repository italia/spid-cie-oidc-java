package it.spid.cie.oidc.exception;

@SuppressWarnings("serial")
public class JWTException extends OIDCException {

	public static class Decryption extends JWTException {

		public Decryption(Throwable cause) {
			super(cause);
		}

	}

	public static class Parse extends JWTException {

		public Parse(Throwable cause) {
			super(cause);
		}

	}

	public static class Generic extends JWTException {

		public Generic(String message) {
			super(message);
		}

		public Generic(Throwable cause) {
			super(cause);
		}

	}

	public static class UnknownKid extends JWTException {

		public UnknownKid(String kid, String jwks) {
			super("kid " + kid + " not found in jwks " + jwks);
		}

	}

	public static class UnsupportedAlgorithm extends JWTException {

		public UnsupportedAlgorithm(String alg) {
			super(alg + " has beed disabled for security reason");
		}

	}

	public static class Verifier extends JWTException {

		public Verifier(String message) {
			super(message);
		}

		public Verifier(Throwable cause) {
			super(cause);
		}

	}

	private JWTException(String message) {
		super(message);
	}

	private JWTException(Throwable cause) {
		super(cause);
	}

}
