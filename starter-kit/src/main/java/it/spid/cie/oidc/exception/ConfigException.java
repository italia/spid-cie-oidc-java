package it.spid.cie.oidc.exception;

public class ConfigException extends OIDCException {

	private static final long serialVersionUID = -3082538413902538010L;

	public ConfigException(String format, Object... values) {
		super(String.format(format, values));
	}

	public ConfigException(String message, Throwable cause) {
		super(message, cause);
	}

	public ConfigException(Throwable cause) {
		super(cause);
	}

}
