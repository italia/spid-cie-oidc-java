package it.spid.cie.oidc.schemas;

import it.spid.cie.oidc.exception.OIDCException;

public enum Scope {

	OPEN_ID("openid"),
	OFFLINE_ACCESS("offline_access"),
	PROFILE("profile"),
	EMAIL("email");

	private final String value;

	public static Scope parse(String value) {
		if (value != null) {
			for (Scope elem : Scope.values()) {
				if (value.equals(elem.value())) {
					return elem;
				}
			}
		}

		return null;
	}

	public static Scope parse(String value, boolean strict) throws OIDCException {
		Scope result = parse(value);

		if (result == null && strict) {
			throw new OIDCException("Invalid value: " + value);
		}

		return result;
	}

	public String value() {
		return value;
	}

	@Override
	public String toString() {
		return value();
	}

	private Scope(String value) {
		this.value = value;
	}

}
