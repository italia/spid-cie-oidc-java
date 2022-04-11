package it.spid.cie.oidc.schemas;

import it.spid.cie.oidc.exception.OIDCException;

public enum GrantType {

	REFRESH_TOKEN("refresh_token"),
	AUTHORIZATION_CODE("authorization_code");

	private final String value;

	public static GrantType parse(String value) {
		if (value != null) {
			for (GrantType elem : GrantType.values()) {
				if (value.equals(elem.value())) {
					return elem;
				}
			}
		}

		return null;
	}

	public static GrantType parse(String value, boolean strict) throws OIDCException {
		GrantType result = parse(value);

		if (result == null && strict) {
			throw new OIDCException("Invalid value: " + value);
		}

		return result;
	}

	@Override
	public String toString() {
		return value();
	}

	public String value() {
		return value;
	}

	private GrantType(String value) {
		this.value = value;
	}

}
