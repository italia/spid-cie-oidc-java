package it.spid.cie.oidc.schemas;

import it.spid.cie.oidc.exception.OIDCException;

public enum ResponseMode {

	FORM_POST("form_post"),
	QUERY("query");

	private final String value;

	public static ResponseMode parse(String value) {
		if (value != null) {
			for (ResponseMode elem : ResponseMode.values()) {
				if (value.equals(elem.value())) {
					return elem;
				}
			}
		}

		return null;
	}

	public static ResponseMode parse(String value, boolean strict) throws OIDCException {
		ResponseMode result = parse(value);

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

	private ResponseMode(String value) {
		this.value =value;
	}

}
