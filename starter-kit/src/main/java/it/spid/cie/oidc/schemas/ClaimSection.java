package it.spid.cie.oidc.schemas;

import it.spid.cie.oidc.exception.OIDCException;

public enum ClaimSection {

	ID_TOKEN("id_token"),
	USER_INFO("userinfo");

	private final String value;

	public static ClaimSection parse(String value) {
		if (value != null) {
			for (ClaimSection elem : ClaimSection.values()) {
				if (value.equals(elem.value())) {
					return elem;
				}
			}
		}

		return null;
	}

	public static ClaimSection parse(String value, boolean strict) throws OIDCException {
		ClaimSection result = parse(value);

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

	private ClaimSection(String value) {
		this.value =value;
	}

}
