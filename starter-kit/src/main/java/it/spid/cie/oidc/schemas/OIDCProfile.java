package it.spid.cie.oidc.schemas;

import it.spid.cie.oidc.exception.OIDCException;

public enum OIDCProfile {

	SPID("spid"),
	CIE("cie");

	private final String value;

	public static OIDCProfile parse(String value) {
		if (value != null) {
			for (OIDCProfile elem : OIDCProfile.values()) {
				if (value.equals(elem.value())) {
					return elem;
				}
			}
		}

		return null;
	}

	public static OIDCProfile parse(String value, boolean strict) throws OIDCException {
		OIDCProfile result = parse(value);

		if (result == null && strict) {
			throw new OIDCException("Invalid value: " + value);
		}

		return result;
	}

	public boolean equalValue(String value) {
		return this.value.equals(value);
	}

	@Override
	public String toString() {
		return value();
	}

	public String value() {
		return value;
	}

	private OIDCProfile(String value) {
		this.value =value;
	}

}
