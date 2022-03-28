package it.spid.cie.oidc.schemas;

import it.spid.cie.oidc.exception.OIDCException;

public enum OIDCProfile {

	SPID("spid"),
	CIE("cie");

	public static OIDCProfile parse(String value) {
		try {
			return parse(value, false);
		}
		catch (Exception e) {
			// Ignore
		}

		return null;
	}

	public static OIDCProfile parse(String value, boolean strict) throws OIDCException {
		if (value != null) {
			if (value.equals(SPID.getValue())) {
				return SPID;
			}
			else if (value.equals(CIE.getValue())) {
				return CIE;
			}
		}

		if (strict) {
			throw new OIDCException("Invalid value: " + value);
		}

		return null;
	}

	public boolean equalValue(String value) {
		return this.value.equals(value);
	}

	public String getValue() {
		return value;
	}

	private OIDCProfile(String value) {
		this.value =value;
	}

	private final String value;
}
