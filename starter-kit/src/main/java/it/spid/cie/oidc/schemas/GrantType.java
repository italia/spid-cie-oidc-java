package it.spid.cie.oidc.schemas;

public enum GrantType {

	REFRESH_TOKEN("refresh_token"),
	AUTHORIZATION_CODE("authorization_code");

	public static GrantType parse(String value) {
		try {
			return parse(value, false);
		}
		catch (Exception e) {
			// Ignore
		}

		return null;
	}

	public static GrantType parse(String value, boolean strict) throws Exception {
		if (value != null) {
			for (GrantType elem : GrantType.values()) {
				if (value.equals(elem.getValue())) {
					return elem;
				}
			}
		}

		if (strict) {
			throw new Exception("Invalid value: " + value);
		}

		return null;
	}

	public String getValue() {
		return value;
	}

	private GrantType(String value) {
		this.value =value;
	}

	private final String value;

}
