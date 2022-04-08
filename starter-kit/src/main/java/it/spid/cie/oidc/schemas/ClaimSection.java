package it.spid.cie.oidc.schemas;

public enum ClaimSection {

	ID_TOKEN("id_token"),
	USER_INFO("userinfo");

	private final String value;

	public static ClaimSection parse(String value) {
		try {
			return parse(value, false);
		}
		catch (Exception e) {
			// Ignore
		}

		return null;
	}

	public static ClaimSection parse(String value, boolean strict) throws Exception {
		if (value != null) {
			for (ClaimSection elem : ClaimSection.values()) {
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

	private ClaimSection(String value) {
		this.value =value;
	}

}
