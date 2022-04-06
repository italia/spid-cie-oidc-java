package it.spid.cie.oidc.schemas;

public enum AcrValue {

	L1("https://www.spid.gov.it/SpidL1"),
	L2("https://www.spid.gov.it/SpidL2"),
	L3("https://www.spid.gov.it/SpidL3");

	public static AcrValue parse(String value) {
		try {
			return parse(value, false);
		}
		catch (Exception e) {
			// Ignore
		}

		return null;
	}

	public static AcrValue parse(String value, boolean strict) throws Exception {
		if (value != null) {
			for (AcrValue elem : AcrValue.values()) {
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

	private AcrValue(String value) {
		this.value =value;
	}

	private final String value;

}
