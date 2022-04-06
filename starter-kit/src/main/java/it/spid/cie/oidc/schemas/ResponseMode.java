package it.spid.cie.oidc.schemas;

public enum ResponseMode {

	FORM_POST("form_post"),
	QUERY("query");

	public static ResponseMode parse(String value) {
		try {
			return parse(value, false);
		}
		catch (Exception e) {
			// Ignore
		}

		return null;
	}

	public static ResponseMode parse(String value, boolean strict) throws Exception {
		if (value != null) {
			for (ResponseMode elem : ResponseMode.values()) {
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

	private ResponseMode(String value) {
		this.value =value;
	}

	private final String value;

}
