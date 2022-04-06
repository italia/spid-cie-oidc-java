package it.spid.cie.oidc.schemas;

public enum Scope {

	OPEN_ID("openid"),
	OFFLINE_ACCESS("offline_access"),
	PROFILE("profile"),
	EMAIL("email");

	public static Scope parse(String value) {
		try {
			return parse(value, false);
		}
		catch (Exception e) {
			// Ignore
		}

		return null;
	}

	public static Scope parse(String value, boolean strict) throws Exception {
		if (value != null) {
			for (Scope elem : Scope.values()) {
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

	@Override
	public String toString() {
		return getValue();
	}

	private Scope(String value) {
		this.value =value;
	}

	private final String value;

}
