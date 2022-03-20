package it.spid.cie.oidc.relying.party.schemas;

public enum AcrValuesSpid {

	L1("https://www.spid.gov.it/SpidL1"),
	L2("https://www.spid.gov.it/SpidL2"),
	L3("https://www.spid.gov.it/SpidL3");

	public static AcrValuesSpid parse(String value) {
		try {
			return parse(value, false);
		}
		catch (Exception e) {
			// Ignore
		}

		return null;
	}

	public static AcrValuesSpid parse(String value, boolean strict) throws Exception {
		if (value != null) {
			if (value.equals(L1.getValue())) {
				return L1;
			}
			else if (value.equals(L2.getValue())) {
				return L2;
			}
			else if (value.equals(L3.getValue())) {
				return L3;
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

	private AcrValuesSpid(String value) {
		this.value =value;
	}

	private final String value;

}
