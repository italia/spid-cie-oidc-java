package it.spid.cie.oidc.schemas;

import it.spid.cie.oidc.exception.OIDCException;

public enum AcrValue {

	L1("https://www.spid.gov.it/SpidL1"),
	L2("https://www.spid.gov.it/SpidL2"),
	L3("https://www.spid.gov.it/SpidL3");

	private final String value;

	/**
	 * Identify the AcrValue by its {@code value} or {@code name}. While value is strictly
	 * checked, name is evalueated case insensitive.
	 *
	 * @param value value to search
	 * @return found element, or null
	 */
	public static AcrValue parse(String value) {
		if (value != null) {
			for (AcrValue elem : AcrValue.values()) {
				if (value.equals(elem.value())) {
					return elem;
				}
			}
			for (AcrValue elem : AcrValue.values()) {
				if (value.equalsIgnoreCase(elem.name())) {
					return elem;
				}
			}
		}

		return null;
	}

	public static AcrValue parse(String value, boolean strict) throws OIDCException {
		AcrValue result = parse(value);

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

	private AcrValue(String value) {
		this.value = value;
	}

}
