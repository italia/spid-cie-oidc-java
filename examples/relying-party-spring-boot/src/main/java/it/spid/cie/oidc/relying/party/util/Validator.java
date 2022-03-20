package it.spid.cie.oidc.relying.party.util;

public class Validator {

	public static boolean isNullOrEmpty(String value) {
		if (value == null) {
			return true;
		}

		for (int x = 0; x < value.length(); x++) {
			char c = value.charAt(x);

			if (c == ' ' || c == '\t') {
				continue;
			}

			return false;
		}

		return true;
	}

}
