package it.spid.cie.oidc.util;

public class Validator {

	public static boolean isNullOrEmpty(String value) {
		if (value == null) {
			return true;
		}

		for (int x = 0; x < value.length(); x++) {
			char c = value.charAt(x);

			if (c != ' ' && c != '\t') {
				return false;
			}
		}

		return true;
	}

}
