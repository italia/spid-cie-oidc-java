package it.spid.cie.oidc.relying.party.util;

public class GetterUtil {

	public static String getString(Object obj) {
		if (obj instanceof String) {
			return (String)obj;
		}
		else {
			return obj.toString();
		}
	}

	public static String getString(Object obj, String defaultValue) {
		if (obj == null) {
			return defaultValue;
		}
		if (obj instanceof String) {
			return (String)obj;
		}
		else {
			return obj.toString();
		}
	}

}
