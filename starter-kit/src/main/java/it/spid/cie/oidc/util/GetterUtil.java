package it.spid.cie.oidc.util;

public class GetterUtil {

	public static long getLong(String value) {
		return getLong(value, 0L);
	}

	public static long getLong(String value, long defaultValue) {
		try {
			return Long.parseLong(value);
		}
		catch (Exception e) {
			return defaultValue;
		}
	}

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
