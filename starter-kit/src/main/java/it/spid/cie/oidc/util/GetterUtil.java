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

	public static <T> T getObject(T value, T defaultValue) {
		if (value != null) {
			return value;
		}

		return defaultValue;
	}

	public static int getRangeEnd(int value, int maxValue) {
		if (value > maxValue) {
			return maxValue;
		}

		return value;
	}

	public static int getRangeStart(int value) {
		return getRangeStart(0, value);
	}

	public static int getRangeStart(int value, int minValue) {
		if (value < minValue) {
			return minValue;
		}

		return value;
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
