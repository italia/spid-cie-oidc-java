package it.spid.cie.oidc.util;

import java.util.HashSet;
import java.util.Set;

public class ArrayUtil {

	@SafeVarargs
	public static <T> Set<T> asSet(T... values) {
		Set<T> result = new HashSet<T>(values.length);

		for (T value : values) {
			result.add(value);
		}

		return result;
	}

	public static boolean contains(String[] array, String value) {
		return contains(array, value, false);
	}

	public static boolean contains(
		String[] array, String value, boolean ignoreCase) {

		if (array == null) {
			return false;
		}

		for (String elem : array) {
			if (elem == null) {
				if (value == null) {
					return true;
				}
			}
			else if (ignoreCase) {
				if (elem.equalsIgnoreCase(value)) {
					return true;
				}
			}
			else if (elem.equals(value)) {
				return true;
			}
		}

		return false;
	}

	public static String[] lasts(String[] array, int count) {
		int end = array.length;
		int start = end - count;

		return subset(array, start, end);
	}

	public static String[] subset(String[] array, int start, int end) {
		start = checkStart(start);
		end = checkEnd(end, array.length);

		if ((start < 0) || (end < 0) || ((end - start) < 0)) {
			return array;
		}

		String[] newArray = new String[end - start];

		System.arraycopy(array, start, newArray, 0, end - start);

		return newArray;
	}

	private static int checkEnd(int end, int arrayLength) {
		if (end < 0) {
			return arrayLength;
		}
		else if (end > arrayLength) {
			return arrayLength;
		}

		return end;
	}

	private static int checkStart(int start) {
		if (start < 0) {
			return 0;
		}

		return start;
	}

}
