package it.spid.cie.oidc.util;

import java.util.Objects;

import org.json.JSONArray;

public class JSONUtil {

	public static JSONArray asJSONArray(String... values) {
		return new JSONArray(values);
	}

	public static boolean contains(JSONArray array, String value) {
		if (array.isEmpty()) {
			return false;
		}

		for (int x = 0; x < array.length(); x++) {
			String elem = array.optString(x);

			if (Objects.equals(value, elem)) {
				return true;
			}
		}

		return false;
	}

}
