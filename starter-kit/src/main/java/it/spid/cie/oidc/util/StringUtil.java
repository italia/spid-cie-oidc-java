package it.spid.cie.oidc.util;

import java.util.Collection;
import java.util.StringJoiner;

public class StringUtil {

	public static final String ensureTrailingSlash(String url) {
		if (url != null && !url.endsWith("/")) {
			return url.concat("/");
		}

		return url;
	}

	public static final String merge(String[] array) {
		StringJoiner sj = new StringJoiner(",");

		for (String value : array) {
			sj.add(value);
		}

		return sj.toString();
	}

	public static final String merge(Collection<?> list) {
		if (list == null || list.isEmpty()) {
			return "";
		}

		StringJoiner sj = new StringJoiner(",");

		for (Object object : list) {
			sj.add(String.valueOf(object));
		}

		return sj.toString();
	}


}
