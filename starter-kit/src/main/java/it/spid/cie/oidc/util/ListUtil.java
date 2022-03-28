package it.spid.cie.oidc.util;

import java.util.Collections;
import java.util.List;

public class ListUtil {

	public static <E> E getLast(List<E> list) {
		if (list != null && !list.isEmpty()) {
			return list.get(list.size() - 1);
		}

		return null;
	}

	public static <E> List<E> lasts(List<E> list, int count) {
		if (list != null && !list.isEmpty()) {
			return subList(list, list.size() - count, list.size());
		}

		return Collections.emptyList();
	}

	public static <E> List<E> subList(List<E> list, int start, int end) {
		if (start < 0) {
			start = 0;
		}

		if ((end < 0) || (end > list.size())) {
			end = list.size();
		}

		if (start < end) {
			return list.subList(start, end);
		}

		return Collections.emptyList();
	}

}
