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
		int goodStart = GetterUtil.getRangeStart(start);
		int goodEnd = GetterUtil.getRangeEnd(end, list.size());

		if (goodStart < goodEnd) {
			return list.subList(goodStart, goodEnd);
		}

		return Collections.emptyList();
	}

}
