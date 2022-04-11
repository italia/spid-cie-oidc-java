package it.spid.cie.oidc.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

public class TestListUtil {

	@Test
	public void testConstructor() {
		ListUtil obj = new ListUtil();

		assertNotNull(obj);
	}

	@Test
	public void getLast1() {
		List<Long> list = null;

		Long res = ListUtil.getLast(list);

		assertNull(res);
	}

	@Test
	public void getLast2() {
		List<Long> list = new ArrayList<>();

		Long res = ListUtil.getLast(list);

		assertNull(res);
	}

	@Test
	public void getLast3() {
		List<String> list = new ArrayList<>();

		list.add("0");
		list.add("1");

		String res = ListUtil.getLast(list);

		assertEquals("1", res);
	}

	@Test
	public void getLasts1() {
		List<Long> list = null;

		List<Long> res = ListUtil.lasts(list, 1);

		assertTrue(res != null && res.size() == 0);
	}

	@Test
	public void getLasts2() {
		List<Long> list = new ArrayList<>();

		List<Long> res = ListUtil.lasts(list, 1);

		assertTrue(res != null && res.size() == 0);
	}

	@Test
	public void getLasts3() {
		List<String> list = new ArrayList<>();

		list.add("0");
		list.add("1");
		list.add("2");

		List<String> res = ListUtil.lasts(list, 1);

		assertEquals(1, res.size());
	}

	@Test
	public void getLasts4() {
		List<String> list = new ArrayList<>();

		list.add("0");
		list.add("1");
		list.add("2");

		List<String> res = ListUtil.lasts(list, 10);

		assertEquals(3, res.size());
	}

	@Test
	public void subList1() {
		List<String> list = new ArrayList<>();

		list.add("0");
		list.add("1");
		list.add("2");

		List<String> res = ListUtil.subList(list, 5, 3);

		assertEquals(0, res.size());
	}

}
