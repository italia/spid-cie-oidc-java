package it.spid.cie.oidc.util;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class TestGetterUtil {

	@Test
	public void testConstructor() {
		GetterUtil obj = new GetterUtil();

		assertNotNull(obj);
	}

	@Test
	public void testGetLong1() {
		long res = GetterUtil.getLong(null);

		assertTrue(res == 0);
	}

	@Test
	public void testGetLong2() {
		long res = GetterUtil.getLong("");

		assertTrue(res == 0);
	}

	@Test
	public void testGetLong3() {
		long res = GetterUtil.getLong("1a");

		assertTrue(res == 0);
	}

	@Test
	public void testGetLong4() {
		long res = GetterUtil.getLong("12", 0L);

		assertTrue(res == 12);
	}

	@Test
	public void testGetObject1() {
		Long def = 0L;

		Long res = GetterUtil.getObject(Long.valueOf(1), def);

		assertTrue(res != null && res.longValue() == 1);
	}

	@Test
	public void testGetObject2() {
		Long def = 0L;

		Long res = GetterUtil.getObject(null, def);

		assertTrue(res != null && res.longValue() == 0L);
	}

	@Test
	public void testGetString1() {
		String res = GetterUtil.getString("test");

		assertTrue("test".equals(res));
	}

	@Test
	public void testGetString2() {
		String res = GetterUtil.getString(Long.valueOf(1));

		assertTrue("1".equals(res));
	}

	@Test
	public void testGetString3() {
		String res = GetterUtil.getString(null, "");

		assertTrue("".equals(res));
	}

	@Test
	public void testGetString4() {
		String res = GetterUtil.getString("test", "");

		assertTrue("test".equals(res));
	}

	@Test
	public void testGetString5() {
		String res = GetterUtil.getString(Long.valueOf(1), "");

		assertTrue("1".equals(res));
	}

	@Test
	public void testGetRangeEnd() {
		int res = GetterUtil.getRangeEnd(10, 5);

		assertTrue(res == 5);
	}

}
