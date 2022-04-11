package it.spid.cie.oidc.util;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.json.JSONArray;
import org.junit.Test;

public class TestJSONUtil {

	@Test
	public void testConstructor() {
		JSONUtil obj = new JSONUtil();

		assertNotNull(obj);
	}

	@Test
	public void asJSONArray1() {
		JSONArray res = JSONUtil.asJSONArray("one", "two");

		assertTrue(res != null && res.length() == 2);
	}

	@Test
	public void asJSONArray2() {
		JSONArray res = JSONUtil.asJSONArray();

		assertTrue(res != null && res.length() == 0);
	}

	@Test
	public void contains1() {
		JSONArray array = JSONUtil.asJSONArray("0", "1");

		assertTrue(JSONUtil.contains(array, "0"));
	}

	@Test
	public void contains2() {
		JSONArray array = JSONUtil.asJSONArray("0", "1");

		assertFalse(JSONUtil.contains(array, "00"));
	}

	@Test
	public void contains3() {
		JSONArray array = new JSONArray();

		assertFalse(JSONUtil.contains(array, "00"));
	}

}
