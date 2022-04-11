package it.spid.cie.oidc.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

public class TestStringUtil {

	@Test
	public void testConstructor() {
		StringUtil obj = new StringUtil();

		assertNotNull(obj);
	}

	@Test
	public void ensureTrailingSlash1() {
		String value = StringUtil.ensureTrailingSlash("test");

		assertNotEquals("test", value);
	}

	@Test
	public void ensureTrailingSlash2() {
		String value = StringUtil.ensureTrailingSlash("test/");

		assertEquals("test/", value);
	}

	@Test
	public void ensureTrailingSlash3() {
		String value = StringUtil.ensureTrailingSlash(null);

		assertNull(value);
	}

	@Test
	public void mergeArray1() {
		String value = StringUtil.merge(new String[] {"0", "1", "2" });

		assertEquals("0,1,2", value);
	}

	@Test
	public void mergeArray2() {
		String value = StringUtil.merge(new String[] {"0"});

		assertEquals("0", value);
	}

	@Test
	public void mergeCollection1() {
		List<Long> list = null;

		String value = StringUtil.merge(list);

		assertEquals("", value);
	}

	@Test
	public void mergeCollection2() {
		List<Long> list = new ArrayList<>();

		String value = StringUtil.merge(list);

		assertEquals("", value);
	}

	@Test
	public void mergeCollection3() {
		List<Object> list = new ArrayList<>();

		list.add(1L);
		list.add("test");
		list.add(true);

		String value = StringUtil.merge(list);

		assertEquals("1,test,true", value);
	}


}
