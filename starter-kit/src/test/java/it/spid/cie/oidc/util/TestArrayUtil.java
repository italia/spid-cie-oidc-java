package it.spid.cie.oidc.util;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.Set;

import org.junit.Test;
//import static org.junit.Assert.assertSame;

public class TestArrayUtil {

	@Test
	public void testAsSetSame() {
		String[] array = new String[] { "1", "2" };

		Set<String> set = ArrayUtil.asSet(array);

		assertSame(array.length, set.size());
	}

	@Test
	public void testAsSetUniq() {
		String[] array = new String[] { "1", "2", "1" };

		Set<String> set = ArrayUtil.asSet(array);

		assertSame(set.size(), 2);
	}

	@Test
	public void testContainsTrue() {
		String[] array = new String[] { "1", "2" };

		assertTrue(ArrayUtil.contains(array, "1"));
	}

	@Test
	public void testContainsFalse() {
		String[] array = new String[] { "1", "2" };

		assertFalse(ArrayUtil.contains(array, "0"));
	}

}
