package it.spid.cie.oidc.util;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.Set;

import org.junit.Test;

public class TestArrayUtil {

	@Test
	public void testConstructor() {
		ArrayUtil obj = new ArrayUtil();

		assertNotNull(obj);
	}

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
		String[] array = new String[] { "one", "two" };

		assertTrue(ArrayUtil.contains(array, "two"));
	}

	@Test
	public void testContainsFalse() {
		String[] array = new String[] { "one", "two" };

		assertFalse(ArrayUtil.contains(array, "three"));
	}

	@Test
	public void testContains3() {
		assertFalse(ArrayUtil.contains(null, "two"));
	}

	@Test
	public void testContains4() {
		String[] array = new String[] { "one", "two" };

		assertFalse(ArrayUtil.contains(array, null));
	}

	@Test
	public void testContains5() {
		String[] array = new String[] { "one", null, "two" };

		assertTrue(ArrayUtil.contains(array, null));
	}

	@Test
	public void testContainsIgnoreCase1() {
		String[] array = new String[] { "one", "two" };

		assertTrue(ArrayUtil.contains(array, "One", true));
	}

	@Test
	public void testLasts1() {
		String[] array = new String[] { "1", "2", "3", "4" };

		String[] lasts = ArrayUtil.lasts(array, 2);

		assertArrayEquals(new String[] { "3", "4" }, lasts);
	}

	@Test
	public void testLasts2() {
		String[] array = new String[] { "1", "2" };

		String[] lasts = ArrayUtil.lasts(array, 4);

		assertArrayEquals(array, lasts);
	}

	@Test
	public void testLasts3() {
		String[] array = new String[] { "1", "2" };

		String[] lasts = ArrayUtil.lasts(array, 0);

		assertArrayEquals(new String[0], lasts);
	}

	@Test
	public void testSubset1() {
		String[] array = new String[] { "0", "1", "2", "3" };

		String[] set = ArrayUtil.subset(array, -1, 1);

		assertArrayEquals(new String[] { "0" }, set);
	}

	@Test
	public void testSubset2() {
		String[] array = new String[] { "0", "1", "2", "3" };

		String[] set = ArrayUtil.subset(array, 1, 2);

		assertArrayEquals(new String[] { "1" }, set);
	}

	@Test
	public void testSubset3() {
		String[] array = new String[] { "0", "1", "2", "3" };

		String[] set = ArrayUtil.subset(array, -1, -1);

		assertArrayEquals(array, set);
	}

	@Test
	public void testSubset4() {
		String[] array = new String[] { "0", "1", "2", "3" };

		String[] set = ArrayUtil.subset(array, 4, -1);

		assertArrayEquals(new String[0], set);
	}

	@Test
	public void testSubset5() {
		String[] array = new String[] { "0", "1", "2", "3" };

		String[] set = ArrayUtil.subset(array, 5, 5);

		assertArrayEquals(new String[0], set);
	}

	@Test
	public void testSubset6() {
		String[] array = new String[] { "0", "1", "2", "3" };

		String[] set = ArrayUtil.subset(array, 5, 2);

		assertArrayEquals(new String[0], set);
	}

}
