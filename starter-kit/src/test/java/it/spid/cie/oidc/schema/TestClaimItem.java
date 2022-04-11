package it.spid.cie.oidc.schema;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import it.spid.cie.oidc.schemas.ClaimItem;

public class TestClaimItem {

	@Test
	public void testClaimItem1() {
		boolean catched = false;

		try {
			MockClientItem.test(null, null, true);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testClaimItem2() {
		boolean catched = false;

		try {
			MockClientItem.test("test", "", true);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testClaimItem3() {
		boolean catched = false;

		try {
			MockClientItem.test("1", "1", true);
			MockClientItem.test("2", "1", false);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testClaimItem4() {
		boolean catched = false;

		try {
			MockClientItem.test("1", "1", true);
			MockClientItem.test("1", "2", false);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testClaimItem5() {
		boolean catched = false;

		ClaimItem res = null;

		try {
			MockClientItem.test("1", "1", true);
			res = MockClientItem.test("name", "alias", false);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertEquals("name", res.getName());
		assertEquals("alias", res.getAlias());
	}

	@SuppressWarnings({ "unused", "serial" })
	private static class MockClientItem extends ClaimItem {

		private static final Map<String, ClaimItem> claims = new HashMap<>();
		private static final Map<String, String> aliasMap = new HashMap<>();

		public static ClaimItem test(String name, String alias, boolean resetMaps) {
			if (resetMaps) {
				claims.clear();
				aliasMap.clear();
			}

			return new MockClientItem(name, alias, claims, aliasMap);
		}

		protected MockClientItem(
			String name, String alias, Map<String, ClaimItem> claims,
			Map<String, String> aliasMap) {

			super(name, alias, claims, aliasMap);
		}

	}
}
