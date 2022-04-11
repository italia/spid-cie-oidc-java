package it.spid.cie.oidc.schema;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import it.spid.cie.oidc.schemas.AcrValue;

public class TestAcrValue {

	@Test
	public void testParse1() {
		AcrValue res = AcrValue.parse(AcrValue.L2.name());

		assertTrue(AcrValue.L2.equals(res));
	}

	@Test
	public void testParse2() {
		AcrValue res = AcrValue.parse(AcrValue.L2.value());

		assertTrue(AcrValue.L2.equals(res));
	}

	@Test
	public void testParse3() {
		AcrValue res = AcrValue.parse("l4");

		assertNull(res);
	}

	@Test
	public void testParse4a() {
		boolean catched = false;

		try {
			AcrValue.parse("l4", true);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testParse4b() {
		boolean catched = false;
		AcrValue res = null;

		try {
			res = AcrValue.parse("l4", false);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNull(res);
	}

	@Test
	public void testParse5() {
		AcrValue res = AcrValue.parse(null);

		assertNull(res);
	}

	@Test
	public void testParse6a() {
		boolean catched = false;
		AcrValue res = null;

		try {
			res = AcrValue.parse("l1", true);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(res);
	}

	@Test
	public void testParse6b() {
		boolean catched = false;

		try {
			AcrValue.parse("L1", false);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
	}

	@Test
	public void testParse7() {
		assertEquals(AcrValue.L1.toString(), AcrValue.L1.value());
	}

}
