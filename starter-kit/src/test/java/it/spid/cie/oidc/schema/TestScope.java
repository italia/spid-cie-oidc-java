package it.spid.cie.oidc.schema;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import it.spid.cie.oidc.schemas.Scope;

public class TestScope {

	@Test
	public void testParse1() {
		Scope res = Scope.parse(Scope.EMAIL.name());

		assertNull(res);
	}

	@Test
	public void testParse2() {
		Scope res = Scope.parse(Scope.EMAIL.value());

		assertTrue(Scope.EMAIL.equals(res));
	}

	@Test
	public void testParse3() {
		Scope res = Scope.parse("ko");

		assertNull(res);
	}

	@Test
	public void testParse4() {
		boolean catched = false;

		try {
			Scope.parse("ko", true);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testParse4b() {
		boolean catched = false;
		Scope res = null;

		try {
			res = Scope.parse("ko", false);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNull(res);
	}

	@Test
	public void testParse5() {
		Scope res = Scope.parse(null);

		assertNull(res);
	}

	@Test
	public void testParse6a() {
		boolean catched = false;
		Scope res = null;

		try {
			res = Scope.parse(Scope.EMAIL.value(), true);
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
		Scope res = null;

		try {
			res = Scope.parse(Scope.EMAIL.value(), false);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(res);
	}

	@Test
	public void testParse7() {
		assertEquals(Scope.OPEN_ID.toString(), Scope.OPEN_ID.value());
	}

}
