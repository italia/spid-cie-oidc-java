package it.spid.cie.oidc.schema;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import it.spid.cie.oidc.schemas.ClaimSection;
import it.spid.cie.oidc.schemas.GrantType;
import it.spid.cie.oidc.schemas.OIDCProfile;

public class TestGrantType {

	@Test
	public void testParse1() {
		GrantType res = GrantType.parse(GrantType.REFRESH_TOKEN.name());

		assertNull(res);
	}

	@Test
	public void testParse2() {
		GrantType res = GrantType.parse(GrantType.REFRESH_TOKEN.value());

		assertTrue(GrantType.REFRESH_TOKEN.equals(res));
	}

	@Test
	public void testParse3() {
		GrantType res = GrantType.parse("ko");

		assertNull(res);
	}

	@Test
	public void testParse4a() {
		boolean catched = false;

		try {
			GrantType.parse("ko", true);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testParse4b() {
		boolean catched = false;
		GrantType res = null;

		try {
			res = GrantType.parse("ko", false);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNull(res);
	}

	@Test
	public void testParse5() {
		GrantType res = GrantType.parse(null);

		assertNull(res);
	}

	@Test
	public void testParse6a() {
		boolean catched = false;
		GrantType res = null;

		try {
			res = GrantType.parse(GrantType.REFRESH_TOKEN.value(), true);
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
		GrantType res = null;

		try {
			res = GrantType.parse(GrantType.REFRESH_TOKEN.value(), false);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(res);
	}

	@Test
	public void testParse7() {
		assertEquals(GrantType.REFRESH_TOKEN.toString(), GrantType.REFRESH_TOKEN.value());
	}

}
