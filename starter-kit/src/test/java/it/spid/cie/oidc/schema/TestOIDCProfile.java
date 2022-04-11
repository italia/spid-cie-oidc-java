package it.spid.cie.oidc.schema;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import it.spid.cie.oidc.schemas.GrantType;
import it.spid.cie.oidc.schemas.OIDCProfile;

public class TestOIDCProfile {

	@Test
	public void testParse1() {
		OIDCProfile res = OIDCProfile.parse(OIDCProfile.CIE.name());

		assertNull(res);
	}

	@Test
	public void testParse2() {
		OIDCProfile res = OIDCProfile.parse(OIDCProfile.CIE.value());

		assertTrue(OIDCProfile.CIE.equals(res));
	}

	@Test
	public void testParse3() {
		OIDCProfile res = OIDCProfile.parse("ko");

		assertNull(res);
	}

	@Test
	public void testParse4a() {
		boolean catched = false;

		try {
			OIDCProfile.parse("ko", true);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testParse4b() {
		boolean catched = false;
		OIDCProfile res = null;

		try {
			res = OIDCProfile.parse("ko", false);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNull(res);
	}

	@Test
	public void testParse5() {
		OIDCProfile res = OIDCProfile.parse(null);

		assertNull(res);
	}

	@Test
	public void testParse6a() {
		boolean catched = false;
		OIDCProfile res = null;

		try {
			res = OIDCProfile.parse("spid", true);
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
		OIDCProfile res = null;

		try {
			res = OIDCProfile.parse("spid", false);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(res);
	}

	@Test
	public void testParse7() {
		assertEquals(OIDCProfile.SPID.toString(), OIDCProfile.SPID.value());
	}

	@Test
	public void testParse8a() {
		assertTrue(OIDCProfile.SPID.equalValue("spid"));
	}

	@Test
	public void testParse8b() {
		assertFalse(OIDCProfile.SPID.equalValue("Spid"));
	}

}
