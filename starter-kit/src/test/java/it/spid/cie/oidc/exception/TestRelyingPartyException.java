package it.spid.cie.oidc.exception;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

public class TestRelyingPartyException extends BaseTestException {

	@Test
	public void testGeneric1() {
		OIDCException e = new RelyingPartyException.Generic("test %d", 1);

		assertNotNull(e);
	}

	@Test
	public void testGeneric2() {
		OIDCException e = new RelyingPartyException.Generic(CAUSE);

		assertNotNull(e);
	}

	@Test
	public void testAuthentication1() {
		OIDCException e = new RelyingPartyException.Authentication("test %d", 1);

		assertNotNull(e);
	}

	@Test
	public void testAuthentication2() {
		OIDCException e = new RelyingPartyException.Authentication(CAUSE);

		assertNotNull(e);
	}

}
