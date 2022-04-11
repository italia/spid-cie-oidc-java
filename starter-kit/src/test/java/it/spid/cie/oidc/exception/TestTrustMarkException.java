package it.spid.cie.oidc.exception;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

public class TestTrustMarkException extends BaseTestException {

	@Test
	public void testConstructor1() {
		OIDCException e = new TrustMarkException("test %s", "test");

		assertNotNull(e);
	}

	@Test
	public void testConstructor2() {
		OIDCException e = new TrustMarkException(CAUSE);

		assertNotNull(e);
	}

}
