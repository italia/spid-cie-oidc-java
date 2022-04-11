package it.spid.cie.oidc.exception;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

public class TestOIDCException {

	@Test
	public void testConstructor() {
		OIDCException e = new OIDCException();

		assertNotNull(e);
	}

	@Test
	public void testConstructor2() {
		OIDCException e = new OIDCException("test");

		assertNotNull("test".equals(e.getMessage()));
	}

	@Test
	public void testConstructor3() {
		OIDCException e = new OIDCException("test", new Exception());

		assertNotNull(e);
	}

	@Test
	public void testConstructor4() {
		OIDCException e = new OIDCException(new Exception());

		assertNotNull(e);
	}

}
