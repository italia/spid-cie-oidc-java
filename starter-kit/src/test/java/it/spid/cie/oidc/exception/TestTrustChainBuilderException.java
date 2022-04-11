package it.spid.cie.oidc.exception;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

public class TestTrustChainBuilderException extends BaseTestException {

	@Test
	public void testConstructor() {
		OIDCException e = new TrustChainBuilderException();

		assertNotNull(e);
	}

	@Test
	public void testConstructor2() {
		OIDCException e = new TrustChainBuilderException("test");

		assertNotNull("test".equals(e.getMessage()));
	}

	@Test
	public void testConstructor3() {
		OIDCException e = new TrustChainBuilderException("test", CAUSE);

		assertNotNull(e);
	}

	@Test
	public void testConstructor4() {
		OIDCException e = new TrustChainBuilderException(CAUSE);

		assertNotNull(e);
	}

}
