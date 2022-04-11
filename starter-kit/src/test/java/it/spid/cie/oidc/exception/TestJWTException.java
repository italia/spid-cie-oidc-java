package it.spid.cie.oidc.exception;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

public class TestJWTException extends BaseTestException {

	@Test
	public void testDecryption() {
		OIDCException e = new JWTException.Decryption(CAUSE);

		assertNotNull(e);
	}

	@Test
	public void testParse() {
		OIDCException e = new JWTException.Parse(CAUSE);

		assertNotNull(e);
	}

	@Test
	public void testGeneric1() {
		OIDCException e = new JWTException.Generic("test");

		assertNotNull(e);
	}

	@Test
	public void testGeneric2() {
		OIDCException e = new JWTException.Generic(CAUSE);

		assertNotNull(e);
	}

	@Test
	public void testUnknownKid() {
		OIDCException e = new JWTException.UnknownKid("kid", "jwks");

		assertNotNull(e);
	}

	@Test
	public void testUnsupportedAlgorithm() {
		OIDCException e = new JWTException.UnsupportedAlgorithm("alg");

		assertNotNull(e);
	}

	@Test
	public void testVerifier1() {
		OIDCException e = new JWTException.Verifier("test");

		assertNotNull(e);
	}

	@Test
	public void testVerifier2() {
		OIDCException e = new JWTException.Verifier(CAUSE);

		assertNotNull(e);
	}

}
