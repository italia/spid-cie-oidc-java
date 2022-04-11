package it.spid.cie.oidc.exception;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

public class TestEntityException extends BaseTestException {

	@Test
	public void testGeneric1() {
		OIDCException e = new EntityException.Generic("test");

		assertNotNull(e);
	}

	@Test
	public void testGeneric2() {
		OIDCException e = new EntityException.Generic(CAUSE);

		assertNotNull(e);
	}

	@Test
	public void testMissingJwksClaim1() {
		OIDCException e = new EntityException.MissingJwksClaim("test");

		assertNotNull(e);
	}

	@Test
	public void testMissingJwksClaim2() {
		OIDCException e = new EntityException.MissingJwksClaim(CAUSE);

		assertNotNull(e);
	}

	@Test
	public void testMissingTrustMarks1() {
		OIDCException e = new EntityException.MissingTrustMarks("test");

		assertNotNull(e);
	}

	@Test
	public void testMissingTrustMarks2() {
		OIDCException e = new EntityException.MissingTrustMarks(CAUSE);

		assertNotNull(e);
	}

}
