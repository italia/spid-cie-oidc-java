package it.spid.cie.oidc.exception;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

public class TestPersistenceException {

	@Test
	public void testConstructor() {
		OIDCException e = new PersistenceException(new Exception());

		assertNotNull(e);
	}

}
