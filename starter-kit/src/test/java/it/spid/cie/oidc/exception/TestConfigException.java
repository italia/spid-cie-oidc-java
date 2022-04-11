package it.spid.cie.oidc.exception;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

public class TestConfigException {

	@Test
	public void testConstructor1() {
		OIDCException e = new ConfigException("test %s", "test");

		assertNotNull(e);
	}

	@Test
	public void testConstructor2() {
		OIDCException e = new ConfigException("test", new Exception());

		assertNotNull(e);
	}

	@Test
	public void testConstructor3() {
		OIDCException e = new ConfigException(new Exception());

		assertNotNull(e);
	}

}
