package it.spid.cie.oidc.util;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class TestValidator {

	@Test
	public void testConstructor() {
		Validator obj = new Validator();

		assertNotNull(obj);
	}

	@Test
	public void testIsNullOrEmpty1() {
		assertTrue(Validator.isNullOrEmpty(null));
	}

	@Test
	public void testIsNullOrEmpty2() {
		assertTrue(Validator.isNullOrEmpty(""));
	}

	@Test
	public void testIsNullOrEmpty3() {
		assertTrue(Validator.isNullOrEmpty("  	 "));
	}

	@Test
	public void testIsNullOrEmpty4() {
		assertFalse(Validator.isNullOrEmpty("  1	 "));
	}

}
