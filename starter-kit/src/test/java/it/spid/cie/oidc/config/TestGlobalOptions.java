package it.spid.cie.oidc.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Set;

import org.junit.Test;

public class TestGlobalOptions {

	@Test
	public void testClass1() {
		FakeOptions res = new FakeOptions();

		assertNotNull(res);

		res.getDefaultJWEAlgorithm();
		res.getDefaultJWEEncryption();
		res.getDefaultJWSAlgorithm();

		assertTrue(
			FakeOptions.DEFAULT_EXPIRING_MINUTES == res.getDefaultExpiringMinutes());
	}

	@Test
	public void testClass2a() {
		FakeOptions res = new FakeOptions();

		String defJWEAlg = res.getDefaultJWEAlgorithm();
		String defJWEEnc = res.getDefaultJWEEncryption();
		String defJWSAlg = res.getDefaultJWSAlgorithm();

		res.setDefaultJWEAlgorithm("");
		res.setDefaultJWEEncryption("");
		res.setDefaultJWSAlgorithm("");

		assertEquals(defJWEAlg, res.getDefaultJWEAlgorithm());
		assertEquals(defJWEEnc, res.getDefaultJWEEncryption());
		assertEquals(defJWSAlg, res.getDefaultJWSAlgorithm());

		res.setDefaultJWEAlgorithm("test");
		res.setDefaultJWEEncryption("test");
		res.setDefaultJWSAlgorithm("test");

		assertEquals("test", res.getDefaultJWEAlgorithm());
		assertEquals("test", res.getDefaultJWEEncryption());
		assertEquals("test", res.getDefaultJWSAlgorithm());
	}

	@Test
	public void testClass2b() {
		FakeOptions res = new FakeOptions();

		Set<String> allowedEncAlg = res.getAllowedEncryptionAlgs();
		Set<String> allowedSignAlg = res.getAllowedSigningAlgs();

		res.setAllowedEncryptionAlgs();
		res.setAllowedSigningAlgs();

		assertEquals(allowedEncAlg, res.getAllowedEncryptionAlgs());
		assertEquals(allowedSignAlg, res.getAllowedSigningAlgs());

		res.setAllowedEncryptionAlgs("1", "2", "2");
		res.setAllowedSigningAlgs("1", "2", "2");

		assertTrue(res.getAllowedEncryptionAlgs().size() == 2);
		assertTrue(res.getAllowedSigningAlgs().size() == 2);
	}

	@Test
	public void testClass3a() {
		boolean catched = false;
		FakeOptions res = new FakeOptions();

		try {
			res.setAllowedEncryptionAlgs("1", "2", "2");

			res.validate();
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testClass3b() {
		boolean catched = false;
		FakeOptions res = new FakeOptions();

		try {
			res.setAllowedSigningAlgs("1", "2", "2");

			res.validate();
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testClass3c() {
		boolean catched = false;
		FakeOptions res = new FakeOptions();

		try {
			res.setDefaultJWEAlgorithm("test");

			res.validate();
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testClass3d() {
		boolean catched = false;
		FakeOptions res = new FakeOptions();

		try {
			res.setDefaultJWSAlgorithm("test");

			res.validate();
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testClass4() {
		boolean catched = false;
		FakeOptions res = new FakeOptions();

		try {
			res.validate();
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
	}

	private static class FakeOptions extends GlobalOptions<FakeOptions> {};

}
