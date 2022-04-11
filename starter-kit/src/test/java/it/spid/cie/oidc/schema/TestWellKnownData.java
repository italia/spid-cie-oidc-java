package it.spid.cie.oidc.schema;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import it.spid.cie.oidc.schemas.WellKnownData;

public class TestWellKnownData {

	@Test
	public void testClass1a() {
		WellKnownData res = WellKnownData.of(1, "test");

		assertNotNull(res);
		assertEquals("[]", res.getPublicJwks());
	}

	@Test
	public void testClass1b() {
		WellKnownData res = WellKnownData.of(1, "test", "fakeJson");

		assertNotNull(res);
		assertEquals("fakeJson", res.getPublicJwks());
		assertEquals("test", res.getValue());
		assertTrue(res.getStep() == 1);
	}

	@Test
	public void testClass2a() {
		WellKnownData res = WellKnownData.of(
			WellKnownData.STEP_ONLY_JWKS, "test", "fakeJson");

		assertTrue(res.hasOnlyJwks());
		assertFalse(res.isIntermediate());
		assertFalse(res.isComplete());
	}

	@Test
	public void testClass2b() {
		WellKnownData res = WellKnownData.of(
			WellKnownData.STEP_INTERMEDIATE, "test", "fakeJson");

		assertFalse(res.hasOnlyJwks());
		assertTrue(res.isIntermediate());
		assertFalse(res.isComplete());
	}

	@Test
	public void testClass2c() {
		WellKnownData res = WellKnownData.of(
			WellKnownData.STEP_COMPLETE, "test", "fakeJson");

		assertFalse(res.hasOnlyJwks());
		assertFalse(res.isIntermediate());
		assertTrue(res.isComplete());
	}

}
