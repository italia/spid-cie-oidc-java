package it.spid.cie.oidc.handler;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import it.spid.cie.oidc.config.OIDCConstants;
import it.spid.cie.oidc.config.RelyingPartyOptions;
import it.spid.cie.oidc.handler.extras.MemoryStorage;
import it.spid.cie.oidc.schemas.WellKnownData;
import it.spid.cie.oidc.util.ArrayUtil;

public class TestRelyingPartyHandlerWellKnown {

	private static String TRUST_ANCHOR = "http://127.0.0.1:18000/";
	private static String SPID_PROVIDER = "http://127.0.0.1:18000/oidc/op/";
	private static String RELYING_PARTY = "http://127.0.0.1:18080/oidc/rp/";

	@Test
	public void testClass1() {
		RelyingPartyOptions options = getOptions();

		boolean catched = false;

		try {
			new RelyingPartyHandler(options, null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		catched = false;
		RelyingPartyHandler handler = null;

		try {
			handler = new RelyingPartyHandler(
				options, new MemoryStorage());
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(handler);
	}

	@Test
	public void testWellKnown1() {
		RelyingPartyOptions options = getOptions();

		boolean catched = false;
		WellKnownData wellKnown = null;

		try {
			RelyingPartyHandler handler = new RelyingPartyHandler(
				options, new MemoryStorage());

			wellKnown = handler.getWellKnownData(false);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(wellKnown.hasOnlyJwks());
	}

	@Test
	public void testWellKnown2b() {
		RelyingPartyOptions options = getOptions();

		boolean catched = false;
		WellKnownData wellKnown = null;

		try {
			options.setJWKFed(getContent("rp-jwks.json"));

			options.setJWKCore(getContent("rp-core-jwks.json"));

			RelyingPartyHandler handler = new RelyingPartyHandler(
				options, new MemoryStorage());

			wellKnown = handler.getWellKnownData(false);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(wellKnown.isIntermediate());
	}

	@Test
	public void testWellKnown2c() {
		RelyingPartyOptions options = getOptions();

		boolean catched = false;
		WellKnownData wellKnown = null;

		try {
			options.setJWKFed(getContent("rp-jwks.json"));
			options.setJWKCore(getContent("rp-core-jwks.json"));
			options.setTrustMarks(getContent("rp-trust-marks.json"));

			RelyingPartyHandler handler = new RelyingPartyHandler(
				options, new MemoryStorage());

			wellKnown = handler.getWellKnownData(false);
		}
		catch (Exception e) {
			System.out.println(e);
			catched = true;
		}

		assertFalse(catched);
		assertTrue(wellKnown.isComplete());
	}

	@Test
	public void testWellKnown2d() {
		RelyingPartyOptions options = getOptions();

		boolean catched = false;
		WellKnownData wellKnown = null;

		try {
			options.setJWKFed(getContent("rp-jwks.json"));
			options.setJWKCore(getContent("rp-core-jwks.json"));
			options.setTrustMarks(getContent("rp-trust-marks.json"));

			RelyingPartyHandler handler = new RelyingPartyHandler(
				options, new MemoryStorage());

			wellKnown = handler.getWellKnownData(
				RELYING_PARTY + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL,
				true);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(wellKnown.isComplete());
	}

	@Test
	public void testWellKnown2e() {
		RelyingPartyOptions options = getOptions();

		boolean catched = false;
		WellKnownData wellKnown = null;

		try {
			options.setJWKFed(getContent("rp-jwks.json"));
			options.setJWKCore(getContent("rp-core-jwks.json"));
			options.setTrustMarks(getContent("rp-trust-marks.json"));

			RelyingPartyHandler handler = new RelyingPartyHandler(
				options, new MemoryStorage());

			wellKnown = handler.getWellKnownData(
				RELYING_PARTY + "ko/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL,
				true);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
		assertNull(wellKnown);
	}

	@Test
	public void testWellKnown2f() {
		RelyingPartyOptions options = getOptions();

		boolean catched = false;
		WellKnownData wellKnown = null;

		try {
			options.setJWKFed(getContent("rp-jwks.json"));
			options.setJWKCore(getContent("rp-core-jwks.json"));
			options.setTrustMarks(getContent("rp-trust-marks.json"));

			RelyingPartyHandler handler = new RelyingPartyHandler(
				options, new MemoryStorage());

			handler.getWellKnownData(
				RELYING_PARTY  +  OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL, true);

			wellKnown = handler.getWellKnownData(
				RELYING_PARTY + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL, true);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(wellKnown.isComplete());
	}

	@Test
	public void testWellKnown2g() {
		RelyingPartyOptions options = getOptions();

		boolean catched = false;
		WellKnownData wellKnown = null;

		try {
			options.setJWKFed(getContent("rp-jwks.json"));
			options.setJWKCore(getContent("rp-core-jwks.json"));
			options.setTrustMarks(getContent("rp-trust-marks.json"));

			RelyingPartyHandler handler = new RelyingPartyHandler(
				options, new MemoryStorage());

			handler.getWellKnownData(false);

			wellKnown = handler.getWellKnownData(false);
		}
		catch (Exception e) {
			System.out.println(e);
			catched = true;
		}

		assertFalse(catched);
		assertTrue(wellKnown.isComplete());
	}

	private RelyingPartyOptions getOptions() {
		Map<String, String> spidProviders = new HashMap<>();

		spidProviders.put(SPID_PROVIDER, TRUST_ANCHOR);

		RelyingPartyOptions options = new RelyingPartyOptions()
			.setDefaultTrustAnchor(TRUST_ANCHOR)
			.setClientId(RELYING_PARTY)
			.setSPIDProviders(spidProviders)
			.setTrustAnchors(ArrayUtil.asSet(TRUST_ANCHOR))
			.setApplicationName("JUnit RP")
			.setRedirectUris(ArrayUtil.asSet(RELYING_PARTY + "callback"));

		return options;
	}

	private String getContent(String resourceName) throws Exception {
		ClassLoader classLoader = getClass().getClassLoader();
		File file = new File(classLoader.getResource(resourceName).getFile());

		return Files.readString(file.toPath());
	}

}
