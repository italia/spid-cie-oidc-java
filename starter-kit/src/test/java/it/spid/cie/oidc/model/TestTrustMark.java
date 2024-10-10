package it.spid.cie.oidc.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.Arrays;

import com.nimbusds.jose.JWEAlgorithm;
import org.json.JSONObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import it.spid.cie.oidc.config.OIDCConstants;
import it.spid.cie.oidc.helper.EntityHelper;
import it.spid.cie.oidc.helper.JWTHelper;
import it.spid.cie.oidc.test.util.RPTestUtils;
import it.spid.cie.oidc.util.JSONUtil;

public class TestTrustMark {

	private static WireMockServer wireMockServer;

	@BeforeClass
	public static void setUp() throws IOException {
		wireMockServer = new WireMockServer(18000);

		wireMockServer.start();

		System.out.println("mock=" + wireMockServer.baseUrl());
	}

	@AfterClass
	public static void tearDown() throws IOException {
		wireMockServer.stop();
	}

	@Test
	public void testTrustMarkClass() {
		TrustMark tm = null;

		boolean catched = false;

		try {
			JWTHelper jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			JWKSet jwkSet = createJWKSet();

			JSONObject jwks = new JSONObject(jwkSet.toJSONObject(false));
			JSONObject payload = new JSONObject()
				.put("id", "id")
				.put("iss", "iss")
				.put("sub", "sub");

			String jwt = RPTestUtils.createJWS(payload, jwks);

			tm = new TrustMark(jwt, jwtHelper);

			tm.toJSON();
			tm.toString();
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertEquals("id", tm.getId());
		assertEquals("iss", tm.getIssuer());
		assertFalse(tm.isValid());
	}

	@Test
	public void test_validateByIssuer1() {
		boolean catched = false;
		boolean res = false;

		try {
			// TrustAnchor Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(RPTestUtils.mockedTrustAnchorEntityConfiguration())
				));

			JWTHelper jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			JSONObject jwks = RPTestUtils.mockedTrustAnchorPrivateJWKS();
			JSONObject payload = new JSONObject()
				.put("id", "id")
				.put("iss", RPTestUtils.TRUST_ANCHOR)
				.put("sub", RPTestUtils.RELYING_PARTY);

			String jwt = RPTestUtils.createJWS(payload, jwks);

			TrustMark tm = new TrustMark(jwt, jwtHelper);

			res = tm.validateByIssuer();
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(res);
	}

	@Test
	public void test_validateByIssuer2() {
		boolean catched = false;
		boolean res = false;

		try {
			// TrustAnchor Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(RPTestUtils.mockedTrustAnchorEntityConfiguration())
				));

			JWTHelper jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			JWKSet jwkSet = createJWKSet();

			JSONObject jwks = new JSONObject(jwkSet.toJSONObject(false));
			JSONObject payload = new JSONObject()
				.put("id", "id")
				.put("iss", RPTestUtils.TRUST_ANCHOR)
				.put("sub", RPTestUtils.RELYING_PARTY);

			String jwt = RPTestUtils.createJWS(payload, jwks);

			TrustMark tm = new TrustMark(jwt, jwtHelper);

			res = tm.validateByIssuer();
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
		assertFalse(res);
	}

	@Test
	public void test_validateByIssuer3() {
		boolean catched = false;
		boolean res = false;

		try {
			// TrustAnchor Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(mockedTrustAnchorEntityConfiguration2())
				));

			JWTHelper jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			JWKSet jwkSet = createJWKSet();

			JSONObject jwks = new JSONObject(jwkSet.toJSONObject(false));
			JSONObject payload = new JSONObject()
				.put("id", "id")
				.put("iss", RPTestUtils.TRUST_ANCHOR)
				.put("sub", RPTestUtils.RELYING_PARTY);

			String jwt = RPTestUtils.createJWS(payload, jwks);

			TrustMark tm = new TrustMark(jwt, jwtHelper);

			res = tm.validateByIssuer();
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertFalse(res);
	}

	@Test
	public void test_validate() {
		boolean catched = false;
		boolean res = false;

		try {
			JWKSet jwkSet = createJWKSet();

			// TrustAnchor Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(mockedTrustAnchorEntityConfiguration3(jwkSet))
				));

			JWTHelper jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			JSONObject jwks = new JSONObject(jwkSet.toJSONObject(false));
			JSONObject payload = new JSONObject()
				.put("id", "id")
				.put("iss", RPTestUtils.TRUST_ANCHOR)
				.put("sub", RPTestUtils.TRUST_ANCHOR);

			String jwt = RPTestUtils.createJWS(payload, jwks);

			TrustMark tm = new TrustMark(jwt, jwtHelper);

			String ec = EntityHelper.getEntityConfiguration(RPTestUtils.TRUST_ANCHOR);

			EntityConfiguration entityEC = new EntityConfiguration(ec, jwtHelper);

			res = tm.validate(entityEC);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(res);

	}

	private static JWKSet createJWKSet() throws Exception {
		RSAKey rsaKey1 = JWTHelper.createRSAKey(JWSAlgorithm.RS256, KeyUse.SIGNATURE);
		RSAKey rsaKey2 = JWTHelper.createRSAEncKey(JWEAlgorithm.RSA_OAEP_256, KeyUse.ENCRYPTION);

		return new JWKSet(Arrays.asList(rsaKey1, rsaKey2));
	}

	/**
	 * Create trust anchor mocked entity configuration with wrong jwks
	 *
	 * @return
	 * @throws Exception
	 */
	private static String mockedTrustAnchorEntityConfiguration2()
		throws Exception {

		JSONObject privateJwks = RPTestUtils.mockedTrustAnchorPrivateJWKS();

		JWKSet jwkSet = createJWKSet();

		JSONObject publicJwks = new JSONObject(jwkSet.toJSONObject());

		return doMockedTrustAnchorEntityConfiguration(privateJwks, publicJwks);
	}

	private static String mockedTrustAnchorEntityConfiguration3(JWKSet jwkSet)
		throws Exception {

		if (jwkSet == null) {
			jwkSet = createJWKSet();
		}

		JSONObject privateJwks = new JSONObject(jwkSet.toJSONObject(false));
		JSONObject publicJwks = new JSONObject(jwkSet.toJSONObject());

		return doMockedTrustAnchorEntityConfiguration(privateJwks, publicJwks);
	}

	private static String doMockedTrustAnchorEntityConfiguration(
			JSONObject privateJwks, JSONObject publicJwks)
		throws Exception {

		JSONObject payload = new JSONObject()
			.put("iat", RPTestUtils.makeIssuedAt())
			.put("exp", RPTestUtils.makeExpiresOn())
			.put("iss", RPTestUtils.TRUST_ANCHOR)
			.put("sub", RPTestUtils.TRUST_ANCHOR)
			.put("jwks", publicJwks);

		JSONObject trustAnchorMetadata = new JSONObject()
			.put("contacts", JSONUtil.asJSONArray("ta@localhost"))
			.put("federation_fetch_endpoint", RPTestUtils.TRUST_ANCHOR + "fetch/")
			.put("federation_resolve_endpoint", RPTestUtils.TRUST_ANCHOR + "resolve/")
			.put("federation_status_endpoint", RPTestUtils.TRUST_ANCHOR + "trust_mask_status/")
			.put("homepage_uri", RPTestUtils.TRUST_ANCHOR)
			.put("name", "example TA")
			.put("federation_list_endpoint", RPTestUtils.TRUST_ANCHOR + "list/");

		payload.put(
			"metadata", new JSONObject().put("federation_entity", trustAnchorMetadata));

		JSONObject trustMarkIssuers = new JSONObject()
			.put(
				"https://www.spid.gov.it/certification/rp/public", JSONUtil.asJSONArray(
					"https://registry.spid.agid.gov.it",
					"https://public.intermediary.spid.it"))
			.put(
				"https://www.spid.gov.it/certification/rp/private", JSONUtil.asJSONArray(
					"https://registry.spid.agid.gov.it",
					"https://private.other.intermediary.it"))
			.put(
				"https://sgd.aa.it/onboarding", JSONUtil.asJSONArray(
					"https://sgd.aa.it"));

		payload.put("trust_mark_issuers", trustMarkIssuers);
		payload.put("constraints", new JSONObject().put("max_path_length", 1));

		return RPTestUtils.createJWS(payload, privateJwks);
	}


}
