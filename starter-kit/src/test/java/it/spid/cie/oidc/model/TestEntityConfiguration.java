package it.spid.cie.oidc.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.nimbusds.jose.jwk.JWKSet;

import it.spid.cie.oidc.config.OIDCConstants;
import it.spid.cie.oidc.helper.JWTHelper;
import it.spid.cie.oidc.test.util.RPTestUtils;
import it.spid.cie.oidc.util.JSONUtil;

public class TestEntityConfiguration {

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
	public void testEntityConfigurationClass() {
		JWTHelper jwtHelper = null;
		EntityConfiguration ec  = null;

		boolean catched = false;

		try {
			jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			String es = RPTestUtils.mockedSPIDProviderEntityStatement();

			ec = new EntityConfiguration(es, jwtHelper);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);

		// Case: getter before processing

		catched = false;

		try {
			ec.getConstraint("test", 0);
			ec.getExp();
			ec.getExpiresOn();
			ec.getFederationFetchEndpoint();
			ec.getIssuedAt();
			ec.getIssuer();
			ec.getJwks();
			ec.getJWKSet();
			ec.getJwt();
			ec.getPayload();
			ec.getPayloadMetadata();
			ec.getSubject();
			ec.hasVerifiedBySuperiors();
			ec.addFailedDescendantStatement("test", new JSONObject());
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertFalse(ec.hasJWK("test"));
		assertFalse(ec.hasJWK(""));

		ec.setVerifiedDescendantStatementJwt("test");
		assertEquals(ec.getVerifiedDescendantStatementJwt(), "test");

		ec.addVerifiedDescendantStatement("1",new JSONObject().put("test","test"));
		List descendant = ec.getVerifiedDescendantStatement();
		assertEquals(descendant.size(),1);

		catched = false;
		EntityConfiguration ec2 = null;

		try {
			CachedEntityInfo cei = CachedEntityInfo.of(
				ec.getSubject(), ec.getIssuer(), ec.getExpiresOn(), ec.getIssuedAt(),
				ec.getPayload(), ec.getJwt());

			ec2 = EntityConfiguration.of(cei, jwtHelper);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(ec2);
		assertEquals(ec.getExp(), ec2.getExp());
	}

	@Test
	public void test_validateBySuperior() {
		EntityConfiguration ec = null;
		boolean catched = false;

		try {
			JWTHelper jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			String es = RPTestUtils.mockedSPIDProviderEntityStatement();

			ec = new EntityConfiguration(es, jwtHelper);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(ec);

		catched = false;
		boolean res = false;

		try {
			res = ec.validateBySuperior("test", null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertFalse(res);
	}

	@Test
	public void test_validateByItself() {
		EntityConfiguration ec = null;
		boolean catched = false;

		try {
			JWTHelper jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			String es = mockedSPIDProviderEntityStatement2();

			ec = new EntityConfiguration(es, jwtHelper);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(ec);

		catched = false;
		boolean res = false;

		try {
			res = ec.validateItself();
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertFalse(res);
	}

	@Test
	public void test_validateDescendant() {
		EntityConfiguration ec = null;
		boolean catched = false;

		try {
			JWTHelper jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			String es = RPTestUtils.mockedSPIDProviderEntityStatement();

			ec = new EntityConfiguration(es, jwtHelper);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(ec);

		catched = false;
		boolean res = false;

		try {
			String es2 = mockedSPIDProviderEntityStatement3();

			res = ec.validateDescendant(es2);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void test_validateBySuperiors() {
		JWTHelper jwtHelper = null;
		EntityConfiguration ec = null;
		boolean catched = false;

		try {
			jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			String es = RPTestUtils.mockedSPIDProviderEntityStatement();

			ec = new EntityConfiguration(es, jwtHelper);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(ec);

		catched = false;
		Map<String, EntityConfiguration> res = null;

		try {
			String es2 = mockedTrustAnchorEntityConfigurationC1();

			List<EntityConfiguration> superiors = Arrays.asList(
				new EntityConfiguration(es2, jwtHelper));

			res = ec.validateBySuperiors(superiors);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(res.size() == 0);
	}

	@Test
	public void test_gettrustMarkIssuers() {
		JWTHelper jwtHelper = null;
		EntityConfiguration ec = null;
		boolean catched = false;

		try {
			jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			String es = mockedTrustAnchorEntityConfigurationC2();

			ec = new EntityConfiguration(es, jwtHelper);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(ec);

		catched = false;
		Map<String, Set<String>> res = null;

		try {
			res = ec.gettrustMarkIssuers();
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(res.size() == 3);
	}

	@Test
	public void test_hasConstraint() {
		JWTHelper jwtHelper = null;
		EntityConfiguration ec = null;
		boolean catched = false;

		try {
			jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			String es = mockedTrustAnchorEntityConfigurationC2();

			ec = new EntityConfiguration(es, jwtHelper);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(ec);

		catched = false;
		boolean res = false;

		try {
			res = ec.hasConstraint("random");
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertFalse(res);
	}

	@Test
	public void test_getSuperiors() {
		JWTHelper jwtHelper = null;
		EntityConfiguration ec = null;
		String es = null;
		boolean catched = false;

		try {
			jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			es = mockedSPIDProviderEntityStatement1();

			ec = new EntityConfiguration(es, jwtHelper);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(ec);

		catched = false;
		Map<String, EntityConfiguration> res = null;

		try {
			wireMockServer.resetAll();

			// TrustAnchor Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(RPTestUtils.mockedTrustAnchorEntityConfiguration())
				));


			List<EntityConfiguration> superiorHints = new ArrayList<>();

			res = ec.getSuperiors(1, superiorHints);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(res.size() == 1);

		catched = false;
		res = null;

		try {
			wireMockServer.resetAll();

			// TrustAnchor Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.badRequest()
				));

			ec = new EntityConfiguration(es, jwtHelper);

			List<EntityConfiguration> superiorHints = new ArrayList<>();

			res = ec.getSuperiors(1, superiorHints);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(res.size() == 0);
	}

	@Test
	public void test_validateByAllowedTrustMarks() {
		JWTHelper jwtHelper = null;
		EntityConfiguration ec = null;
		EntityConfiguration ta = null;
		boolean catched = false;

		try {
			jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			String es = mockedSPIDProviderEntityStatement4();

			String es2 = RPTestUtils.mockedTrustAnchorEntityConfiguration();

			ta = new EntityConfiguration(es2, jwtHelper);

			ec = new EntityConfiguration(es, ta, jwtHelper);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(ec);

		catched = false;
		boolean res = false;

		try {
			ec.setAllowedTrustMarks(new String[0]);

			res = ec.validateByAllowedTrustMarks();
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(res);

		catched = false;
		res = false;

		try {
			ec.setAllowedTrustMarks(new String[] { "test" });

			res = ec.validateByAllowedTrustMarks();
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertFalse(res);

		catched = false;
		res = false;

		try {
			String es = mockedSPIDProviderEntityStatement5();

			ec = new EntityConfiguration(es, ta, jwtHelper);

			ec.setAllowedTrustMarks(new String[] { "test" });

			res = ec.validateByAllowedTrustMarks();
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
		assertFalse(res);

		catched = false;
		res = false;

		try {
			String es = mockedSPIDProviderEntityStatement6();

			ec = new EntityConfiguration(es, ta, jwtHelper);

			ec.setAllowedTrustMarks(new String[] { "test" });

			res = ec.validateByAllowedTrustMarks();
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
		assertFalse(res);

		catched = false;
		res = false;

		try {
			wireMockServer.resetAll();

			// TrustMark Issuer1 Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/tmi1/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(RPTestUtils.mockedTrustMarkIssuer1EntityConfiguration())
				));

			String es = mockedSPIDProviderEntityStatement7();

			ec = new EntityConfiguration(es, ta, jwtHelper);

			ec.setAllowedTrustMarks(
				new String[] {
					"https://www.spid.gov.it/certification/rp/public",
					"https://www.spid.gov.it/certification/rp/private"
				});

			res = ec.validateByAllowedTrustMarks();
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(ec.getVerifiedTrustMarks().size() == 1);
	}

	@Test
	public void test_isTrustMarkAllowed() {
		JWTHelper jwtHelper = null;
		EntityConfiguration ec  = null;
		Method privateMethod = null;

		boolean catched = false;

		try {
			jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			String es = RPTestUtils.mockedSPIDProviderEntityStatement();

			ec = new EntityConfiguration(es, jwtHelper);

			privateMethod = EntityConfiguration.class.getDeclaredMethod(
				"isTrustMarkAllowed", JSONObject.class);

			privateMethod.setAccessible(true);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);

		boolean returnValue = false;
		catched = false;

		try {
			JSONObject trustMark = new JSONObject();

			returnValue = (boolean) privateMethod.invoke(ec, trustMark);
		}
		catch (Exception e) {
			System.err.println(e);
			catched = true;
		}

		assertFalse(catched);
		assertTrue(returnValue);
	}

	private String mockedSPIDProviderEntityStatement1() throws Exception {
		JSONObject payload = new JSONObject()
			.put("iat", RPTestUtils.makeIssuedAt())
			.put("exp", RPTestUtils.makeExpiresOn())
			.put("iss", RPTestUtils.TRUST_ANCHOR)
			.put("sub", RPTestUtils.SPID_PROVIDER)
			.put("jwks", RPTestUtils.mockedSPIDProviderPublicJWKS());

		JSONObject providerPolicy = new JSONObject()
			.put(
				"subject_types_supported", new JSONObject()
					.put("value", JSONUtil.asJSONArray("pairwise")))
			.put(
				"id_token_signing_alg_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"RS256", "RS384", "RS512", "ES256", "ES384", "ES512")))
			.put(
				"userinfo_signing_alg_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"RS256", "RS384", "RS512", "ES256", "ES384", "ES512")))
			.put(
				"token_endpoint_auth_methods_supported", new JSONObject()
					.put("value", JSONUtil.asJSONArray("private_key_jwt")))
			.put(
				"userinfo_encryption_alg_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW",
							"ECDH-ES+A192KW", "ECDH-ES+A256KW")))
			.put(
				"userinfo_encryption_enc_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM",
							"A192GCM", "A256GCM")))
			.put(
				"request_object_encryption_alg_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW",
							"ECDH-ES+A192KW", "ECDH-ES+A256KW")))
			.put(
				"request_object_encryption_enc_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM",
							"A192GCM", "A256GCM")))
			.put(
				"request_object_signing_alg_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"RS256", "RS384", "RS512", "ES256", "ES384", "ES512")));

		payload.put(
			"metadata_policy", new JSONObject().put("openid_provider", providerPolicy));

		JSONArray trustMarks = new JSONArray(
			RPTestUtils.getContent("spid-op-trust-marks.json"));

		payload.put("trust_marks", trustMarks);

		payload.put("authority_hints", JSONUtil.asJSONArray(
			RPTestUtils.TRUST_ANCHOR + "1", RPTestUtils.TRUST_ANCHOR + "2",
			RPTestUtils.TRUST_ANCHOR));

		JSONObject jwks = RPTestUtils.mockedSPIDProviderPrivateJWKS();

		return RPTestUtils.createJWS(payload, jwks);
	}

	private String mockedSPIDProviderEntityStatement2() throws Exception {
		JWKSet jwkSet = RPTestUtils.createJWKSet();

		JSONObject publicJwks = new JSONObject(jwkSet.toJSONObject(true));
		JSONObject privateJwks = RPTestUtils.mockedSPIDProviderPrivateJWKS();

		JSONObject payload = mockedSPIDProviderEntityStatementJSON(publicJwks);

		return RPTestUtils.createJWS(payload, privateJwks);
	}

	private String mockedSPIDProviderEntityStatement3() throws Exception {
		JWKSet jwkSet = RPTestUtils.createJWKSet();

		JSONObject publicJwks = new JSONObject(jwkSet.toJSONObject(true));
		JSONObject privateJwks = new JSONObject(jwkSet.toJSONObject(false));

		JSONObject payload = mockedSPIDProviderEntityStatementJSON(publicJwks);

		return RPTestUtils.createJWS(payload, privateJwks);
	}

	private String mockedSPIDProviderEntityStatement4() throws Exception {
		JWKSet jwkSet = RPTestUtils.createJWKSet();

		JSONObject publicJwks = new JSONObject(jwkSet.toJSONObject(true));
		JSONObject privateJwks = new JSONObject(jwkSet.toJSONObject(false));

		JSONObject payload = mockedSPIDProviderEntityStatementJSON(publicJwks);

		payload.remove("trust_marks");

		return RPTestUtils.createJWS(payload, privateJwks);
	}

	private String mockedSPIDProviderEntityStatement5() throws Exception {
		JWKSet jwkSet = RPTestUtils.createJWKSet();

		JSONObject publicJwks = new JSONObject(jwkSet.toJSONObject(true));
		JSONObject privateJwks = new JSONObject(jwkSet.toJSONObject(false));

		JSONObject payload = mockedSPIDProviderEntityStatementJSON(publicJwks);

		payload.remove("trust_marks");

		payload.put("trust_marks", new JSONArray().put("test"));

		return RPTestUtils.createJWS(payload, privateJwks);
	}

	private String mockedSPIDProviderEntityStatement6() throws Exception {
		JWKSet jwkSet = RPTestUtils.createJWKSet();

		JSONObject publicJwks = new JSONObject(jwkSet.toJSONObject(true));
		JSONObject privateJwks = new JSONObject(jwkSet.toJSONObject(false));

		JSONObject payload = mockedSPIDProviderEntityStatementJSON(publicJwks);

		payload.remove("trust_marks");

		JSONObject trustMark = new JSONObject().put("id", "test");

		payload.put("trust_marks", new JSONArray().put(trustMark));

		return RPTestUtils.createJWS(payload, privateJwks);
	}

	private String mockedSPIDProviderEntityStatement7() throws Exception {
		//JWKSet jwkSet = RPTestUtils.createJWKSet();
		//JSONObject publicJwks = new JSONObject(jwkSet.toJSONObject(true));
		//JSONObject privateJwks = new JSONObject(jwkSet.toJSONObject(false));
		JSONObject publicJwks = RPTestUtils.mockedTrustAnchorPublicJWKS();
		JSONObject privateJwks = RPTestUtils.mockedTrustAnchorPrivateJWKS();

		JWKSet jwkSet = JWKSet.parse(privateJwks.toMap());

		JSONObject payload = mockedSPIDProviderEntityStatementJSON(publicJwks);

		payload.remove("trust_marks");

		JSONObject trustMark1 = RPTestUtils.mockedTrustMark(
			jwkSet, "https://www.spid.gov.it/certification/rp/public",
			RPTestUtils.TM_ISSUER1, null);

			JSONObject trustMark2 = RPTestUtils.mockedTrustMark(
			jwkSet, "https://www.spid.gov.it/certification/rp/private",
			"https://public.intermediary.spid.local", null);

		payload.put("trust_marks", new JSONArray().put(trustMark1).put(trustMark2));

		return RPTestUtils.createJWS(payload, privateJwks);
	}

	private String mockedTrustAnchorEntityConfigurationC1()
		throws Exception {

		JSONObject payload = new JSONObject()
			.put("iat", RPTestUtils.makeIssuedAt())
			.put("exp", RPTestUtils.makeExpiresOn())
			.put("iss", RPTestUtils.TRUST_ANCHOR)
			.put("sub", RPTestUtils.TRUST_ANCHOR)
			.put("jwks", RPTestUtils.mockedTrustAnchorPublicJWKS());

		JSONObject trustAnchorMetadata = new JSONObject()
			.put("contacts", JSONUtil.asJSONArray("ta@localhost"))
			//.put("federation_fetch_endpoint", RPTestUtils.TRUST_ANCHOR + "fetch/")
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

		JSONObject jwks = RPTestUtils.mockedTrustAnchorPrivateJWKS();

		return RPTestUtils.createJWS(payload, jwks);
	}

	private String mockedTrustAnchorEntityConfigurationC2()
		throws Exception {

		JSONObject payload = new JSONObject()
			.put("iat", RPTestUtils.makeIssuedAt())
			.put("exp", RPTestUtils.makeExpiresOn())
			.put("iss", RPTestUtils.TRUST_ANCHOR)
			.put("sub", RPTestUtils.TRUST_ANCHOR)
			.put("jwks", RPTestUtils.mockedTrustAnchorPublicJWKS());

		JSONObject trustAnchorMetadata = new JSONObject()
			.put("contacts", JSONUtil.asJSONArray("ta@localhost"))
			//.put("federation_fetch_endpoint", RPTestUtils.TRUST_ANCHOR + "fetch/")
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
			.put("wrong-issuer", false)
			.put(
				"https://sgd.aa.it/onboarding", JSONUtil.asJSONArray(
					"https://sgd.aa.it"));

		payload.put("trust_mark_issuers", trustMarkIssuers);
		//payload.put("constraints", new JSONObject().put("max_path_length", 1));

		JSONObject jwks = RPTestUtils.mockedTrustAnchorPrivateJWKS();

		return RPTestUtils.createJWS(payload, jwks);
	}

	private JSONObject mockedSPIDProviderEntityStatementJSON(JSONObject publicJwks)
		throws Exception {

		JSONObject payload = new JSONObject()
			.put("iat", RPTestUtils.makeIssuedAt())
			.put("exp", RPTestUtils.makeExpiresOn())
			.put("iss", RPTestUtils.TRUST_ANCHOR)
			.put("sub", RPTestUtils.SPID_PROVIDER)
			.put("jwks", publicJwks);

		JSONObject providerPolicy = new JSONObject()
			.put(
				"subject_types_supported", new JSONObject()
					.put("value", JSONUtil.asJSONArray("pairwise")))
			.put(
				"id_token_signing_alg_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"RS256", "RS384", "RS512", "ES256", "ES384", "ES512")))
			.put(
				"userinfo_signing_alg_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"RS256", "RS384", "RS512", "ES256", "ES384", "ES512")))
			.put(
				"token_endpoint_auth_methods_supported", new JSONObject()
					.put("value", JSONUtil.asJSONArray("private_key_jwt")))
			.put(
				"userinfo_encryption_alg_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW",
							"ECDH-ES+A192KW", "ECDH-ES+A256KW")))
			.put(
				"userinfo_encryption_enc_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM",
							"A192GCM", "A256GCM")))
			.put(
				"request_object_encryption_alg_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW",
							"ECDH-ES+A192KW", "ECDH-ES+A256KW")))
			.put(
				"request_object_encryption_enc_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM",
							"A192GCM", "A256GCM")))
			.put(
				"request_object_signing_alg_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"RS256", "RS384", "RS512", "ES256", "ES384", "ES512")));

		payload.put(
			"metadata_policy", new JSONObject().put("openid_provider", providerPolicy));

		JSONArray trustMarks = new JSONArray(
			RPTestUtils.getContent("spid-op-trust-marks.json"));

		payload.put("trust_marks", trustMarks);

		return payload;
	}


}
