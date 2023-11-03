package it.spid.cie.oidc.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

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
import it.spid.cie.oidc.model.extras.ExtTrustChainBuilder;
import it.spid.cie.oidc.test.util.RPTestUtils;
import it.spid.cie.oidc.util.JSONUtil;

public class TestTrustChainBuilder {

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
	public void testTrustChainBuilderClass() {
		TrustChainBuilder tcb = null;

		boolean catched = false;

		try {
			JWTHelper jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			tcb = new TrustChainBuilder(
				RPTestUtils.SPID_PROVIDER, OIDCConstants.OPENID_PROVIDER, jwtHelper);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(tcb);

		catched = false;

		try {
			tcb.getChain();
			//tcb.getChainAsString();
			tcb.getExpiresOn();
			tcb.getFinalMetadata();
			tcb.getPartiesInvolvedAsString();
			tcb.getSubject();
			tcb.getVerifiedTrustMarksAsString();
			tcb.setMaxAuthorityHints(1);
			tcb.setRequiredTrustMask(new String[0]);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);

		catched = false;

		try {
			tcb.start();
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void test_setSubjectConfiguration() {
		boolean catched = false;

		try {
			JWTHelper jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			String es = RPTestUtils.mockedSPIDProviderEntityStatement();

			EntityConfiguration ec = new EntityConfiguration(es, jwtHelper);

			TrustChainBuilder tcb = new TrustChainBuilder(
				RPTestUtils.SPID_PROVIDER, OIDCConstants.OPENID_PROVIDER, jwtHelper);

			tcb.setSubjectConfiguration(ec);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
	}

	@Test
	public void test_setTrustAnchor() {
		boolean catched = false;

		try {
			wireMockServer.resetAll();

			// TrustAnchor Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(RPTestUtils.mockedTrustAnchorEntityConfiguration())
				));

			JWTHelper jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			TrustChainBuilder tcb = new TrustChainBuilder(
				RPTestUtils.SPID_PROVIDER, OIDCConstants.OPENID_PROVIDER, jwtHelper);

			tcb.setTrustAnchor(RPTestUtils.TRUST_ANCHOR);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
	}

	@Test
	public void test_ApplyPolicy() {
		ExtTrustChainBuilder tcb = null;

		boolean catched = false;

		try {
			JWTHelper jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			tcb = new ExtTrustChainBuilder(
				RPTestUtils.SPID_PROVIDER, OIDCConstants.OPENID_PROVIDER, jwtHelper);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(tcb);

		JSONObject res = null;
		catched = false;

		try {
			JSONObject metadata = new JSONObject();

			JSONObject policy = new JSONObject()
				.put("test1", new JSONObject().put("value", "value"))
				.put("test2", new JSONObject().put("add", "add"))
				.put("test3", new JSONObject().put("default", "default"))
				.put("test4", new JSONObject().put("essential", "essential"));

			res = tcb.tastableApplyPolicy(metadata, policy);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);

		catched = false;

		try {
			JSONObject metadata = new JSONObject()
				.put("test1", JSONUtil.asJSONArray("0", "1"))
				.put("test2", JSONUtil.asJSONArray("0", "1", "2", "3"));

			JSONObject policy = new JSONObject()
				.put("test1", new JSONObject().put("value", "value"))
				.put("test2", new JSONObject().put(
					"one_of", JSONUtil.asJSONArray("1", "3")));

			res = tcb.tastableApplyPolicy(metadata, policy);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertEquals("value", res.optString("test1"));
		assertEquals("1", res.optString("test2"));

		catched = false;

		try {
			JSONObject metadata = new JSONObject()
				.put("test1", JSONUtil.asJSONArray("0", "1"))
				.put("test2", JSONUtil.asJSONArray("0", "1", "2", "3"));

			JSONObject policy = new JSONObject()
				.put("test1", new JSONObject().put("value", "value"))
				.put("test2", new JSONObject().put(
					"one_of", JSONUtil.asJSONArray("4", "5")));

			res = tcb.tastableApplyPolicy(metadata, policy);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		catched = false;

		try {
			JSONObject metadata = new JSONObject()
				.put("test1", "0")
				.put("test2", JSONUtil.asJSONArray("0", "1", "2", "3"))
				.put("test3", JSONUtil.asJSONArray("0", "1", "2", "3"))
				.put("test1b", "0")
				.put("test1c", JSONUtil.asJSONArray("0", "1"))
				.put("test1d", JSONUtil.asJSONArray("0", "1"));


			JSONObject policy = new JSONObject()
				.put("test1", new JSONObject().put(
					"add", JSONUtil.asJSONArray("2", "3")))
				.put("test1b", new JSONObject().put("add", "2"))
				.put("test1c", new JSONObject().put("add", "2"))
				.put("test1d", new JSONObject().put(
					"add", JSONUtil.asJSONArray("2", "3")))
				.put("test2", new JSONObject().put(
					"superset_of", JSONUtil.asJSONArray("3", "4", "5")))
				.put("test3", new JSONObject().put(
					"subset_of", JSONUtil.asJSONArray("3", "4", "5")));

			res = tcb.tastableApplyPolicy(metadata, policy);

			//System.out.println(res);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);

		catched = false;

		try {
			JSONObject metadata = new JSONObject()
				.put("test1", JSONUtil.asJSONArray("0", "1"))
				.put("test2", JSONUtil.asJSONArray("0", "1", "2", "3"));

			JSONObject policy = new JSONObject()
				.put("test1", new JSONObject().put("add", "2"))
				.put("test2", new JSONObject().put(
					"superset_of", JSONUtil.asJSONArray("1", "2")));

			res = tcb.tastableApplyPolicy(metadata, policy);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		catched = false;

		try {
			JSONObject metadata = new JSONObject()
				.put("test1", JSONUtil.asJSONArray("0", "1"))
				.put("test2", JSONUtil.asJSONArray("0", "1", "2", "3"));

			JSONObject policy = new JSONObject()
				.put("test1", new JSONObject().put("add", "2"))
				.put("test2", new JSONObject().put(
					"subset_of", JSONUtil.asJSONArray("4", "5")));

			res = tcb.tastableApplyPolicy(metadata, policy);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		catched = false;

		try {
			JSONObject metadata = new JSONObject()
				.put("test1", "1")
				.put("test2", "1");

			JSONObject policy = new JSONObject()
				.put("test1", new JSONObject().put("superset_of", "2"))
				.put("test2", new JSONObject().put("subset_of", "1"));

			res = tcb.tastableApplyPolicy(metadata, policy);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);

		catched = false;

		try {
			JSONObject metadata = new JSONObject()
				.put("test1", "1");

			JSONObject policy = new JSONObject()
				.put("test1", new JSONObject().put(
					"one_of", JSONUtil.asJSONArray("2", "3")));

			res = tcb.tastableApplyPolicy(metadata, policy);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void test_processSubjectConfiguration1() {
		boolean catched = false;

		try {
			wireMockServer.resetAll();

			// Provider Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/oidc/op/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(mockedSPIDProviderEntityStatement2())
				));


			JWTHelper jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			ExtTrustChainBuilder tcb = new ExtTrustChainBuilder(
				RPTestUtils.SPID_PROVIDER, OIDCConstants.OPENID_PROVIDER, jwtHelper);

			tcb.testableProcessSubjectConfiguration();
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void test_processSubjectConfiguration2() {
		boolean catched = false;

		try {
			wireMockServer.resetAll();

			// Provider Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/oidc/op/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(RPTestUtils.mockedSPIDProviderEntityStatement())
				));


			JWTHelper jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			ExtTrustChainBuilder tcb = new ExtTrustChainBuilder(
				RPTestUtils.SPID_PROVIDER, OIDCConstants.OPENID_PROVIDER, jwtHelper);

			tcb.setRequiredTrustMask(
				new String[] {
					"https://www.spid.gov.it/openid-federation/agreement/op-public/"
				});

			tcb.testableProcessSubjectConfiguration();
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// Case ...

		catched = false;

		try {
			wireMockServer.resetAll();

			// Provider Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/oidc/op/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(RPTestUtils.mockedSPIDProviderEntityStatement())
				));

			// TrustAnchor Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(RPTestUtils.mockedTrustAnchorEntityConfiguration())
				));

			JWTHelper jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			ExtTrustChainBuilder tcb = new ExtTrustChainBuilder(
				RPTestUtils.SPID_PROVIDER, OIDCConstants.OPENID_PROVIDER, jwtHelper);

			tcb.setTrustAnchor(RPTestUtils.TRUST_ANCHOR);
			tcb.setRequiredTrustMask(
				new String[] {
					"https://www.spid.gov.it/openid-federation/agreement/op-public/"
				});

			tcb.testableProcessSubjectConfiguration();
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// Case: TrustMark non present in valid list

		catched = false;

		try {
			wireMockServer.resetAll();

			// Provider Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/oidc/op/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(RPTestUtils.mockedSPIDProviderEntityStatement())
				));

			// TrustAnchor Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(RPTestUtils.mockedTrustAnchorEntityConfiguration())
				));

			JWTHelper jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			ExtTrustChainBuilder tcb = new ExtTrustChainBuilder(
				RPTestUtils.SPID_PROVIDER, OIDCConstants.OPENID_PROVIDER, jwtHelper);

			tcb.setTrustAnchor(RPTestUtils.TRUST_ANCHOR);
			tcb.setRequiredTrustMask(
				new String[] {
					"https://www.spid.gov.it/openid-federation/agreement/op-public/ko"
				});

			tcb.testableProcessSubjectConfiguration();
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// Case: TrustMark present and valid

		catched = false;
		String verifiedTrustMarks = "";

		try {
			JWKSet jwkSet = RPTestUtils.createJWKSet();

			wireMockServer.resetAll();

			// Provider Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/oidc/op/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(mockedSPIDProviderEntityStatementC3(jwkSet))
				));

			// TrustAnchor Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(mockedTrustAnchorEntityConfigurationC3(jwkSet))
				));

			JWTHelper jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			ExtTrustChainBuilder tcb = new ExtTrustChainBuilder(
				RPTestUtils.SPID_PROVIDER, OIDCConstants.OPENID_PROVIDER, jwtHelper);

			tcb.setTrustAnchor(RPTestUtils.TRUST_ANCHOR);
			tcb.setRequiredTrustMask(
				new String[] {
					"https://www.spid.gov.it/openid-federation/agreement/op-public/"
				});

			tcb.testableProcessSubjectConfiguration();
			verifiedTrustMarks = tcb.getVerifiedTrustMarksAsString();
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(verifiedTrustMarks);
	}

	@Test
	public void test_processSubjectConfiguration3() {
		boolean catched = false;

		try {
			JWTHelper jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			String es = RPTestUtils.mockedSPIDProviderEntityStatement();

			EntityConfiguration ec = new EntityConfiguration(es, jwtHelper);

			ExtTrustChainBuilder tcb = new ExtTrustChainBuilder(
				RPTestUtils.SPID_PROVIDER, OIDCConstants.OPENID_PROVIDER, jwtHelper);

			tcb.setSubjectConfiguration(ec);
			tcb.testableProcessSubjectConfiguration();
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
	}

	@Test
	public void test_processTrustAnchorConfiguration() {
		boolean catched = false;

		try {
			JWTHelper jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			String es = mockedTrustAnchorEntityConfigurationC4();

			EntityConfiguration ec = new EntityConfiguration(es, jwtHelper);

			ExtTrustChainBuilder tcb = new ExtTrustChainBuilder(
				RPTestUtils.SPID_PROVIDER, OIDCConstants.OPENID_PROVIDER, jwtHelper);

			tcb.setTrustAnchor(ec);
			tcb.testableProcessTrustAnchorConfiguration();
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	private String mockedSPIDProviderEntityStatement2() throws Exception {
		JSONObject payload = new JSONObject()
			.put("iat", RPTestUtils.makeIssuedAt())
			.put("exp", RPTestUtils.makeExpiresOn())
			.put("iss", RPTestUtils.TRUST_ANCHOR)
			.put("sub", RPTestUtils.SPID_PROVIDER);

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

		JSONArray trustMarks = new JSONArray(RPTestUtils.getContent("spid-op-trust-marks.json"));

		payload.put("trust_marks", trustMarks);

		JSONObject jwks = RPTestUtils.mockedSPIDProviderPrivateJWKS();

		return RPTestUtils.createJWS(payload, jwks);
	}

	private String mockedSPIDProviderEntityStatementC3(JWKSet jwkSet) throws Exception {
		JSONObject payload = new JSONObject()
			.put("iat", RPTestUtils.makeIssuedAt())
			.put("exp", RPTestUtils.makeExpiresOn())
			.put("iss", RPTestUtils.TRUST_ANCHOR)
			.put("sub", RPTestUtils.SPID_PROVIDER)
			.put("jwks", JWTHelper.getJWKSetAsJSONObject(jwkSet, true));

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

		JSONArray trustMarks = new JSONArray().put(
			RPTestUtils.mockedTrustMark(
				jwkSet,
				"https://www.spid.gov.it/openid-federation/agreement/op-public/"));

		payload.put("trust_marks", trustMarks);

		JSONObject jwks = new JSONObject(jwkSet.toJSONObject(false));

		return RPTestUtils.createJWS(payload, jwks);
	}

	private static String mockedTrustAnchorEntityConfigurationC3(JWKSet jwkSet)
		throws Exception {

		JSONObject payload = new JSONObject()
			.put("iat", RPTestUtils.makeIssuedAt())
			.put("exp", RPTestUtils.makeExpiresOn())
			.put("iss", RPTestUtils.TRUST_ANCHOR)
			.put("sub", RPTestUtils.TRUST_ANCHOR)
			.put("jwks", JWTHelper.getJWKSetAsJSONObject(jwkSet, true));

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

		JSONObject jwks = new JSONObject(jwkSet.toJSONObject(false));

		return RPTestUtils.createJWS(payload, jwks);
	}

	private static String mockedTrustAnchorEntityConfigurationC4()
		throws Exception {

		JSONObject payload = new JSONObject()
			.put("iat", RPTestUtils.makeIssuedAt())
			.put("exp", RPTestUtils.makeExpiresOn())
			.put("iss", RPTestUtils.TRUST_ANCHOR)
			.put("sub", RPTestUtils.TRUST_ANCHOR)
			.put("jwks", RPTestUtils.mockedTrustAnchorPublicJWKS());

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

		JSONObject jwks = new JSONObject(RPTestUtils.createJWKSet().toJSONObject(false));

		return RPTestUtils.createJWS(payload, jwks);
	}

}
