package it.spid.cie.oidc.handler;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.jwk.KeyUse;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

import it.spid.cie.oidc.config.OIDCConstants;
import it.spid.cie.oidc.config.RelyingPartyOptions;
import it.spid.cie.oidc.handler.extras.MemoryStorage;
import it.spid.cie.oidc.handler.extras.MockRelyingPartyLogoutCallback;
import it.spid.cie.oidc.helper.JWTHelper;
import it.spid.cie.oidc.model.AuthnToken;
import it.spid.cie.oidc.model.TrustChain;
import it.spid.cie.oidc.schemas.OIDCProfile;
import it.spid.cie.oidc.schemas.ProviderButtonInfo;
import it.spid.cie.oidc.util.ArrayUtil;
import it.spid.cie.oidc.util.JSONUtil;
import it.spid.cie.oidc.util.Validator;

public class TestRelyingPartyHandler {

	private static String TRUST_ANCHOR = "http://127.0.0.1:18000/";
	private static String SPID_PROVIDER = "http://127.0.0.1:18000/oidc/op/";
	private static String RELYING_PARTY = "http://127.0.0.1:18080/oidc/rp/";

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
	public void testAuthnURL1() {
		boolean catched = false;

		try {
			RelyingPartyOptions options = getOptions();

			RelyingPartyHandler handler = new RelyingPartyHandler(
				options, new MemoryStorage());

			handler.getAuthorizeURL(null, null, null, null, null, null);
		}
		catch (Exception e) {
			System.err.println(e);
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testAuthnURL2() {
		boolean catched = false;

		try {
			RelyingPartyOptions options = getOptions();

			RelyingPartyHandler handler = new RelyingPartyHandler(
				options, new MemoryStorage());

			handler.getAuthorizeURL(SPID_PROVIDER, "fake-url", null, null, null, null);
		}
		catch (Exception e) {
			System.err.println(e);
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testProviderButtons() {
		boolean catched = false;

		List<ProviderButtonInfo> cieButtons = null;
		List<ProviderButtonInfo> spidButtons = null;

		try {
			wireMockServer.resetAll();

			// SPID Provider Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/oidc/op/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(mockedSPIDProviderEntityConfiguration())
				));

			// TrustAnchor Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(mockedTrustAnchorEntityConfiguration())
				));

			// TrustAnchor fetch Provider

			wireMockServer.stubFor(
				WireMock.get(
						WireMock.urlPathMatching("/fetch.*")
					).withQueryParam(
						"sub", WireMock.equalTo(SPID_PROVIDER)
					).willReturn(
						WireMock.ok(mockedSPIDProviderEntityStatement())
					));

			RelyingPartyOptions options = getOptions();

			options.setCIEProviders(options.getSPIDProviders());

			RelyingPartyHandler handler = new RelyingPartyHandler(
				options, new MemoryStorage());

			spidButtons = handler.getProviderButtonInfos(OIDCProfile.SPID);
			cieButtons = handler.getProviderButtonInfos(OIDCProfile.CIE);
		}
		catch (Exception e) {
			System.err.println(e);
			catched = true;
		}

		assertFalse(catched);
		assertTrue(spidButtons.size() == 1);
		assertTrue(cieButtons.size() == 1);
	}

	@Test
	public void testLoginLogout() {
		MemoryStorage storage = new MemoryStorage();

		doTestLoginLogout(storage);

		// Expire provider TrustChain to force rebuild

		boolean catched = false;

		try {
			TrustChain taChain = storage.fetchTrustChain(SPID_PROVIDER, TRUST_ANCHOR);

			taChain.setExpiresOn(LocalDateTime.now());

			storage.storeTrustChain(taChain);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);

		doTestLoginLogout(storage);

		// Disable provider TrustChain to force error

		catched = false;

		try {
			TrustChain taChain = storage.fetchTrustChain(SPID_PROVIDER, TRUST_ANCHOR);

			taChain.setActive(false);

			storage.storeTrustChain(taChain);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);

		doTestLoginLogout2(storage);
	}

	protected void doTestLoginLogout(MemoryStorage storage) {
		boolean catched = false;
		String url = "";
		RelyingPartyOptions options = null;
		RelyingPartyHandler handler = null;

		try {
			wireMockServer.resetAll();

			// SPID Provider Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/oidc/op/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(mockedSPIDProviderEntityConfiguration())
				));

			// TrustAnchor Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(mockedTrustAnchorEntityConfiguration())
				));

			// TrustAnchor fetch Provider

			wireMockServer.stubFor(
				WireMock.get(
						WireMock.urlPathMatching("/fetch.*")
					).withQueryParam(
						"sub", WireMock.equalTo(SPID_PROVIDER)
					).willReturn(
						WireMock.ok(mockedSPIDProviderEntityStatement())
					));

//			wireMockServer.getStubMappings().forEach(sb -> {
//				System.out.println("stub:" + sb.toString());
//			});

			options = getOptions();

			handler = new RelyingPartyHandler(options, storage);

			url = handler.getAuthorizeURL(
				SPID_PROVIDER, null, null, null, null, null);
		}
		catch (Exception e) {
			//System.err.println(e);
			e.printStackTrace();
			catched = true;
		}

		assertFalse(catched);


		Map<String, String> urlParams = getURLParams(url);

		String state = urlParams.get("state");
		String code = urlParams.get("code_challenge");

		assertNotNull(state);
		assertNotNull(code);

		catched = false;
		JSONObject userInfo = null;

		try {
			// SPID Provider Entity Configuration

			wireMockServer.stubFor(
				WireMock.post(
					"/oidc/op/token/"
				).willReturn(
					WireMock.ok(
						mockedSPIDProviderToken()
					).withHeader(
						"content-type", "application/json")
				));

			// SPID Provider UserInfo

			wireMockServer.stubFor(
				WireMock.get(
					WireMock.urlPathMatching("/oidc/op/introspection/.*")
				).willReturn(
					WireMock.ok(mockedSPIDProviderUserInfo())
				));

			userInfo = handler.getUserInfo(state, code);
		}
		catch (Exception e) {
			//System.err.println(e);
			e.printStackTrace();
			catched = true;
		}

		assertFalse(catched);
		assertFalse(userInfo.isEmpty());

		AuthnToken authnToken = storage.fetchAuthnToken(state);

		assertNotNull(authnToken);

		String userKey = authnToken.getUserKey();

		assertNotNull(userKey);

		catched = false;

		try {
			// SPID Provider Logout

			wireMockServer.stubFor(
				WireMock.post(
					"/oidc/op/revocation/"
				).willReturn(
					WireMock.ok("")
				));

			handler.performLogout(userKey, new MockRelyingPartyLogoutCallback());
		}
		catch (Exception e) {
			//System.err.println(e);
			e.printStackTrace();
			catched = true;
		}

		assertFalse(catched);
	}

	protected void doTestLoginLogout2(MemoryStorage storage) {
		boolean catched = false;
		RelyingPartyOptions options = null;
		RelyingPartyHandler handler = null;

		try {
			wireMockServer.resetAll();

			// SPID Provider Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/oidc/op/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(mockedSPIDProviderEntityConfiguration())
				));

			// TrustAnchor Entity Configuration

			wireMockServer.stubFor(
				WireMock.get(
					"/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
				).willReturn(
					WireMock.ok(mockedTrustAnchorEntityConfiguration())
				));

			// TrustAnchor fetch Provider

			wireMockServer.stubFor(
				WireMock.get(
						WireMock.urlPathMatching("/fetch.*")
					).withQueryParam(
						"sub", WireMock.equalTo(SPID_PROVIDER)
					).willReturn(
						WireMock.ok(mockedSPIDProviderEntityStatement())
					));

//			wireMockServer.getStubMappings().forEach(sb -> {
//				System.out.println("stub:" + sb.toString());
//			});

			options = getOptions();

			handler = new RelyingPartyHandler(options, storage);

			handler.getAuthorizeURL(
				SPID_PROVIDER, null, null, null, null, null);
		}
		catch (Exception e) {
			//e.printStackTrace();
			catched = true;
		}

		assertTrue(catched);
	}

	private RelyingPartyOptions getOptions() throws Exception {
		Map<String, String> spidProviders = new HashMap<>();

		spidProviders.put(SPID_PROVIDER, TRUST_ANCHOR);

		RelyingPartyOptions options = new RelyingPartyOptions()
			.setDefaultTrustAnchor(TRUST_ANCHOR)
			.setClientId(RELYING_PARTY)
			.setSPIDProviders(spidProviders)
			.setTrustAnchors(ArrayUtil.asSet(TRUST_ANCHOR))
			.setApplicationName("JUnit RP")
			.setRedirectUris(ArrayUtil.asSet(RELYING_PARTY + "callback"))
			.setJWKFed(getContent("rp-jwks.json"))
			.setJWKCore(getContent("rp-core-jwks.json"))
			.setTrustMarks(getContent("rp-trust-marks.json"));

		return options;
	}

	private String getContent(String resourceName) throws Exception {
		ClassLoader classLoader = getClass().getClassLoader();
		File file = new File(classLoader.getResource(resourceName).getFile());

		return Files.readString(file.toPath());
	}

	private static long makeIssuedAt() {
		return LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
	}

	private static long makeExpiresOn() {
		return LocalDateTime.now().toEpochSecond(ZoneOffset.UTC) + (60 * 30);
	}

	private String mockedSPIDProviderEntityConfiguration() throws Exception {
		JSONObject payload = new JSONObject()
			.put("iat", makeIssuedAt())
			.put("exp", makeExpiresOn())
			.put("iss", SPID_PROVIDER)
			.put("sub", SPID_PROVIDER)
			.put("jwks", mockedSPIDProviderPublicJWKS())
			.put("authority_hints", JSONUtil.asJSONArray(TRUST_ANCHOR));

		JSONObject providerMetadata = new JSONObject()
			.put("authorization_endpoint", SPID_PROVIDER + "authorization")
			.put("revocation_endpoint", SPID_PROVIDER + "revocation/")
			.put(
				"id_token_encryption_alg_values_supported",
				JSONUtil.asJSONArray("RSA-OAEP"))
			.put(
				"id_token_encryption_enc_values_supported",
				JSONUtil.asJSONArray("A128CBC-HS256"))
			.put("op_name", "Agenzia per Italia Digitale")
			.put("op_uri", "https://www.agid.gov.it")
			.put("token_endpoint", SPID_PROVIDER + "token/")
			.put("userinfo_endpoint", SPID_PROVIDER + "introspection/")
			.put("claims_parameter_supported", true)
			.put("contacts", JSONUtil.asJSONArray("ops@https://idp.it"))
			.put("client_registration_types_supported", JSONUtil.asJSONArray("automatic"))
			.put("code_challenge_methods_supported", JSONUtil.asJSONArray("S256"))
			.put(
				"request_authentication_methods_supported",
				new JSONObject().put("ar", JSONUtil.asJSONArray("request_object")))
			.put(
				"acr_values_supported", JSONUtil.asJSONArray(
					"https://www.spid.gov.it/SpidL1", "https://www.spid.gov.it/SpidL2",
					"https://www.spid.gov.it/SpidL3"))
			.put(
				"claims_supported", JSONUtil.asJSONArray(
						"https://attributes.eid.gov.it/spid_code",
							"given_name",
							"family_name",
							"place_of_birth",
							"birthdate",
							"gender",
							"https://attributes.eid.gov.it/company_name",
							"https://attributes.eid.gov.it/registered_office",
							"https://attributes.eid.gov.it/fiscal_number",
							"https://attributes.eid.gov.it/company_fiscal_number",
							"https://attributes.eid.gov.it/vat_number",
							"document_details",
							"phone_number",
							"email",
							"https://attributes.eid.gov.it/e_delivery_service",
							"https://attributes.eid.gov.it/eid_exp_date",
							"address"))
			.put(
				"grant_types_supported", JSONUtil.asJSONArray(
					"authorization_code", "refresh_token"))
			.put(
				"id_token_signing_alg_values_supported", JSONUtil.asJSONArray(
					"RS256", "ES256"))
			.put("issuer", SPID_PROVIDER)
			.put("jwks", mockedSPIDProviderPublicJWKS())
			.put("scopes_supported", JSONUtil.asJSONArray("openid", "offline_access"))
			.put("logo_uri", "http://127.0.0.1:8000/static/svg/spid-logo-c-lb.svg")
			.put("organization_name", "SPID OIDC identity provider")
			.put(
				"op_policy_uri",
				"http://127.0.0.1:8000/oidc/op/en/website/legal-information/")
			.put("request_parameter_supported", true)
			.put("request_uri_parameter_supported", true)
			.put("require_request_uri_registration", true)
			.put("response_types_supported", JSONUtil.asJSONArray("code"))
			.put("subject_types_supported", JSONUtil.asJSONArray("pairwise", "public"))
			.put(
				"token_endpoint_auth_methods_supported", JSONUtil.asJSONArray(
					"private_key_jwt"))
			.put(
				"token_endpoint_auth_signing_alg_values_supported", JSONUtil.asJSONArray(
					"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"))
			.put(
				"userinfo_encryption_alg_values_supported", JSONUtil.asJSONArray(
					"RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW",
					"ECDH-ES+A192KW", "ECDH-ES+A256KW"))
			.put(
				"userinfo_encryption_enc_values_supported", JSONUtil.asJSONArray(
					"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM",
					"A192GCM", "A256GCM"))
			.put(
				"userinfo_signing_alg_values_supported", JSONUtil.asJSONArray(
					"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"))
			.put(
				"request_object_encryption_alg_values_supported", JSONUtil.asJSONArray(
					"RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW",
					"ECDH-ES+A192KW", "ECDH-ES+A256KW"))
			.put(
				"request_object_encryption_enc_values_supported", JSONUtil.asJSONArray(
					"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM",
					"A192GCM", "A256GCM"))
			.put("request_object_signing_alg_values_supported", JSONUtil.asJSONArray(
				"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"));


		JSONObject metadata = new JSONObject()
			.put("openid_provider", providerMetadata);

		payload.put("metadata", metadata);

		JSONObject jwks = mockedSPIDProviderPrivateJWKS();

		return createJWS(payload, jwks);
	}

	private String mockedSPIDProviderEntityStatement() throws Exception {
		JSONObject payload = new JSONObject()
			.put("iat", makeIssuedAt())
			.put("exp", makeExpiresOn())
			.put("iss", TRUST_ANCHOR)
			.put("sub", SPID_PROVIDER)
			.put("jwks", mockedSPIDProviderPublicJWKS());

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

		JSONArray trustMarks = new JSONArray(getContent("spid-op-trust-marks.json"));

		payload.put("trust_marks", trustMarks);

		JSONObject jwks = mockedSPIDProviderPrivateJWKS();

		return createJWS(payload, jwks);
	}

	private JSONObject mockedSPIDProviderPublicJWKS() throws Exception {
		return new JSONObject(getContent("spid-op-public-jwks.json"));
	}

	private JSONObject mockedSPIDProviderPrivateJWKS() throws Exception {
		return new JSONObject(getContent("spid-op-private-jwks.json"));
	}

	private String mockedSPIDProviderToken() throws Exception {
		JSONObject providerJWKS = mockedSPIDProviderPrivateJWKS();

		String idToken = createJWS(
			new JSONObject().put("test", "test"), providerJWKS);
		String accessToken = createJWS(
			new JSONObject().put("test", "test"), providerJWKS);

		JSONObject token = new JSONObject()
			.put("id_token", idToken)
			.put("token_type", "Bearer")
			.put("access_token", accessToken);

		return token.toString();
	}

	private String mockedSPIDProviderUserInfo() throws Exception {
		JSONObject providerJWKS = mockedSPIDProviderPrivateJWKS();
		String relyingPartyJWK = getContent("rp-core-jwks.json");
		JWKSet keys = JWTHelper.getJWKSetFromJSON(relyingPartyJWK);
		JWK jwk = keys.getKeys().stream()
				.filter(key -> key.getKeyUse() == KeyUse.ENCRYPTION)
				.findFirst()
				.orElse(null);
		String jwkCoreEnc = jwk.toString();
		JSONObject payload = new JSONObject()
			.put(
				"sub", "e6b06083c2644bdc06f5a1cea22e6538b8fd59fc091837938c5969a8390be944")
			.put("given_name", "peppe")
			.put("family_name", "maradona")
			.put("email", "that@ema.il")
			.put("https://attributes.eid.gov.it/fiscal_number", "abcabc00a00a123a");

		return createJWE(payload, providerJWKS, jwkCoreEnc);
	}

	private String mockedTrustAnchorEntityConfiguration() throws Exception {
		JSONObject payload = new JSONObject()
			.put("iat", makeIssuedAt())
			.put("exp", makeExpiresOn())
			.put("iss", TRUST_ANCHOR)
			.put("sub", TRUST_ANCHOR)
			.put("jwks", mockedTrustAnchorPublicJWKS());

		JSONObject trustAnchorMetadata = new JSONObject()
			.put("contacts", JSONUtil.asJSONArray("ta@localhost"))
			.put("federation_fetch_endpoint", TRUST_ANCHOR + "fetch/")
			.put("federation_resolve_endpoint", TRUST_ANCHOR + "resolve/")
			.put("federation_status_endpoint", TRUST_ANCHOR + "trust_mask_status/")
			.put("homepage_uri", TRUST_ANCHOR)
			.put("name", "example TA")
			.put("federation_list_endpoint", TRUST_ANCHOR + "list/");

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

		JSONObject jwks = mockedTrustAnchorPrivateJWKS();

		return createJWS(payload, jwks);
	}

	private static String createJWS(JSONObject payload, JSONObject jwks)
		throws Exception {

		JWKSet jwkSet = JWKSet.parse(jwks.toString());

		JWK jwk = JWTHelper.getFirstJWK(jwkSet);

		RSAKey rsaKey = (RSAKey)jwk;

		JWSSigner signer = new RSASSASigner(rsaKey);
		JWSAlgorithm alg = JWSAlgorithm.RS256;

		// Prepare JWS object with the payload

		JWSObject jwsObject = new JWSObject(
			new JWSHeader.Builder(alg).keyID(jwk.getKeyID()).build(),
			new Payload(payload.toString()));

		// Compute the signature
		jwsObject.sign(signer);

		// Serialize to compact form
		return jwsObject.serialize();
	}

	private static String createJWE(
			JSONObject payload, JSONObject senderJwks, String recipientJWK)
		throws Exception {

		String jws = createJWS(payload, senderJwks);

		//JWKSet recipientJWKSet = JWTHelper.getJWKSetFromJSON(recipientJwks);
		//JWK jwk = JWTHelper.getFirstJWK(recipientJWKSet);
		//RSAKey rsaKey = (RSAKey)jwk;

		RSAKey rsaKey = JWTHelper.parseRSAKey(recipientJWK);

		JWEHeader header = new JWEHeader.Builder(
				JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM
			).keyID(
				rsaKey.getKeyID()
			).contentType(
				"JWT"  // required to indicate nested JWT
			).build();

		JWEObject jweObject = new JWEObject(header, new Payload(jws));

		// Encrypt with the recipient's public key
		jweObject.encrypt(new RSAEncrypter(rsaKey.toRSAPublicKey()));

		// Serialise to JWE compact form
		return jweObject.serialize();
	}

	private JSONObject mockedTrustAnchorPublicJWKS() throws Exception {
		return new JSONObject(getContent("ta-public-jwks.json"));
	}

	private JSONObject mockedTrustAnchorPrivateJWKS() throws Exception {
		return new JSONObject(getContent("ta-private-jwks.json"));
	}

	private Map<String, String> getURLParams(String url) {
		Map<String, String> result = new HashMap<>();

		if (Validator.isNullOrEmpty(url)) {
			return result;
		}

		String[] parts = url.split("\\?");

		if (parts.length == 2) {
			String[] params = parts[1].split("&");

			for (String param : params) {
				String[] kvp = param.split("=");

				if (kvp.length > 1) {
					result.put(
						URLDecoder.decode(kvp[0], StandardCharsets.UTF_8),
						URLDecoder.decode(kvp[1], StandardCharsets.UTF_8));
				}
			}
		}

		return result;
	}
}
