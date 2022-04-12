package it.spid.cie.oidc.helper;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.nimbusds.jose.jwk.JWKSet;

import it.spid.cie.oidc.config.RelyingPartyOptions;
import it.spid.cie.oidc.model.FederationEntity;
import it.spid.cie.oidc.test.util.TestUtils;
import it.spid.cie.oidc.util.ArrayUtil;

public class TestOAuth2Helper {

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
	public void testClass1() {
		boolean catched = false;

		RelyingPartyOptions options = null;
		OAuth2Helper helper = null;

		// Chained constructor

		try {
			options = getOptions();

			JWTHelper jwtHelper = new JWTHelper(options);

			helper = new OAuth2Helper(jwtHelper);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(options);
		assertNotNull(helper);
	}

	@Test
	public void testClass2() {
		boolean catched = false;

		RelyingPartyOptions options = null;
		OAuth2Helper helper = null;

		// Chained constructor

		try {
			options = getOptions();

			JWTHelper jwtHelper = new JWTHelper(options);

			helper = new OAuth2Helper(jwtHelper);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);

		// wrong args

		catched = false;

		try {
			helper.performAccessTokenRequest(null, null, null, null, null, null, null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// wrong args

		catched = false;

		try {
			helper.performAccessTokenRequest(
				null, null, null, null, new FederationEntity(), null, null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// wrong args

		catched = false;

		try {
			helper.performAccessTokenRequest(
				null, null, null, null, null, "test", null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// wrong args

		catched = false;

		try {
			FederationEntity clientConf = new FederationEntity();

			clientConf.setSubject(RELYING_PARTY);
			clientConf.setJwks(mockedSPIDProviderPublicJWKS().toString());

			helper.performAccessTokenRequest(
				null, null, null, null, clientConf, SPID_PROVIDER + "test", null);
		}
		catch (Exception e) {
			System.err.println(e);
			catched = true;
		}

		assertTrue(catched);

		// good required args but no mockServer

		catched = false;
		JSONObject accessToken = null;
		try {
			JWKSet jwks = JWTHelper.getJWKSetFromJWK(options.getJwk());

			FederationEntity clientConf = new FederationEntity();

			clientConf.setSubject(RELYING_PARTY);
			clientConf.setJwks(jwks.toString(false));

			accessToken = helper.performAccessTokenRequest(
				null, null, null, null, clientConf, SPID_PROVIDER + "test", null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(accessToken.isEmpty());

		// good required args and wrong mockServer response

		catched = false;

		try {
			wireMockServer.stubFor(
				WireMock.post(
					"/oidc/op/test"
				).willReturn(
					WireMock.ok("invalid-json")
				));

			JWKSet jwks = JWTHelper.getJWKSetFromJWK(options.getJwk());

			FederationEntity clientConf = new FederationEntity();

			clientConf.setSubject(RELYING_PARTY);
			clientConf.setJwks(jwks.toString(false));

			accessToken = helper.performAccessTokenRequest(
				null, null, null, null, clientConf, SPID_PROVIDER + "test", null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(accessToken.isEmpty());
	}

	@Test
	public void testClass3() {
		boolean catched = false;

		RelyingPartyOptions options = null;
		OAuth2Helper helper = null;

		// Chained constructor

		try {
			options = getOptions();

			JWTHelper jwtHelper = new JWTHelper(options);

			helper = new OAuth2Helper(jwtHelper);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);

		// wrong args

		catched = false;

		try {
			helper.sendRevocationRequest(null, null, null, null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// wrong args

		catched = false;

		try {
			helper.sendRevocationRequest(
				null, null, null, new FederationEntity());
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// wrong args

		catched = false;

		try {
			helper.sendRevocationRequest(null, null, "test", null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// wrong args

		catched = false;

		try {
			FederationEntity clientConf = new FederationEntity();

			clientConf.setSubject(RELYING_PARTY);
			clientConf.setJwks(mockedSPIDProviderPublicJWKS().toString());

			helper.sendRevocationRequest(null, null, "test", clientConf);
		}
		catch (Exception e) {
			System.err.println(e);
			catched = true;
		}

		assertTrue(catched);

		// required args but wrong url

		catched = false;

		try {
			JWKSet jwks = JWTHelper.getJWKSetFromJWK(options.getJwk());

			FederationEntity clientConf = new FederationEntity();

			clientConf.setSubject(RELYING_PARTY);
			clientConf.setJwks(jwks.toString(false));

			helper.sendRevocationRequest(null, null, "test", clientConf);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// required args but bad mock server

		catched = false;

		try {
			wireMockServer.resetAll();

			wireMockServer.stubFor(
				WireMock.post(
					"/oidc/op/test"
				).willReturn(
					WireMock.forbidden()
				));

			JWKSet jwks = JWTHelper.getJWKSetFromJWK(options.getJwk());

			FederationEntity clientConf = new FederationEntity();

			clientConf.setSubject(RELYING_PARTY);
			clientConf.setJwks(jwks.toString(false));

			helper.sendRevocationRequest(null, null, SPID_PROVIDER + "test", clientConf);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);

		// good required args and good mockServer response

		catched = false;

		try {
			wireMockServer.resetAll();

			wireMockServer.stubFor(
				WireMock.post(
					"/oidc/op/test"
				).willReturn(
					WireMock.ok()
				));

			JWKSet jwks = JWTHelper.getJWKSetFromJWK(options.getJwk());

			FederationEntity clientConf = new FederationEntity();

			clientConf.setSubject(RELYING_PARTY);
			clientConf.setJwks(jwks.toString(false));

			helper.sendRevocationRequest(null, null, SPID_PROVIDER + "test", clientConf);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
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
			.setJWK(TestUtils.getContent("rp-jwks.json"))
			.setTrustMarks(TestUtils.getContent("rp-trust-marks.json"));

		return options;
	}

	private JSONObject mockedSPIDProviderPublicJWKS() throws Exception {
		return new JSONObject(TestUtils.getContent("spid-op-public-jwks.json"));
	}



}
