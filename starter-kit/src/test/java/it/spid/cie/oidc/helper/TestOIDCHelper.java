package it.spid.cie.oidc.helper;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import org.json.JSONObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.nimbusds.jose.jwk.JWKSet;

import it.spid.cie.oidc.test.util.RPTestUtils;

public class TestOIDCHelper {

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
	public void testOIDCHelperClass() {
		OIDCHelper helper = null;

		boolean catched = false;

		try {
			JWTHelper jwtHelper = new JWTHelper(RPTestUtils.getOptions());

			helper = new OIDCHelper(jwtHelper);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);

		catched = false;

		try {
			helper.getUserInfo("a", "b", null, true, new JWKSet());
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		catched = false;

		try {
			// SPID Provider UserInfo

			wireMockServer.stubFor(
				WireMock.get(
					WireMock.urlPathMatching("/oidc/op/introspection/.*")
				).willReturn(
					WireMock.ok(mockedSPIDProviderUserInfo())
				));

			JSONObject providerConf = new JSONObject()
				.put("userinfo_endpoint", RPTestUtils.SPID_PROVIDER + "introspection/");

			helper.getUserInfo("a", "b", providerConf, true, new JWKSet());
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		catched = false;

		try {
			// SPID Provider UserInfo

			wireMockServer.stubFor(
				WireMock.get(
					WireMock.urlPathMatching("/oidc/op/introspection/.*")
				).willReturn(
					WireMock.badRequest()
				));

			JSONObject providerConf = new JSONObject()
				.put("userinfo_endpoint", RPTestUtils.SPID_PROVIDER + "introspection/");

			helper.getUserInfo("a", "b", providerConf, true, new JWKSet());
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	private String mockedSPIDProviderUserInfo() throws Exception {
		JSONObject providerJWKS = RPTestUtils.mockedSPIDProviderPrivateJWKS();
		String relyingPartyJWK = RPTestUtils.getContent("rp-core-jwks.json");
		JWKSet keys = JWTHelper.getJWKSetFromJSON(relyingPartyJWK);
		JWK jwk = keys.getKeys().stream()
				.filter(key -> key.getKeyUse() == KeyUse.ENCRYPTION)
				.findFirst()
				.orElse(null);
		String jwkCoreEnc = jwk.toString();

		JSONObject payload = new JSONObject()
			.put(
				"sub", "e6b06083c2644bdc06f5a1cea22e6538b8fd59fc091837938c5969a8390be944")
			.put("https://attributes.spid.gov.it/name", "peppe")
			.put("https://attributes.spid.gov.it/familyName", "maradona")
			.put("https://attributes.spid.gov.it/email", "that@ema.il")
			.put("https://attributes.spid.gov.it/fiscalNumber", "abcabc00a00a123a");

		return RPTestUtils.createJWE(payload, providerJWKS, jwkCoreEnc);
	}


}
