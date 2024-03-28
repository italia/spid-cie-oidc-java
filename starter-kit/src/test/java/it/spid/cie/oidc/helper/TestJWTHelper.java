package it.spid.cie.oidc.helper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import com.nimbusds.jose.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;

import it.spid.cie.oidc.config.RelyingPartyOptions;
import it.spid.cie.oidc.test.util.TestUtils;
import it.spid.cie.oidc.util.ArrayUtil;

public class TestJWTHelper {

	private static String TRUST_ANCHOR = "http://127.0.0.1:18000/";
	private static String SPID_PROVIDER = "http://127.0.0.1:18000/oidc/op/";
	private static String RELYING_PARTY = "http://127.0.0.1:18080/oidc/rp/";

	@Test
	public void testClass1() {
		RelyingPartyOptions options = new RelyingPartyOptions();

		JWTHelper helper = new JWTHelper(options);

		assertNotNull(helper);
	}

	@Test
	public void testClass2() {
		RSAKey rsaKey = null;
		boolean catched = false;

		try {
			rsaKey = JWTHelper.createRSAKey(null, KeyUse.SIGNATURE);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(rsaKey.getKeyType().equals(KeyType.RSA));
	}

	@Test
	public void testClass2enc() {
		RSAKey rsaKey = null;
		boolean catched = false;

		try {
			rsaKey = JWTHelper.createRSAEncKey(null, KeyUse.ENCRYPTION);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(rsaKey.getKeyType().equals(KeyType.RSA));
	}
	@Test
	public void testClass3() {
		String test = "sample-value";

		String encoded = encode64(test);

		assertEquals(test, JWTHelper.decodeBase64(encoded));
	}

	@Test
	public void testClass4() {
		JSONObject jsonHeader = new JSONObject()
			.put("one", "one");
		JSONObject jsonPayload = new JSONObject()
			.put("two", "two");

		StringBuilder sb1 = new StringBuilder();

		sb1.append(encode64(jsonHeader.toString()));

		boolean catched = false;

		try {
			JWTHelper.fastParse(sb1.toString());
		}
		catch(Exception e) {
			catched = true;
		}

		assertTrue(catched);

		StringBuilder sb2 = new StringBuilder();

		sb2.append(encode64(jsonHeader.toString()));
		sb2.append(".");
		sb2.append(encode64("no-json"));

		catched = false;

		try {
			JWTHelper.fastParse(sb2.toString());
		}
		catch(Exception e) {
			catched = true;
		}

		assertTrue(catched);

		StringBuilder sb3 = new StringBuilder();

		sb3.append(encode64(jsonHeader.toString()));
		sb3.append(".");
		sb3.append(encode64(jsonPayload.toString()));

		catched = false;

		try {
			JWTHelper.fastParse(sb3.toString());
		}
		catch(Exception e) {
			catched = true;
		}

		assertFalse(catched);
	}

	@Test
	public void test_createRSAKey() {
		boolean catched = false;

		try {
			JWTHelper.createRSAKey(JWSAlgorithm.ES256, KeyUse.SIGNATURE);
		}
		catch(Exception e) {
			catched = true;
		}

		assertFalse(catched);
	}

	@Test
	public void test_createRSAEncKey() {
		boolean catched = false;

		try {
			JWTHelper.createRSAEncKey(JWEAlgorithm.RSA_OAEP_256, KeyUse.ENCRYPTION);
		}
		catch(Exception e) {
			catched = true;
		}

		assertFalse(catched);
	}

	@Test
	public void test_fastParseHeader() {
		boolean catched = false;
		JSONObject header = null;

		try {
			JWKSet jwkSet = createJWKSet();

			JSONObject jwks = new JSONObject(jwkSet.toJSONObject(false));
			JSONObject payload = new JSONObject().put("sub", "sub");

			String jws = createJWS(payload, jwks);

			header = JWTHelper.fastParseHeader(jws);
		}
		catch(Exception e) {
			e.printStackTrace();
			catched = true;
		}

		assertFalse(catched);
		assertFalse(header.isEmpty());
	}

	@Test
	public void test_getFirstJWK() {
		boolean catched = false;

		try {
			JWTHelper.getFirstJWK(null);
		}
		catch(Exception e) {
			catched = true;
		}

		assertTrue(catched);

		catched = false;

		try {
			JWTHelper.getFirstJWK(new JWKSet());
		}
		catch(Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void test_getJWKFromJWT() {
		boolean catched = false;
		JWK jwk = null;

		try {
			JWKSet jwkSet = createJWKSet();

			JSONObject jwks = new JSONObject(jwkSet.toJSONObject(false));
			JSONObject payload = new JSONObject().put("sub", "sub");

			String jws = createJWS(payload, jwks);

			jwk = JWTHelper.getJWKFromJWT(jws, jwkSet);
		}
		catch(Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(jwk);
	}

	@Test
	public void test_getJWKSetAsJSONArray() {
		boolean catched = false;
		JSONArray jsonArray = null;

		try {
			RSAKey rsaKey1 = JWTHelper.createRSAKey(null, KeyUse.SIGNATURE);
			RSAKey rsaKey2 = JWTHelper.createRSAEncKey(null, KeyUse.ENCRYPTION);

			JWKSet jwkSet = new JWKSet(Arrays.asList(rsaKey1, rsaKey2));

			jsonArray = JWTHelper.getJWKSetAsJSONArray(jwkSet, true);
		}
		catch(Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(jsonArray.length() == 2);
		assertFalse(jsonArray.getJSONObject(0).has("use"));

		catched = false;
		jsonArray = null;

		try {
			RSAKey rsaKey = JWTHelper.createRSAKey(null, KeyUse.SIGNATURE);
			RSAKey rsaEncKey = JWTHelper.createRSAEncKey(null, KeyUse.ENCRYPTION);
			ECKey ecKey = createECKey(KeyUse.ENCRYPTION);

			JWKSet jwkSet = new JWKSet(Arrays.asList(rsaKey, ecKey, rsaEncKey));

			jsonArray = JWTHelper.getJWKSetAsJSONArray(jwkSet, false);
		}
		catch(Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(jsonArray.length() == 3);
		assertTrue(jsonArray.getJSONObject(0).has("use"));

		catched = false;
		jsonArray = null;

		try {
			RSAKey rsaKey = JWTHelper.createRSAKey(null, KeyUse.SIGNATURE);
			RSAKey rsaEncKey = JWTHelper.createRSAEncKey(null, KeyUse.ENCRYPTION);
			ECKey ecKey = createECKey(KeyUse.ENCRYPTION);

			JWKSet jwkSet = new JWKSet(Arrays.asList(rsaKey, ecKey, rsaEncKey));

			jsonArray = JWTHelper.getJWKSetAsJSONArray(jwkSet, true, false);
		}
		catch(Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(jsonArray.length() == 3);
		assertTrue(jsonArray.getJSONObject(0).has("use"));

		catched = false;
		jsonArray = null;

		try {
			JWK osKey = createOSKey(KeyUse.SIGNATURE);

			JWKSet jwkSet = new JWKSet(Arrays.asList(osKey));

			jsonArray = JWTHelper.getJWKSetAsJSONArray(jwkSet, true, false);
		}
		catch(Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(jsonArray.isEmpty());
	}

	@Test
	public void test_getJWKSetFromJSON1() {
		boolean catched = false;

		try {
			JWTHelper.getJWKSetFromJSON("{invalid-json}");
		}
		catch(Exception e) {
			catched = true;
		}

		assertTrue(catched);

		catched = false;
		JWKSet res = null;

		try {
			RSAKey rsaKey1 = JWTHelper.createRSAKey(null, KeyUse.SIGNATURE);
			RSAKey rsaKey2 = JWTHelper.createRSAEncKey(null, KeyUse.ENCRYPTION);

			JWKSet jwkSet = new JWKSet(Arrays.asList(rsaKey1, rsaKey2));

			String s = jwkSet.toString();

			res = JWTHelper.getJWKSetFromJSON(s);
		}
		catch(Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertTrue(res.getKeys().size() == 2);
	}

	@Test
	public void test_getJWKSetFromJSON2() {
		boolean catched = false;

		try {
			JWTHelper.getJWKSetFromJSON(new JSONObject());
		}
		catch(Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// Good path is already tested implicitly
	}

	@Test
	public void test_getJWKSetFromJWK() {
		boolean catched = false;

		try {
			JWTHelper.getJWKSetFromJWK("{invalid-json}");
		}
		catch(Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// Good path is already tested implicitly
	}

	@Test
	public void test_getJWKSetFromJWT() {
		boolean catched = false;

		try {
			JWTHelper.getJWKSetFromJWT("{invalid-json}");
		}
		catch(Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// Good path is already tested implicitly
	}

	@Test
	public void test_getMetadataJWKSet() {
		boolean catched = false;

		try {
			JWTHelper.getMetadataJWKSet(new JSONObject());
		}
		catch(Exception e) {
			catched = true;
		}

		assertTrue(catched);

		catched = false;

		try {
			JSONObject metadata = new JSONObject().put("jwks", "ko");

			JWTHelper.getMetadataJWKSet(metadata);
		}
		catch(Exception e) {
			catched = true;
		}

		assertTrue(catched);

		catched = false;

		try {
			JSONObject metadata = new JSONObject().put("jwks_uri", "ko");

			JWTHelper.getMetadataJWKSet(metadata);
		}
		catch(Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// Good path is already tested implicitly
	}

	@Test
	public void test_parseRSAKey() {
		boolean catched = false;

		try {
			JWTHelper.parseRSAKey("{invalid-json}");
		}
		catch(Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// Good path is already tested implicitly
	}

	@Test
	public void test_createJWS() {
		JSONObject payload = new JSONObject().put("test", "test");

		boolean catched = false;
		JWTHelper helper = null;

		try {
			RelyingPartyOptions options = getOptions();

			helper = new JWTHelper(options);
		}
		catch(Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(helper);

		catched = false;
		String res = null;

		try {
			ECKey ecKey = createECKey(KeyUse.ENCRYPTION);

			JWKSet jwkSet = new JWKSet(Arrays.asList(ecKey));

			res = helper.createJWS(payload, jwkSet);
		}
		catch(Exception e) {
			catched = true;
		}

		assertTrue(catched); // Default signer make fail

		// Good path is already tested implicitly
	}

	@Test
	public void test_decryptJWE() {
		boolean catched = false;
		JWTHelper helper = null;

		try {
			RelyingPartyOptions options = getOptions();

			helper = new JWTHelper(options);
		}
		catch(Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(helper);

		catched = false;

		try {
			helper.decryptJWE("invalid-jwe", null);
		}
		catch(Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void test_verifyJWS() {
		boolean catched = false;
		RelyingPartyOptions options = null;
		JWTHelper helper = null;

		try {
			options = getOptions();

			helper = new JWTHelper(options);
		}
		catch(Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(helper);
		assertNotNull(options);

		catched = false;

		try {
			JWKSet jwkSet = createJWKSet();

			JSONObject jwks = new JSONObject(jwkSet.toJSONObject(false));
			JSONObject payload = new JSONObject().put("sub", "sub");

			String jws = createJWS(payload, jwks);

			helper.verifyJWS(jws, new JWKSet());
		}
		catch(Exception e) {
			catched = true;
		}

		assertTrue(catched);

		catched = false;

		try {
			helper.verifyJWS("invalid-jws", new JWKSet());
		}
		catch(Exception e) {
			catched = true;
		}

		assertTrue(catched);

		catched = false;

		try {
			JWKSet jwkSet = createJWKSet();

			JSONObject jwks = new JSONObject(jwkSet.toJSONObject(false));
			JSONObject payload = new JSONObject().put("sub", "sub");

			String jws = createJWS(payload, jwks);

			options.setAllowedSigningAlgs("RS512", "ES512");

			helper.verifyJWS(jws, jwkSet);
		}
		catch(Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	private String encode64(String value) {
		return java.util.Base64.getEncoder().encodeToString(value.getBytes());
	}

	private static JWKSet createJWKSet() throws Exception {
		RSAKey rsaKey1 = JWTHelper.createRSAKey(JWSAlgorithm.RS256, KeyUse.SIGNATURE);
		RSAKey rsaKey2 = JWTHelper.createRSAEncKey(JWEAlgorithm.RSA_OAEP_256, KeyUse.ENCRYPTION);

		return new JWKSet(Arrays.asList(rsaKey1, rsaKey2));
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

	private static ECKey createECKey(KeyUse use) throws Exception {
		return new ECKeyGenerator(Curve.P_256)
			.keyUse(use)
			.keyIDFromThumbprint(true)
			.generate();
	}

	private static OctetSequenceKey createOSKey(KeyUse use) throws Exception {
		return new OctetSequenceKeyGenerator(256)
			.algorithm(JWSAlgorithm.HS256)
			.keyUse(use)
			.keyIDFromThumbprint(true)
			.generate();
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
			.setJWKFed(TestUtils.getContent("rp-jwks.json"))
			.setTrustMarks(TestUtils.getContent("rp-trust-marks.json"));

		return options;
	}


}
