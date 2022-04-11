package it.spid.cie.oidc.helper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.json.JSONObject;
import org.junit.Test;

import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import it.spid.cie.oidc.config.RelyingPartyOptions;

public class TestJWTHelper {

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

	private String encode64(String value) {
		return java.util.Base64.getEncoder().encodeToString(value.getBytes());
	}

}
