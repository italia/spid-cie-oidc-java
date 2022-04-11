package it.spid.cie.oidc.schema;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.json.JSONObject;
import org.junit.Test;

import it.spid.cie.oidc.schemas.TokenResponse;

public class TestTokenResponse {

	@Test
	public void testClass1a() {
		boolean catched = false;

		try {
			TokenResponse.of(null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testClass1b() {
		boolean catched = false;

		try {
			TokenResponse.of(new JSONObject());
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testClass2() {
		boolean catched = false;

		TokenResponse res = null;

		try {
			TokenResponse.of(new JSONObject().put("test", "test"));
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testClass3a() {
		boolean catched = false;

		TokenResponse res = null;

		try {
			JSONObject token = new JSONObject()
				.put("access_token", "abc123.123abc.a1b2c3")
				.put("token_type", "Bearer")
				.put("id_token", "abc123.123abc.a1b2c3")
				.put("expiresIn", 10);

			res = TokenResponse.of(token);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(res.getAccessToken());
		assertNotNull(res.getIdToken());
		assertNotNull(res.getTokenType());
		assertTrue(res.getExpiresIn() == 0);
	}

	@Test
	public void testClass3b() {
		boolean catched = false;

		TokenResponse res = null;

		try {
			JSONObject token = new JSONObject()
				.put("access_token", "abc123123abc.a1b2c3")
				.put("token_type", "Bearer")
				.put("id_token", "abc123.123abc.a1b2c3")
				.put("expiresIn", 10);

			res = TokenResponse.of(token);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testClass3c() {
		boolean catched = false;

		try {
			JSONObject token = new JSONObject()
				.put("access_token", "abc123.123abc.a1b2c3")
				.put("token_type", "bearer")
				.put("id_token", "abc123.123abc.a1b2c3")
				.put("expiresIn", 10);

			TokenResponse.of(token);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testClass3d() {
		boolean catched = false;

		try {
			JSONObject token = new JSONObject()
				.put("access_token", "abc123.123abc.a1b2c3")
				.put("token_type", "Bearer")
				.put("id_token", "abc123123abc.a1b2c3")
				.put("expiresIn", 10);

			TokenResponse.of(token);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testClass4() {
		boolean catched = false;

		JSONObject json = null;

		try {
			JSONObject token = new JSONObject()
				.put("access_token", "abc123.123abc.a1b2c3")
				.put("token_type", "Bearer")
				.put("id_token", "abc123.123abc.a1b2c3")
				.put("expiresIn", 10);

			TokenResponse res = TokenResponse.of(token);

			json = new JSONObject(res.toString());
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertEquals("abc123.123abc.a1b2c3", json.getString("id_token"));
	}

}
