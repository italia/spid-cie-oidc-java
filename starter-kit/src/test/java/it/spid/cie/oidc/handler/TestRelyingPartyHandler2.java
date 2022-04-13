package it.spid.cie.oidc.handler;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONObject;
import org.junit.Test;

import it.spid.cie.oidc.config.RelyingPartyOptions;
import it.spid.cie.oidc.handler.extras.MemoryStorage;
import it.spid.cie.oidc.schemas.CIEClaimItem;
import it.spid.cie.oidc.schemas.SPIDClaimItem;
import it.spid.cie.oidc.test.util.TestUtils;
import it.spid.cie.oidc.util.ArrayUtil;

public class TestRelyingPartyHandler2 {

	private static String TRUST_ANCHOR = "http://127.0.0.1:18000/";
	private static String SPID_PROVIDER = "http://127.0.0.1:18000/oidc/op/";
	private static String RELYING_PARTY = "http://127.0.0.1:18080/oidc/rp/";

	@Test
	public void TestGetUserKeyFromUserInfo1() {
		boolean catched = false;

		RelyingPartyOptions options = null;
		RelyingPartyHandler handler = null;
		Method privateMethod = null;

		try {
			options = getOptions();

			handler = new RelyingPartyHandler(
				options, new MemoryStorage());

			privateMethod = RelyingPartyHandler.class.getDeclaredMethod(
				"getUserKeyFromUserInfo", JSONObject.class);

			privateMethod.setAccessible(true);
		}
		catch (Exception e) {
			System.err.println(e);
			catched = true;
		}

		assertFalse(catched);

		String returnValue = "";
		catched = false;

		try {
			options.setUserKeyClaim(SPIDClaimItem.FISCAL_NUMBER.getName());

			JSONObject userInfo = new JSONObject()
				.put(SPIDClaimItem.FISCAL_NUMBER.getAlias(), "test");

			returnValue = (String) privateMethod.invoke(handler, userInfo);
		}
		catch (Exception e) {
			System.err.println(e);
			catched = true;
		}

		assertFalse(catched);
		assertEquals("test", returnValue);

		catched = false;

		try {
			options.setUserKeyClaim(SPIDClaimItem.FISCAL_NUMBER.getAlias());

			JSONObject userInfo = new JSONObject()
				.put(SPIDClaimItem.FISCAL_NUMBER.getName(), "test");

			returnValue = (String) privateMethod.invoke(handler, userInfo);
		}
		catch (Exception e) {
			System.err.println(e);
			catched = true;
		}

		assertFalse(catched);
		assertEquals("test", returnValue);

		catched = false;

		try {
			CIEClaimItem.registerItem("test_uk_name", "test_uk_alias");

			options.setUserKeyClaim("test_uk_name");

			JSONObject userInfo = new JSONObject()
				.put("test_uk_alias", "test");

			returnValue = (String) privateMethod.invoke(handler, userInfo);
		}
		catch (Exception e) {
			System.err.println(e);
			catched = true;
		}

		assertFalse(catched);
		assertEquals("test", returnValue);

		catched = false;

		try {
			options.setUserKeyClaim("test_uk_alias");

			JSONObject userInfo = new JSONObject()
				.put("test_uk_name", "test");

			returnValue = (String) privateMethod.invoke(handler, userInfo);
		}
		catch (Exception e) {
			System.err.println(e);
			catched = true;
		}

		assertFalse(catched);
		assertEquals("test", returnValue);

		catched = false;

		try {
			options.setUserKeyClaim("test");

			JSONObject userInfo = new JSONObject()
				.put("test_alias", "test");

			returnValue = (String) privateMethod.invoke(handler, userInfo);
		}
		catch (Exception e) {
			System.err.println(e);
			catched = true;
		}

		assertFalse(catched);
		assertNull(returnValue);
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


}
