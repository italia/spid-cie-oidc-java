package it.spid.cie.oidc.handler;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Method;

import it.spid.cie.oidc.exception.OIDCException;
import org.json.JSONObject;
import org.junit.Test;

import it.spid.cie.oidc.config.RelyingPartyOptions;
import it.spid.cie.oidc.handler.extras.MemoryStorage;
import it.spid.cie.oidc.model.AuthnRequest;
import it.spid.cie.oidc.model.AuthnToken;
import it.spid.cie.oidc.model.FederationEntity;
import it.spid.cie.oidc.schemas.CIEClaimItem;
import it.spid.cie.oidc.schemas.SPIDClaimItem;
import it.spid.cie.oidc.test.util.RPTestUtils;

public class TestRelyingPartyHandler2 {

	@Test
	public void test_getUserKeyFromUserInfo() {
		boolean catched = false;

		RelyingPartyOptions options = null;
		RelyingPartyHandler handler = null;
		Method privateMethod = null;

		try {
			options = RPTestUtils.getOptions();

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

	@Test
	public void test_getUserInfo() {
		RelyingPartyOptions options = null;
		RelyingPartyHandler handler = null;
		MemoryStorage storage = null;

		boolean catched = false;
		try {
			options = RPTestUtils.getOptions();
			storage = new MemoryStorage();
			handler = new RelyingPartyHandler(options, storage);
			handler.getUserInfo("test","test");
		} catch (OIDCException e) {
			catched = true;
		} catch (Exception e) {
			catched = true;
		}
		assertTrue(catched);

		try {
			options = RPTestUtils.getOptions();
			storage = new MemoryStorage();

			handler = new RelyingPartyHandler(options, storage);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// Case

		catched = false;

		try {
			handler.doGetUserInfo(" ", null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// Case

		catched = false;

		try {
			handler.doGetUserInfo("test", "test");
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// Case

		catched = false;

		try {
			AuthnRequest authnRequest = new AuthnRequest();

			authnRequest.setState("test");
			authnRequest.setStorageId("1");
			authnRequest.setClientId("test");

			storage.storeOIDCAuthnRequest(authnRequest);

			handler.doGetUserInfo("test", "test");
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// Case

		catched = false;

		try {
			FederationEntity entity = new FederationEntity();

			entity.setSubject("test");
			entity.setActive(true);

			storage.storeFederationEntity(entity);

			handler.doGetUserInfo("test", "test");
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void test_performLogout() {
		RelyingPartyOptions options = null;
		RelyingPartyHandler handler = null;
		MemoryStorage storage = null;

		boolean catched = false;

		try {
			options = RPTestUtils.getOptions();
			storage = new MemoryStorage();

			handler = new RelyingPartyHandler(options, storage);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);

		// Case

		catched = false;

		try {
			handler.performLogout(" ", null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// Case

		catched = false;
		String res = null;

		try {
			res = handler.performLogout("test", null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertEquals(res, options.getLogoutRedirectURL());

		// Case

		catched = false;

		try {
			AuthnToken authnToken = new AuthnToken();

			authnToken.setUserKey("1111");
			authnToken.setAuthnRequestId("2222");

			storage.storeOIDCAuthnToken(authnToken);

			handler.performLogout("1111", null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);

		// Case

		catched = false;
		res = "";

		try {
			AuthnRequest authnRequest = new AuthnRequest();

			authnRequest.setState("2222");
			authnRequest.setStorageId("2222");
			authnRequest.setClientId("test");
			authnRequest.setProviderConfiguration(new JSONObject().toString());

			storage.storeOIDCAuthnRequest(authnRequest);

			res = handler.performLogout("1111", null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertEquals(res, options.getLogoutRedirectURL());

	}

}
