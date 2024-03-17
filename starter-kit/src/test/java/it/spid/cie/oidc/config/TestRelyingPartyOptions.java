package it.spid.cie.oidc.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.json.JSONObject;
import org.junit.Test;

import it.spid.cie.oidc.schemas.AcrValue;
import it.spid.cie.oidc.schemas.CIEClaimItem;
import it.spid.cie.oidc.schemas.ClaimSection;
import it.spid.cie.oidc.schemas.OIDCProfile;
import it.spid.cie.oidc.schemas.SPIDClaimItem;
import it.spid.cie.oidc.util.ArrayUtil;

public class TestRelyingPartyOptions {

	@Test
	public void testClass1() {
		RelyingPartyOptions res = new RelyingPartyOptions();

		res.getApplicationType();

		// ApplicationName

		String appName = res.getApplicationName();

		res.setApplicationName("");

		assertEquals(appName, res.getApplicationName());

		res.setApplicationName("test");

		assertEquals("test", res.getApplicationName());

		// ClientId

		String clientId = res.getClientId();

		res.setClientId("");

		assertEquals(clientId, res.getClientId());

		res.setClientId("test");

		assertEquals("test", res.getClientId());

		// Contacts

		res.setContacts(null);

		assertTrue(res.getContacts().size() == 0);

		Set<String> contacts = new HashSet<>();

		res.setContacts(contacts);

		assertTrue(res.getContacts().size() == 0);

		contacts.add("test@test.com");

		res.setContacts(contacts);

		assertTrue(res.getContacts().size() == 1);

		// DefaultTrustAnchor

		String defaultTA = res.getDefaultTrustAnchor();

		res.setDefaultTrustAnchor("");

		assertEquals(defaultTA, res.getDefaultTrustAnchor());

		res.setDefaultTrustAnchor("test");

		assertEquals("test", res.getDefaultTrustAnchor());

		// Jwk

		String jwk = res.getJwkFed();

		res.setJWKFed("");

		assertEquals(jwk, res.getJwkFed());

		res.setJWKFed("test");

		assertEquals("test", res.getJwkFed());

		// Login

		String login = res.getLoginURL();

		res.setLoginURL("");

		assertEquals(login, res.getLoginURL());

		res.setLoginURL("test");

		assertEquals("test", res.getLoginURL());

		// LoginRedirect

		String loginRedirect = res.getLoginRedirectURL();

		res.setLoginRedirectURL("");

		assertEquals(loginRedirect, res.getLoginRedirectURL());

		res.setLoginRedirectURL("test");

		assertEquals("test", res.getLoginRedirectURL());

		// LogoutRedirect

		String logoutRedirect = res.getLogoutRedirectURL();

		res.setLogoutRedirectURL("");

		assertEquals(logoutRedirect, res.getLogoutRedirectURL());

		res.setLogoutRedirectURL("test");

		assertEquals("test", res.getLogoutRedirectURL());

		// AcrValue

		res.setProfileAcr(null, "l4");

		// AcrValue SPID

		String spidAcrValue = res.getAcrValue(OIDCProfile.SPID);

		res.setProfileAcr(OIDCProfile.SPID, null);

		assertEquals(spidAcrValue, res.getAcrValue(OIDCProfile.SPID));

		res.setProfileAcr(OIDCProfile.SPID, "l4");

		assertEquals(spidAcrValue, res.getAcrValue(OIDCProfile.SPID));

		res.setProfileAcr(OIDCProfile.SPID, "l1");

		assertEquals(AcrValue.L1.value(), res.getAcrValue(OIDCProfile.SPID));

		// AcrValue CIE

		String cieAcrValue = res.getAcrValue(OIDCProfile.CIE);

		res.setProfileAcr(OIDCProfile.CIE, null);

		assertEquals(cieAcrValue, res.getAcrValue(OIDCProfile.CIE));

		res.setProfileAcr(OIDCProfile.CIE, "l4");

		assertEquals(cieAcrValue, res.getAcrValue(OIDCProfile.CIE));

		res.setProfileAcr(OIDCProfile.CIE, "l1");

		assertEquals(AcrValue.L1.value(), res.getAcrValue(OIDCProfile.CIE));

		// RedirectUris

		res.setRedirectUris(null);

		assertTrue(res.getRedirectUris().size() == 0);

		Set<String> redirectUris = new HashSet<>();

		res.setRedirectUris(redirectUris);

		assertTrue(res.getRedirectUris().size() == 0);

		redirectUris.add("url1");

		res.setRedirectUris(redirectUris);

		assertTrue(res.getRedirectUris().size() == 1);

		// Scopes

		res.setScopes(null, null);

		// Scopes SPID

		Set<String> spidScopes = res.getScopes(OIDCProfile.SPID);

		res.setScopes(OIDCProfile.SPID, null);

		assertEquals(spidScopes, res.getScopes(OIDCProfile.SPID));

		Set<String> spidScopesNew = new HashSet<>();

		res.setScopes(OIDCProfile.SPID, spidScopesNew);

		assertEquals(spidScopes, res.getScopes(OIDCProfile.SPID));

		spidScopesNew.add("test");

		res.setScopes(OIDCProfile.SPID, spidScopesNew);

		assertTrue(res.getScopes(OIDCProfile.SPID).size() == 1);

		// Scopes CIE

		Set<String> cieScopes = res.getScopes(OIDCProfile.CIE);

		res.setScopes(OIDCProfile.CIE, null);

		assertEquals(cieScopes, res.getScopes(OIDCProfile.CIE));

		Set<String> cieScopesNew = new HashSet<>();

		res.setScopes(OIDCProfile.CIE, cieScopesNew);

		assertEquals(cieScopes, res.getScopes(OIDCProfile.CIE));

		cieScopesNew.add("test");

		res.setScopes(OIDCProfile.CIE, cieScopesNew);

		assertTrue(res.getScopes(OIDCProfile.CIE).size() == 1);

		// Trust Anchors

		res.setTrustAnchors(null);

		assertTrue(res.getTrustAnchors().size() == 0);

		Set<String> trustAnchors = new HashSet<>();

		res.setTrustAnchors(trustAnchors);

		assertTrue(res.getTrustAnchors().size() == 0);

		trustAnchors.add("test");

		res.setTrustAnchors(trustAnchors);

		assertTrue(res.getTrustAnchors().size() == 1);

		// TrustMarks

		String trustMarks = res.getTrustMarks();

		res.setTrustMarks("");

		assertEquals(trustMarks, res.getTrustMarks());

		res.setTrustMarks("test");

		assertEquals("test", res.getTrustMarks());

		// UserKeyClaim

		String userkeyClaim = res.getUserKeyClaim();

		res.setUserKeyClaim("");

		assertEquals(userkeyClaim, res.getUserKeyClaim());

		res.setUserKeyClaim("test");

		assertEquals("test", res.getUserKeyClaim());

		// SPID providers

		res.setSPIDProviders(null);

		assertTrue(res.getSPIDProviders().size() == 0);

		Map<String, String> spidProviders = new HashMap<>();

		res.setSPIDProviders(spidProviders);

		assertTrue(res.getSPIDProviders().size() == 0);

		spidProviders.put("one", "test");
		spidProviders.put("two", null);

		res.setSPIDProviders(spidProviders);

		assertTrue(res.getSPIDProviders().size() == 2);

		// CIE providers

		res.setCIEProviders(null);

		assertTrue(res.getCIEProviders().size() == 0);

		Map<String, String> cieProviders = new HashMap<>();

		res.setCIEProviders(cieProviders);

		assertTrue(res.getCIEProviders().size() == 0);

		cieProviders.put("one", "test");
		cieProviders.put("two", null);

		res.setCIEProviders(cieProviders);

		assertTrue(res.getCIEProviders().size() == 2);

		// Providers

		assertTrue(res.getProviders(OIDCProfile.SPID).size() == 2);
		assertTrue(res.getProviders(OIDCProfile.CIE).size() == 2);
		assertTrue(res.getProviders(null).size() == 0);

		//signing and encryption algorithms
		res.setTokenEndpointAuthMethod("test");

		assertEquals("test", res.getTokenEndpointAuthMethod());

		res.setUserinfoEncryptedResponseEnc("test");

		assertEquals("test", res.getTokenEndpointAuthMethod());

		res.setUserinfoSignedResponseAlg("test");

		assertEquals("test", res.getUserinfoSignedResponseAlg());

		res.setUserinfoEncryptedResponseAlg("test");

		assertEquals("test", res.getUserinfoEncryptedResponseAlg());

		res.setIdTokenSignedResponseAlg("test");

		assertEquals("test", res.getIdTokenSignedResponseAlg());

		//federation_entity metadata
		res.setFederationResolveEndpoint("test");

		assertEquals("test", res.getFederationResolveEndpoint());

		res.setOrganizationName("test");

		assertEquals("test", res.getOrganizationName());

		res.setPolicyUri("test");

		assertEquals("test", res.getPolicyUri());

		res.setHomepageUri("test");

		assertEquals("test", res.getHomepageUri());

		res.setLogoUri("test");

		assertEquals("test", res.getLogoUri());

		// Federation Contacts

		res.setFederationContacts(null);

		assertTrue(res.getFederationContacts().size() == 0);

		Set<String> federationContacts = new HashSet<>();

		res.setFederationContacts(federationContacts);

		assertTrue(res.getFederationContacts().size() == 0);

		federationContacts.add("test@test.com");

		res.setFederationContacts(federationContacts);

		assertTrue(res.getFederationContacts().size() == 1);
	}

	@Test
	public void testClass2a() {
		boolean catched = false;
		RelyingPartyOptions res = new RelyingPartyOptions();

		try {
			res.addRequestedClaim(null, null, SPIDClaimItem.NAME, null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testClass2b() {
		boolean catched = false;
		RelyingPartyOptions res = new RelyingPartyOptions();

		try {
			res.addRequestedClaim(OIDCProfile.SPID, null, SPIDClaimItem.NAME, null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testClass2c() {
		boolean catched = false;
		RelyingPartyOptions res = new RelyingPartyOptions();

		try {
			res.addRequestedClaim(OIDCProfile.CIE, null, SPIDClaimItem.NAME, null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testClass3() {
		RelyingPartyOptions res = new RelyingPartyOptions();

		boolean catched = false;
		try {
			res.addRequestedClaim(
				OIDCProfile.SPID, ClaimSection.ID_TOKEN, SPIDClaimItem.NAME, null);
			res.addRequestedClaim(
				OIDCProfile.SPID, ClaimSection.ID_TOKEN, SPIDClaimItem.FAMILY_NAME, null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);

		JSONObject json = res.getRequestedClaimsAsJSON(OIDCProfile.SPID);

		assertFalse(json.isEmpty());

		json = res.getRequestedClaimsAsJSON(OIDCProfile.CIE);

		assertTrue(json.isEmpty());

		catched = false;

		try {
			res.addRequestedClaim(
				OIDCProfile.CIE, ClaimSection.ID_TOKEN, CIEClaimItem.FAMILY_NAME, null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);

		json = res.getRequestedClaimsAsJSON(OIDCProfile.SPID);

		assertFalse(json.isEmpty());
	}

	@Test
	public void testClass4() {
		RelyingPartyOptions res = new RelyingPartyOptions();

		testValidateKO(res, "01", "no-default-trust-anchor");

		res.setDefaultTrustAnchor("testTA");

		Map<String, String> spidProviders = new HashMap<>();

		spidProviders.put("provider1", "TA_one");
		spidProviders.put("provider2", "TA_two");

		res.setSPIDProviders(spidProviders);

		testValidateKO(res, "02", "invalid-spid-provider");

		res.setTrustAnchors(ArrayUtil.asSet("TA_one", "TA_two"));

		Map<String, String> cieProviders = new HashMap<>();

		cieProviders.put("provider1", "testTA");

		res.setCIEProviders(cieProviders);

		testValidateKO(res, "03", "invalid-cie-provider");

		res.setTrustAnchors(ArrayUtil.asSet("testTA", "TA_one", "TA_two"));

		testValidateKO(res, "04", "no-client-id");

		res.setClientId("testClientId");

		res.setScopes(OIDCProfile.SPID, ArrayUtil.asSet("open_id", "test"));

		testValidateKO(res, "05", "unsupported-spid-scope");

		res.setScopes(OIDCProfile.SPID, new HashSet<>());

		res.setScopes(OIDCProfile.CIE, ArrayUtil.asSet("open_id", "test"));

		testValidateKO(res, "06", "unsupported-cie-scope");

		res.setScopes(OIDCProfile.CIE, new HashSet<>());

		testValidateKO(res, "07", "no-redirect-uris");

		res.setRedirectUris(ArrayUtil.asSet("testRedirect"));

		testValidateOK(res, "08");

		res.setUserKeyClaim("test");

		testValidateKO(res, "09", "invalid-user-key-claim-for-spid");

		try {
			res.addRequestedClaim(
				OIDCProfile.SPID, ClaimSection.ID_TOKEN, SPIDClaimItem.FISCAL_NUMBER, true);
		}
		catch (Exception e) {
			// ignore
		}

		res.setUserKeyClaim("fiscal_number");

		testValidateKO(res, "10", "invalid-user-key-claim-for-cie");
	}

	protected void testValidateKO(
		RelyingPartyOptions options, String message, String prefix) {

		boolean catched = false;
		String errorMsg = "";

		try {
			options.validate();
		}
		catch (Exception e) {
			catched = true;
			errorMsg = e.getMessage();
		}

		//System.out.println("catched:" + catched + " msg:" + errorMsg);

		assertTrue(message, catched);
		assertTrue(message, errorMsg.startsWith(prefix));
	}

	@SuppressWarnings("unused")
	protected void testValidateOK(RelyingPartyOptions options, String message) {
		boolean catched = false;
		String errorMsg = "";

		try {
			options.validate();
		}
		catch (Exception e) {
			catched = true;
			errorMsg = e.getMessage();
		}

		assertFalse(message, catched);
	}

}
