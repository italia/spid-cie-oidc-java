package it.spid.cie.oidc.config;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.json.JSONObject;

import it.spid.cie.oidc.exception.ConfigException;
import it.spid.cie.oidc.exception.OIDCException;
import it.spid.cie.oidc.schemas.AcrValue;
import it.spid.cie.oidc.schemas.CIEClaimItem;
import it.spid.cie.oidc.schemas.ClaimItem;
import it.spid.cie.oidc.schemas.ClaimSection;
import it.spid.cie.oidc.schemas.GrantType;
import it.spid.cie.oidc.schemas.OIDCProfile;
import it.spid.cie.oidc.schemas.SPIDClaimItem;
import it.spid.cie.oidc.schemas.Scope;
import it.spid.cie.oidc.util.ArrayUtil;
import it.spid.cie.oidc.util.Validator;

public class RelyingPartyOptions extends GlobalOptions<RelyingPartyOptions> {

	public static final String[] SUPPORTED_APPLICATION_TYPES = new String[] { "web" };

	public static final String[] SUPPORTED_GRANT_TYPES = new String[] {
		GrantType.REFRESH_TOKEN.value(),
		GrantType.AUTHORIZATION_CODE.value()
	};

	public static final String[] SUPPORTED_RESPONSE_TYPES = new String[] { "code" };

	public static final String[] SUPPORTED_SCOPES_SPID = new String[] {
		Scope.OPEN_ID.value(), Scope.OFFLINE_ACCESS.value()
	};

	public static final String[] SUPPORTED_SCOPES_CIE = new String[] {
		Scope.OPEN_ID.value(), Scope.OFFLINE_ACCESS.value(),
		Scope.PROFILE.value(), Scope.EMAIL.value()
	};

	private String defaultTrustAnchor;
	private Set<String> trustAnchors = new HashSet<>();
	private Map<String, String> spidProviders = new HashMap<>();
	private Map<String, String> cieProviders = new HashMap<>();

	private String applicationName;
	private String applicationType = "web";
	private Set<String> contacts = new HashSet<>();
	private String clientId;
	private Set<String> redirectUris = new HashSet<>();
	private String jwk;
	private String trustMarks;

	private String loginURL = "/oidc/rp/landing";
	private String loginRedirectURL = "/oidc/rp/echo_attributes";
	private String logoutRedirectURL = "/oidc/rp/landing";

	private String userKeyClaim;

	private Map<String, String> acrMap = new HashMap<>();
	private Map<String, Set<String>> scopeMap = new HashMap<>();
	private Map<String, ClaimOptions> requestedClaimsMap = new HashMap<>();

	public RelyingPartyOptions addRequestedClaim(
			OIDCProfile profile, ClaimSection section, ClaimItem claimItem,
			Boolean essential)
		throws OIDCException {

		return addRequestedClaim(profile, section, claimItem.getName(), essential);
	}

	public RelyingPartyOptions addRequestedClaim(
			OIDCProfile profile, ClaimSection section, String name, Boolean essential)
		throws OIDCException {

		if (profile == null || section == null ) {
			throw new ConfigException("null profile or section");
		}

		ClaimOptions claims = requestedClaimsMap.get(profile.value());

		if (claims == null) {
			claims = new ClaimOptions();

			requestedClaimsMap.put(profile.value(), claims);
		}

		if (OIDCProfile.SPID.equals(profile)) {
			claims.addSectionItem(section, SPIDClaimItem.get(name), essential);
		}
		else if (OIDCProfile.CIE.equals(profile)) {
			claims.addSectionItem(section, CIEClaimItem.get(name), essential);
		}
		else {
			throw new ConfigException("unknown profile %s", profile.value());
		}

		return this;
	}

	public String getAcrValue(OIDCProfile profile) {
		return acrMap.get(profile.value());
	}

	public String getDefaultTrustAnchor() {
		return defaultTrustAnchor;
	}

	public Set<String> getTrustAnchors() {
		return Collections.unmodifiableSet(trustAnchors);
	}

	public Map<String, String> getProviders(OIDCProfile profile) {
		if (OIDCProfile.SPID.equals(profile)) {
			return getSPIDProviders();
		}
		else if (OIDCProfile.CIE.equals(profile)) {
			return getCIEProviders();
		}
		else {
			return Collections.emptyMap();
		}
	}

	public Map<String, String> getSPIDProviders() {
		return Collections.unmodifiableMap(spidProviders);
	}

	public Map<String, String> getCIEProviders() {
		return Collections.unmodifiableMap(cieProviders);
	}

	public String getApplicationName() {
		return applicationName;
	}

	public String getApplicationType() {
		return applicationType;
	}

	public Set<String> getContacts() {
		return Collections.unmodifiableSet(contacts);
	}

	public Set<String> getScopes(OIDCProfile profile) {
		Set<String> result = scopeMap.get(profile.value());

		if (result != null) {
			return Collections.unmodifiableSet(result);
		}

		return Collections.emptySet();
	}

	public String getClientId() {
		return clientId;
	}

	public Set<String> getRedirectUris() {
		return Collections.unmodifiableSet(redirectUris);
	}

	public String getJwk() {
		return jwk;
	}

	public String getTrustMarks() {
		return trustMarks;
	}

	public String getLoginURL() {
		return loginURL;
	}

	public String getUserKeyClaim() {
		return userKeyClaim;
	}

	public String getLoginRedirectURL() {
		return loginRedirectURL;
	}

	public String getLogoutRedirectURL() {
		return logoutRedirectURL;
	}

	public ClaimOptions getRequestedClaims(OIDCProfile profile) {
		return requestedClaimsMap.get(profile.value());
	}

	public JSONObject getRequestedClaimsAsJSON(OIDCProfile profile) {
		ClaimOptions claims = getRequestedClaims(profile);

		if (claims != null) {
			return claims.toJSON();
		}

		return new JSONObject();
	}

	public RelyingPartyOptions setProfileAcr(OIDCProfile profile, String acr) {
		if (acr != null) {
			if (OIDCProfile.SPID.equals(profile)) {
				AcrValue acrValue = AcrValue.parse(acr);

				if (acrValue != null) {
					this.acrMap.put(profile.value(), acrValue.value());
				}
			}
			else if (OIDCProfile.CIE.equals(profile)) {
				AcrValue acrValue = AcrValue.parse(acr);

				if (acrValue != null) {
					this.acrMap.put(profile.value(), acrValue.value());
				}
			}
		}

		return this;
	}

	public RelyingPartyOptions setApplicationName(String applicationName) {
		if (!Validator.isNullOrEmpty(applicationName)) {
			this.applicationName = applicationName;
		}

		return this;
	}

	public RelyingPartyOptions setClientId(String clientId) {
		if (!Validator.isNullOrEmpty(clientId)) {
			this.clientId = clientId;
		}

		return this;
	}

	public RelyingPartyOptions setContacts(Collection<String> contacts) {
		if (contacts != null && !contacts.isEmpty()) {
			this.contacts.clear();
			this.contacts.addAll(contacts);
		}

		return this;
	}

	public RelyingPartyOptions setDefaultTrustAnchor(String defaultTrustAnchor) {
		if (!Validator.isNullOrEmpty(defaultTrustAnchor)) {
			this.defaultTrustAnchor = defaultTrustAnchor;
		}

		return this;
	}

	public RelyingPartyOptions setJWK(String jwk) {
		if (!Validator.isNullOrEmpty(jwk)) {
			this.jwk = jwk;
		}

		return this;
	}

	public RelyingPartyOptions setRedirectUris(Collection<String> redirectUris) {
		if (redirectUris != null && !redirectUris.isEmpty()) {
			this.redirectUris.clear();
			this.redirectUris.addAll(redirectUris);
		}

		return this;
	}

	public RelyingPartyOptions setScopes(OIDCProfile profile, Collection<String> scopes) {
		if (scopes != null) {
			this.scopeMap.put(profile.value(), new HashSet<>(scopes));
		}

		return this;
	}

	public RelyingPartyOptions setTrustAnchors(Collection<String> trustAnchors) {
		if (trustAnchors != null && !trustAnchors.isEmpty()) {
			this.trustAnchors.clear();
			this.trustAnchors.addAll(trustAnchors);
		}

		return this;
	}

	public RelyingPartyOptions setTrustMarks(String trustMarks) {
		if (!Validator.isNullOrEmpty(trustMarks)) {
			this.trustMarks = trustMarks;
		}

		return this;
	}

	public RelyingPartyOptions setSPIDProviders(Map<String, String> providers) {
		if (providers != null && !providers.isEmpty()) {
			this.spidProviders.clear();

			for (Map.Entry<String, String> entry : providers.entrySet()) {
				if (Validator.isNullOrEmpty(entry.getValue())) {
					this.spidProviders.put(entry.getKey(), defaultTrustAnchor);
				}
				else {
					this.spidProviders.put(entry.getKey(), entry.getValue());
				}
			}
		}

		return this;
	}

	public RelyingPartyOptions setCIEProviders(Map<String, String> providers) {
		if (providers != null && !providers.isEmpty()) {
			this.cieProviders.clear();

			for (Map.Entry<String, String> entry : providers.entrySet()) {
				if (Validator.isNullOrEmpty(entry.getValue())) {
					this.cieProviders.put(entry.getKey(), defaultTrustAnchor);
				}
				else {
					this.cieProviders.put(entry.getKey(), entry.getValue());
				}
			}
		}

		return this;
	}

	public RelyingPartyOptions setLoginURL(String loginURL) {
		if (!Validator.isNullOrEmpty(loginURL)) {
			this.loginURL = loginURL;
		}

		return this;
	}

	public RelyingPartyOptions setLoginRedirectURL(String loginRedirectURL) {
		if (!Validator.isNullOrEmpty(loginRedirectURL)) {
			this.loginRedirectURL = loginRedirectURL;
		}

		return this;
	}

	public RelyingPartyOptions setLogoutRedirectURL(String logoutRedirectURL) {
		if (!Validator.isNullOrEmpty(logoutRedirectURL)) {
			this.logoutRedirectURL = logoutRedirectURL;
		}

		return this;
	}

	public RelyingPartyOptions setUserKeyClaim(String userKeyClaim) {
		if (!Validator.isNullOrEmpty(userKeyClaim)) {
			this.userKeyClaim = userKeyClaim;
		}

		return this;
	}

	public void validate() throws OIDCException {
		super.validate();

		if (Validator.isNullOrEmpty(defaultTrustAnchor)) {
			throw new ConfigException("no-default-trust-anchor");
		}

		for (Map.Entry<String, String> entry : spidProviders.entrySet()) {
			if (Validator.isNullOrEmpty(entry.getKey()) ||
				!trustAnchors.contains(entry.getValue())) {

				throw new ConfigException(
					"invalid-spid-provider %s:%s", entry.getKey(), entry.getValue());
			}
		}

		for (Map.Entry<String, String> entry : cieProviders.entrySet()) {
			if (Validator.isNullOrEmpty(entry.getKey()) ||
				!trustAnchors.contains(entry.getValue())) {

				throw new ConfigException(
					"invalid-cie-provider %s:%s", entry.getKey(), entry.getValue());
			}
		}

		if (Validator.isNullOrEmpty(clientId)) {
			throw new ConfigException("no-client-id");
		}

		Set<String> spidScopes = scopeMap.get(OIDCProfile.SPID.value());

		if (spidScopes == null || spidScopes.isEmpty()) {
			scopeMap.put(
				OIDCProfile.SPID.value(), ArrayUtil.asSet(SUPPORTED_SCOPES_SPID));
		}
		else {
			for (String scope : spidScopes) {
				if (!ArrayUtil.contains(SUPPORTED_SCOPES_SPID, scope)) {
					throw new ConfigException("unsupported-spid-scope %s", scope);
				}
			}
		}

		Set<String> cieScopes = scopeMap.get(OIDCProfile.CIE.value());

		if (cieScopes == null || cieScopes.isEmpty()) {
			scopeMap.put(
				OIDCProfile.CIE.value(), ArrayUtil.asSet(SUPPORTED_SCOPES_CIE));
		}
		else {
			for (String scope : cieScopes) {
				if (!ArrayUtil.contains(SUPPORTED_SCOPES_CIE, scope)) {
					throw new ConfigException("unsupported-cie-scope %s", scope);
				}
			}
		}

		if (redirectUris.isEmpty()) {
			throw new ConfigException("no-redirect-uris");
		}

		if (!acrMap.containsKey(OIDCProfile.SPID.value())) {
			acrMap.put(OIDCProfile.SPID.value(), AcrValue.L2.value());
		}
		if (!acrMap.containsKey(OIDCProfile.CIE.value())) {
			acrMap.put(OIDCProfile.CIE.value(), AcrValue.L2.value());
		}

		if (Validator.isNullOrEmpty(logoutRedirectURL)) {
			throw new ConfigException("no-logout-redirect-url");
		}

		validateRequestedClaims();
		validateUserKeyClaim();
	}

	protected void validateRequestedClaims() throws OIDCException {
		ClaimOptions spidClaims = getRequestedClaims(OIDCProfile.SPID);

		if (spidClaims == null || spidClaims.isEmpty()) {
			addRequestedClaim(
				OIDCProfile.SPID, ClaimSection.ID_TOKEN, SPIDClaimItem.FAMILY_NAME, true);
			addRequestedClaim(
				OIDCProfile.SPID, ClaimSection.ID_TOKEN, SPIDClaimItem.EMAIL, true);
			addRequestedClaim(
				OIDCProfile.SPID, ClaimSection.USER_INFO, SPIDClaimItem.NAME, null);
			addRequestedClaim(
				OIDCProfile.SPID, ClaimSection.USER_INFO, SPIDClaimItem.FAMILY_NAME,
				null);
			addRequestedClaim(
				OIDCProfile.SPID, ClaimSection.USER_INFO, SPIDClaimItem.EMAIL, null);
			addRequestedClaim(
				OIDCProfile.SPID, ClaimSection.USER_INFO, SPIDClaimItem.FISCAL_NUMBER,
				null);
		}

		ClaimOptions cieClaims = getRequestedClaims(OIDCProfile.CIE);

		if (cieClaims == null || cieClaims.isEmpty()) {
			addRequestedClaim(
				OIDCProfile.CIE, ClaimSection.ID_TOKEN, CIEClaimItem.FAMILY_NAME, true);
			addRequestedClaim(
				OIDCProfile.CIE, ClaimSection.ID_TOKEN, CIEClaimItem.EMAIL, true);
			addRequestedClaim(
				OIDCProfile.CIE, ClaimSection.USER_INFO, CIEClaimItem.GIVEN_NAME, null);
			addRequestedClaim(
				OIDCProfile.CIE, ClaimSection.USER_INFO, CIEClaimItem.FAMILY_NAME, null);
			addRequestedClaim(
				OIDCProfile.CIE, ClaimSection.USER_INFO, CIEClaimItem.EMAIL, null);
		}
	}

	protected void validateUserKeyClaim() throws OIDCException {
		if (Validator.isNullOrEmpty(userKeyClaim)) {
			this.userKeyClaim = "email";
		}

		ClaimOptions claims = getRequestedClaims(OIDCProfile.SPID);

		if (!claims.hasEssentialItem(userKeyClaim)) {
			throw new ConfigException(
				"invalid-user-key-claim-for-spid: %s", userKeyClaim);
		}

		claims = getRequestedClaims(OIDCProfile.CIE);

		if (!claims.hasEssentialItem(userKeyClaim)) {
			throw new ConfigException(
				"invalid-user-key-claim-for-cie: %s", userKeyClaim);
		}
	}

}
