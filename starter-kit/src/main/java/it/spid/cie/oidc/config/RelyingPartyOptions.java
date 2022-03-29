package it.spid.cie.oidc.config;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import it.spid.cie.oidc.exception.ConfigException;
import it.spid.cie.oidc.exception.OIDCException;
import it.spid.cie.oidc.model.OIDCConstants;
import it.spid.cie.oidc.schemas.AcrValuesSpid;
import it.spid.cie.oidc.schemas.OIDCProfile;
import it.spid.cie.oidc.util.ArrayUtil;
import it.spid.cie.oidc.util.Validator;

public class RelyingPartyOptions extends GlobalOptions<RelyingPartyOptions> {

	public static final String[] SUPPORTED_APPLICATION_TYPES = new String[] { "web" };

	public static final String[] SUPPORTED_GRANT_TYPES = new String[] {
		"refresh_token", "authorization_code" };

	public static final String[] SUPPORTED_RESPONSE_TYPES = new String[] { "code" };

	public static final String[] SUPPORTED_SCOPES = new String[] {
		OIDCConstants.SCOPE_OPENID, "offline_access" };

	public String getAcrValue(OIDCProfile profile) {
		return acrMap.get(profile.getValue());
	}

	public String getDefaultTrustAnchor() {
		return defaultTrustAnchor;
	}

	public Set<String> getTrustAnchors() {
		return Collections.unmodifiableSet(trustAnchors);
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

	public Set<String> getScopes() {
		return Collections.unmodifiableSet(scopes);
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

	public RelyingPartyOptions setProfileAcr(OIDCProfile profile, String acr) {
		if (acr != null) {
			if (OIDCProfile.SPID.equals(profile)) {
				AcrValuesSpid value = AcrValuesSpid.parse(acr);

				if (value != null) {
					this.acrMap.put(profile.getValue(), acr);
				}
			}
			else if (OIDCProfile.CIE.equals(profile)) {
				//TODO: validate
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

	public RelyingPartyOptions setScopes(Collection<String> scopes) {
		if (scopes != null && !scopes.isEmpty()) {
			this.scopes.clear();
			this.scopes.addAll(scopes);
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

		if (scopes.isEmpty()) {
			throw new ConfigException("no-scopes");
		}
		else {
			for (String scope : scopes) {
				if (!ArrayUtil.contains(SUPPORTED_SCOPES, scope)) {
					throw new ConfigException("unsupported-scope %s", scope);
				}
			}
		}

		if (redirectUris.isEmpty()) {
			throw new ConfigException("no-redirect-uris");
		}

		if (!acrMap.containsKey(OIDCProfile.SPID.getValue())) {
			acrMap.put(OIDCProfile.SPID.getValue(), AcrValuesSpid.L2.getValue());
		}
		if (!acrMap.containsKey(OIDCProfile.CIE.getValue())) {
			// TODO: acrMap.put(OIDCProfile.SPID.getValue(), AcrValuesSpid.L2.getValue());
		}

	}

	private String defaultTrustAnchor;
	private Set<String> trustAnchors = new HashSet<>();
	private Map<String, String> spidProviders = new HashMap<>();
	private Map<String, String> cieProviders = new HashMap<>();

	private String applicationName;
	private String applicationType = "web";
	private Set<String> contacts = new HashSet<>();
	private Set<String> scopes = ArrayUtil.asSet(SUPPORTED_SCOPES);
	private String clientId;
	private Set<String> redirectUris = new HashSet<>();
	private String jwk;
	private String trustMarks;

	private String loginURL = "/oidc/rp/landing";
	private String loginRedirectURL = "/oidc/rp/echo_attributes";
	private String logoutRedirectURL = "/oidc/rp/landing";

	private Map<String, String> acrMap = new HashMap<>();

}
