package it.spid.cie.oidc.spring.boot.relying.party.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import it.spid.cie.oidc.schemas.OIDCProfile;

@Configuration
@ConfigurationProperties(prefix = "oidc")
public class OidcConfig extends BaseConfig {

	public String getDefaultTrustAnchor() {
		return defaultTrustAnchor;
	}

	public List<ProviderInfo> getCieProviders() {
		return cieProviders;
	}

	public List<ProviderInfo> getSpidProviders() {
		return spidProviders;
	}

	public Map<String, String> getIdentityProviders(OIDCProfile profile) {
		Map<String, String> result = new HashMap<>();

		if (OIDCProfile.CIE.equals(profile)) {
			for (ProviderInfo provider : cieProviders) {
				result.put(provider.getSubject(), provider.getTrustAnchor());
			}
		}
		else if (OIDCProfile.SPID.equals(profile)) {
			for (ProviderInfo provider : spidProviders) {
				result.put(provider.getSubject(), provider.getTrustAnchor());
			}
		}

		return result;
	}

	public List<String> getTrustAnchors() {
		return trustAnchors;
	}

	public RelyingParty getRelyingParty() {
		return relyingParty;
	}

	public Hosts getHosts() {
		return hosts;
	}

	public void setDefaultTrustAnchor(String defaultTrustAnchor) {
		this.defaultTrustAnchor = defaultTrustAnchor;
	}

	public void setTrustAnchors(List<String> trustAnchors) {
		this.trustAnchors = trustAnchors;
	}

	public JSONObject toJSON() {
		JSONObject json = new JSONObject();

		json.put("defaultTrustAnchor", defaultTrustAnchor);
		json.put("trustAnchors", trustAnchors);
		json.put("relyingParty", relyingParty.toJSON());
		json.put("spidProviders", new JSONArray(spidProviders));
		json.put("cieProviders", new JSONArray(cieProviders));
		json.put("hosts", hosts.toJSON());

		return json;
	}

	private String defaultTrustAnchor;
	private List<String> trustAnchors = new ArrayList<>();
	private RelyingParty relyingParty = new RelyingParty();
	private Hosts hosts = new Hosts();
	private List<ProviderInfo> spidProviders = new ArrayList<>();
	private List<ProviderInfo> cieProviders = new ArrayList<>();

	public static class Hosts extends BaseConfig {

		public String getTrustAnchor() {
			return trustAnchor;
		}

		public String getCieProvider() {
			return cieProvider;
		}

		public String getRelyingParty() {
			return relyingParty;
		}

		public void setTrustAnchor(String trustAnchor) {
			this.trustAnchor = trustAnchor;
		}

		public void setCieProvider(String cieProvider) {
			this.cieProvider = cieProvider;
		}

		public void setRelyingParty(String relyingParty) {
			this.relyingParty = relyingParty;
		}

		public JSONObject toJSON() {
			return new JSONObject()
				.put("trust-anchor", trustAnchor)
				.put("cie-provider", cieProvider)
				.put("relying-party", relyingParty);
		}

		private String trustAnchor = "127.0.0.1";
		private String cieProvider = "127.0.0.1";
		private String relyingParty = "127.0.0.1";

	}

	public static class ProviderInfo extends BaseConfig {

		public String getSubject() {
			return subject;
		}

		public String getTrustAnchor() {
			return trustAnchor;
		}

		public void setSubject(String subject) {
			this.subject = subject;
		}

		public void setTrustAnchor(String trustAnchor) {
			this.trustAnchor = trustAnchor;
		}

		public JSONObject toJSON() {
			return new JSONObject()
				.put("subject", subject)
				.put("trust-anchor", trustAnchor);
		}

		private String subject;
		private String trustAnchor;

	}

	public static class RelyingParty {

		public String getApplicationName() {
			return applicationName;
		}

		public String getApplicationType() {
			return applicationType;
		}

		public Set<String> getContacts() {
			return Collections.unmodifiableSet(contacts);
		}

		public Set<String> getScope() {
			return Collections.unmodifiableSet(scope);
		}

		public String getClientId() {
			return clientId;
		}

		public String getIdTokenSignedResponseAlg() {
			return idTokenSignedResponseAlg;
		}
		public String getUserinfoSignedResponseAlg() {
			return userinfoSignedResponseAlg;
		}
		public String getUserinfoEncryptedResponseAlg() {
			return userinfoEncryptedResponseAlg;
		}
		public String getUserinfoEncryptedResponseEnc() { return userinfoEncryptedResponseEnc; }

		public String getTokenEndpointAuthMethod() { return tokenEndpointAuthMethod; }

		public String getFederationResolveEndpoint() { return federationResolveEndpoint; }
		public String getOrganizationName() { return organizationName; }
		public String getHomepageUri() { return homepageUri; }
		public String getPolicyUri() { return policyUri; }
		public String getLogoUri() { return logoUri; }
		public Set<String> getFederationContacts() {
			return Collections.unmodifiableSet(federationContacts);
		}

		public Set<String> getRedirectUris() {
			return Collections.unmodifiableSet(redirectUris);
		}

//		public String getJwk() {
//			return jwk;
//		}

		public String getJwkFedFilePath() {
			return jwkFedFilePath;
		}
		public String getJwkCoreFilePath() {
			return jwkCoreFilePath;
		}
//		public String getTrustMarks() {
//			return trustMarks;
//		}

		public String getTrustMarksFilePath() {
			return trustMarksFilePath;
		}

		public void setApplicationName(String applicationName) {
			this.applicationName = applicationName;
		}

		public void setApplicationType(String applicationType) {
			this.applicationType = applicationType;
		}

		public void setClientId(String clientId) {
			this.clientId = clientId;
		}

		public void setIdTokenSignedResponseAlg(String idTokenSignedResponseAlg) {
			this.idTokenSignedResponseAlg = idTokenSignedResponseAlg;
		}
		public void setUserinfoSignedResponseAlg(String userinfoSignedResponseAlg) {
			this.userinfoSignedResponseAlg = userinfoSignedResponseAlg;
		}
		public void setUserinfoEncryptedResponseAlg(String userinfoEncryptedResponseAlg) {
			this.userinfoEncryptedResponseAlg = userinfoEncryptedResponseAlg;
		}
		public void setUserinfoEncryptedResponseEnc(String userinfoEncryptedResponseEnc) {
			this.userinfoEncryptedResponseEnc = userinfoEncryptedResponseEnc;
		}
		public void setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {
			this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
		}

		public void setFederationResolveEndpoint(String federationResolveEndpoint) {
			this.federationResolveEndpoint = federationResolveEndpoint;
		}
		public void setOrganizationName(String organizationName) {
			this.organizationName = organizationName;
		}
		public void setHomepageUri(String homepageUri) {
			this.homepageUri = homepageUri;
		}
		public void setPolicyUri(String policyUri) {
			this.policyUri = policyUri;
		}
		public void setLogoUri(String logoUri) {
			this.logoUri = logoUri;
		}
		public void setFederationContacts(Set<String> federationContacts) {
			this.federationContacts = federationContacts;
		}

//		public void setJwk(String jwk) {
//			this.jwk = jwk;
//		}

		public void setJwkFedFilePath(String jwkFedFilePath) {
			this.jwkFedFilePath = jwkFedFilePath;
		}

		public void setJwkCoreFilePath(String jwkCoreFilePath) {
			this.jwkCoreFilePath = jwkCoreFilePath;
		}
//		public void setTrustMarks(String trustMarks) {
//			this.trustMarks = trustMarks;
//		}

		public void setTrustMarksFilePath(String trustMarksFilePath) {
			this.trustMarksFilePath = trustMarksFilePath;
		}

		public void setContacts(Set<String> contacts) {
			this.contacts = contacts;
		}

		public void setScope(Set<String> scope) {
			this.scope = scope;
		}

		public void setRedirectUris(Set<String> redirectUris) {
			this.redirectUris = redirectUris;
		}

		public JSONObject toJSON() {
			JSONObject json = new JSONObject();

			json.put("applicationName", applicationName);
			json.put("applicationType", applicationType);
			json.put("contacts", contacts);
			json.put("scope", scope);
			json.put("clientId", clientId);
			json.put("redirectUris", redirectUris);
			//json.put("jwk", jwk);
			json.put("jwkFilePath", jwkFedFilePath);
			json.put("jwkCoreFilePath", jwkCoreFilePath);
			//json.put("trustMarks", trustMarks);
			json.put("trustMarksFilePath", trustMarksFilePath);

			return json;
		}

		private String applicationName;
		private String applicationType;
		private Set<String> contacts = new HashSet<>();
		private Set<String> scope = new HashSet<>();
		private String clientId;
		private Set<String> redirectUris = new HashSet<>();
		//private String jwk;
		private String jwkFedFilePath;
		private String jwkCoreFilePath;
		//private String trustMarks;
		private String trustMarksFilePath;

		private String idTokenSignedResponseAlg;
		private String userinfoSignedResponseAlg;
		private String userinfoEncryptedResponseAlg;
		private String userinfoEncryptedResponseEnc;
		private String tokenEndpointAuthMethod;

		private String federationResolveEndpoint;
		private String organizationName;
		private String homepageUri;
		private String policyUri;
		private String logoUri;
		private Set<String> federationContacts = new HashSet<>();

	}

}
