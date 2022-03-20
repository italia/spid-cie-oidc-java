package it.spid.cie.oidc.spring.boot.relying.party.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.json.JSONObject;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "oidcfed")
public class OidcConfig {

	private String defaultTrustAnchor;
	private List<String> trustAnchors = new ArrayList<>();
	private Map<String, String> identityProviders = new HashMap<>();
	private RelyingParty relyingParty = new RelyingParty();

	public String getDefaultTrustAnchor() {
		return defaultTrustAnchor;
	}

	public Map<String, String> getIdentityProviders() {
		return identityProviders;
	}

	public List<String> getTrustAnchors() {
		return trustAnchors;
	}

	public RelyingParty getRelyingParty() {
		return relyingParty;
	}

	public void setDefaultTrustAnchor(String defaultTrustAnchor) {
		this.defaultTrustAnchor = defaultTrustAnchor;
	}

	public void setIdentityProviders(Map<String, String> identityProviders) {
		this.identityProviders = identityProviders;
	}

	public void setTrustAnchors(List<String> trustAnchors) {
		this.trustAnchors = trustAnchors;
	}

	public JSONObject toJSON() {
		JSONObject json = new JSONObject();

		json.put("defaultTrustAnchor", defaultTrustAnchor);
		json.put("trustAnchors", trustAnchors);
		json.put("identityProviders", identityProviders);
		json.put("relyingParty", relyingParty.toJSON());

		return json;
	}

	public String toJSONString() {
		return toJSON().toString();
	}

	public String toJSONString(int indentFactor) {
		return toJSON().toString(indentFactor);
	}

	public static class RelyingParty {

		private String applicationName;
		private String applicationType;
		private Set<String> contacts = new HashSet<>();
		private Set<String> scope = new HashSet<>();
		private String clientId;
		private Set<String> redirectUris = new HashSet<>();
		private String jwk;
		private String trustMarks;

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

		public Set<String> getRedirectUris() {
			return Collections.unmodifiableSet(redirectUris);
		}

		public String getJwk() {
			return jwk;
		}

		public String getTrustMarks() {
			return trustMarks;
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

		public void setJwk(String jwk) {
			this.jwk = jwk;
		}

		public void setTrustMarks(String trustMarks) {
			this.trustMarks = trustMarks;
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
			json.put("jwk", jwk);
			json.put("trustMarks", trustMarks);

			return json;
		}

		public String toJSONString() {
			return toJSON().toString();
		}

		public String toJSONString(int indentFactor) {
			return toJSON().toString(indentFactor);
		}
	}

}
