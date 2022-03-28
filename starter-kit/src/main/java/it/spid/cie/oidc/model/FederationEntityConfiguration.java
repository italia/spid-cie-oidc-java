package it.spid.cie.oidc.model;

import org.json.JSONObject;

import it.spid.cie.oidc.config.GlobalOptions;

public class FederationEntityConfiguration extends BaseModel {

	public String getJwks() {
		return jwks;
	}

	public String getMetadata() {
		return metadata;
	}

	public JSONObject getMetadataValue(String key) {
		try {
			JSONObject json = new JSONObject(metadata);

			return json.optJSONObject(key);
		}
		catch (Exception e) {
			return null;
		}
	}

	public boolean isActive() {
		return active;
	}

	public FederationEntityConfiguration setActive(boolean active) {
		this.active = active;

		return this;
	}

	public FederationEntityConfiguration setMetadata(String metadata) {
		this.metadata = metadata;

		return this;
	}

	/**
	 * URL that identifies this Entity in the Federation. Inside {@link EntityConfiguration}
	 * this value will be used as {@code sub} and/or {@code iss}.
	 */
	private String sub;

	/**
	 * how many minutes from now() an issued statement must expire
	 */
	private int defaultExpireMinutes;
	private String defaultSignatureAlg = GlobalOptions.DEFAULT_SIGNING_ALG;
	private String authorityHints;
	private String jwks;
	private String trustMarks;
	private String trustMarksIssuers;
	private String metadata;
	private boolean active = false;
	private String constraints;
	private String entityType;

}
