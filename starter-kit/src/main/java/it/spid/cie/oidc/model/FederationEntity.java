package it.spid.cie.oidc.model;

import org.json.JSONObject;

import it.spid.cie.oidc.config.GlobalOptions;

/**
 * This class describes a "Federation Entity" (Federation Entity Configuration). It
 * represent the touch point between the starter kit and the final application where this
 * element have to be persisted into a database or something similar.
 *
 * @author Mauro Mariuzzo
 */
public class FederationEntity extends BaseModel {

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
	private String trustMarkIssuers;
	private String metadata;
	private boolean active = false;
	private String constraints;
	private String entityType;

	public String getAuthorityHints() {
		return authorityHints;
	}

	public String getConstraints() {
		return constraints;
	}

	public String getEntityType() {
		return entityType;
	}

	public int getDefaultExpireMinutes() {
		return defaultExpireMinutes;
	}

	public String getDefaultSignatureAlg() {
		return defaultSignatureAlg;
	}

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

	public String getSubject() {
		return sub;
	}

	public String getTrustMarks() {
		return trustMarks;
	}

	public String gettrustMarkIssuers() {
		return trustMarkIssuers;
	}

	public boolean isActive() {
		return active;
	}

	public FederationEntity setActive(boolean active) {
		this.active = active;

		return this;
	}

	public void setAuthorityHints(String authorityHints) {
		this.authorityHints = authorityHints;
	}

	public void setConstraints(String constraints) {
		this.constraints = constraints;
	}

	public void setDefaultExpireMinutes(int defaultExpireMinutes) {
		this.defaultExpireMinutes = defaultExpireMinutes;
	}

	public void setDefaultSignatureAlg(String defaultSignatureAlg) {
		this.defaultSignatureAlg = defaultSignatureAlg;
	}

	public void setEntityType(String entityType) {
		this.entityType = entityType;
	}

	public void setJwks(String jwks) {
		this.jwks = jwks;
	}

	public FederationEntity setMetadata(String metadata) {
		this.metadata = metadata;

		return this;
	}

	public FederationEntity setSubject(String subject) {
		this.sub = subject;

		return this;
	}

	public void setTrustMarks(String trustMarks) {
		this.trustMarks = trustMarks;
	}

	public void settrustMarkIssuers(String trustMarkIssuers) {
		this.trustMarkIssuers = trustMarkIssuers;
	}


}
