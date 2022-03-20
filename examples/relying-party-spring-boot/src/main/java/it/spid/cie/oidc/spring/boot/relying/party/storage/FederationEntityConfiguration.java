package it.spid.cie.oidc.spring.boot.relying.party.storage;

import java.time.LocalDateTime;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import org.json.JSONObject;

@Entity
@Table(name = "federation_entity_configuration")
public class FederationEntityConfiguration {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false)
	private LocalDateTime created;

	@Column(nullable = false)
	private LocalDateTime modified;

	/**
	 * URL that identifies this Entity in the Federation. This value and iss are the same
	 * in the Entity Configuration.
	 */
	@Column(nullable = false)
	private String sub;

	/**
	 * how many minutes from now() an issued statement must expire
	 */
	@Column(name = "default_exp", nullable = false)
	private int defaultExpireMinutes;

	@Column(name = "default_signature_alg", nullable = false, length = 16)
	private String defaultSignatureAlg = "RS256";

	@Column(name = "authority_hints", nullable = false, length = 2000)
	private String authorityHints;

	@Column(nullable = false, length = 2000)
	private String jwks;

	@Column(name = "trust_marks", nullable = false, length = 2000)
	private String trustMarks;

	@Column(name = "trust_marks_issuers", nullable = false, length = 2000)
	private String trustMarksIssuers;

	@Column(nullable = false, length = 5000)
	private String metadata;

	@Column(name = "is_active", nullable = false)
	private boolean active = false;

	@Column(nullable = false, length = 5000)
	private String constraints;

	@Column(name = "entity_type", nullable = false, length = 50)
	private String entityType;

	public FederationEntityConfiguration() {
		created = LocalDateTime.now();
		modified = created;
	}

	public Long getId() {
		return id;
	}

	public LocalDateTime getCreated() {
		return created;
	}

	public LocalDateTime getModified() {
		return modified;
	}

	public String getSub() {
		return sub;
	}

	public int getDefaultExpireMinutes() {
		return defaultExpireMinutes;
	}

	public String getDefaultSignatureAlg() {
		return defaultSignatureAlg;
	}

	public String getAuthorityHints() {
		return authorityHints;
	}

	public String getJwks() {
		return jwks;
	}

	public String getTrustMarks() {
		return trustMarks;
	}

	public String getTrustMarksIssuers() {
		return trustMarksIssuers;
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

	public String getConstraints() {
		return constraints;
	}

	public String getEntityType() {
		return entityType;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public void setCreated(LocalDateTime created) {
		this.created = created;
	}

	public void setModified(LocalDateTime modified) {
		this.modified = modified;
	}

	public void setSub(String sub) {
		this.sub = sub;
	}

	public void setDefaultExpireMinutes(int defaultExpireMinutes) {
		this.defaultExpireMinutes = defaultExpireMinutes;
	}

	public void setDefaultSignatureAlg(String defaultSignatureAlg) {
		this.defaultSignatureAlg = defaultSignatureAlg;
	}

	public void setAuthorityHints(String authorityHints) {
		this.authorityHints = authorityHints;
	}

	public void setJwks(String jwks) {
		this.jwks = jwks;
	}

	public void setTrustMarks(String trustMarks) {
		this.trustMarks = trustMarks;
	}

	public void setTrustMarksIssuers(String trustMarksIssuers) {
		this.trustMarksIssuers = trustMarksIssuers;
	}

	public void setMetadata(String metadata) {
		this.metadata = metadata;
	}

	public void setActive(boolean active) {
		this.active = active;
	}

	public void setConstraints(String constraints) {
		this.constraints = constraints;
	}

	public void setEntityType(String entityType) {
		this.entityType = entityType;
	}

}
