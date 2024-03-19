package it.spid.cie.oidc.spring.boot.relying.party.persistence.model;

import java.time.LocalDateTime;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import com.nimbusds.jose.jwk.KeyUse;
import it.spid.cie.oidc.model.FederationEntity;
import it.spid.cie.oidc.util.GetterUtil;
import it.spid.cie.oidc.util.Validator;

@Entity
@Table(name = "federation_entity_configuration")
public class FederationEntityModel {

	public static FederationEntityModel of(FederationEntity source) {
		FederationEntityModel target = new FederationEntityModel();

		target.setId(source.getStorageId());
		target.setCreated(source.getCreateDate());
		target.setModified(source.getModifiedDate());
		target.setSub(source.getSubject());
		target.setDefaultExpireMinutes(source.getDefaultExpireMinutes());
		target.setDefaultSignatureAlg(source.getDefaultSignatureAlg());
		target.setEntityType(source.getEntityType());
		target.setActive(source.isActive());
		target.setAuthorityHints(source.getAuthorityHints());
		target.setConstraints(source.getConstraints());
		target.setJwksFed(source.getJwksFed());
		target.setJwksCore(source.getJwksCore());
		target.setTrustMarks(source.getTrustMarks());
		target.setTrustMarkIssuers(source.gettrustMarkIssuers());
		target.setMetadata(source.getMetadata());

		return target;
	}

	public FederationEntityModel() {
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

	public String getJwksFed() {
		return jwksFed;
	}

	public String getJwksCore() {
		return jwksCore;
	}

	public String getTrustMarks() {
		return trustMarks;
	}

	public String getTrustMarkIssuers() {
		return trustMarkIssuers;
	}

	public String getMetadata() {
		return metadata;
	}

	public String getConstraints() {
		return constraints;
	}

	public String getEntityType() {
		return entityType;
	}

	public boolean isActive() {
		return active;
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

	public void setJwksFed(String jwksFed) {
		this.jwksFed = jwksFed;
	}
	public void setJwksCore(String jwksCore) {
		this.jwksCore = jwksCore;
	}
	public void setTrustMarks(String trustMarks) {
		this.trustMarks = trustMarks;
	}

	public void setTrustMarkIssuers(String trustMarkIssuers) {
		this.trustMarkIssuers = trustMarkIssuers;
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

	public FederationEntity toFederationEntity() {
		FederationEntity target = new FederationEntity();

		target.setStorageId(getStorageId());
		target.setCreateDate(getCreated());
		target.setModifiedDate(getModified());
		target.setSubject(getSub());
		target.setDefaultExpireMinutes(getDefaultExpireMinutes());
		target.setDefaultSignatureAlg(getDefaultSignatureAlg());
		target.setEntityType(getEntityType());
		target.setActive(isActive());
		target.setAuthorityHints(getAuthorityHints());
		target.setConstraints(getConstraints());
		target.setJwksFed(getJwksFed());
		target.setJwksCore(getJwksCore());
		target.setTrustMarks(getTrustMarks());
		target.settrustMarkIssuers(getTrustMarkIssuers());
		target.setMetadata(getMetadata());

		return target;
	}

	protected void setId(String storageId) {
		if (!Validator.isNullOrEmpty(storageId)) {
			setId(GetterUtil.getLong(storageId));
		}
	}

	private String getStorageId() {
		if (id > 0) {
			return String.valueOf(id);
		}

		return null;
	}


	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false)
	private LocalDateTime created;

	@Column(nullable = false)
	private LocalDateTime modified;

	@Column(nullable = false)
	private String sub;

	@Column(name = "default_exp", nullable = false)
	private int defaultExpireMinutes;

	@Column(name = "default_signature_alg", nullable = false, length = 16)
	private String defaultSignatureAlg = "RS256";

	@Column(name = "authority_hints", nullable = false, length = 2000)
	private String authorityHints;

	@Column(nullable = false, length = 2000)
	private String jwksFed;

	@Column(nullable = false, length = 2000)
	private String jwksCore;
	@Column(name = "trust_marks", nullable = false, length = 2000)
	private String trustMarks;

	@Column(name = "trust_mark_issuers", nullable = false, length = 2000)
	private String trustMarkIssuers;

	@Column(nullable = false, length = 5000)
	private String metadata;

	@Column(name = "is_active", nullable = false)
	private boolean active = false;

	@Column(nullable = false, length = 5000)
	private String constraints;

	@Column(name = "entity_type", nullable = false, length = 50)
	private String entityType;

}
