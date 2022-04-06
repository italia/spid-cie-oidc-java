package it.spid.cie.oidc.spring.boot.relying.party.persistence.model;

import java.time.LocalDateTime;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Transient;

import it.spid.cie.oidc.model.TrustChain;
import it.spid.cie.oidc.util.GetterUtil;
import it.spid.cie.oidc.util.Validator;

@Entity
@Table(name = "trust_chain")
public class TrustChainModel {

	public static TrustChainModel of(
		TrustChain source, EntityInfoModel trustAnchorModel) {

		TrustChainModel target = new TrustChainModel();

		target.setId(source.getStorageId());
		target.setCreated(source.getCreateDate());
		target.setModified(source.getModifiedDate());
		target.setSub(source.getSubject());
		target.setType(source.getType());
		target.setExp(source.getExpiresOn());
		target.setIat(source.getIssuedAt());
		target.setChain(source.getChain());
		target.setPartiesInvolved(source.getPartiesInvolved());
		target.setActive(source.isActive());
		target.setLog(source.getLog());
		target.setMetadata(source.getMetadata());
		target.setProcessingStart(source.getProcessingStart());
		target.setTrustAnchorId(trustAnchorModel.getId());
		target.setTrustAnchor(trustAnchorModel.getSub());
		target.setTrustMasks(source.getTrustMarks());
		target.setStatus(source.getStatus());

		return target;
	}

	public TrustChainModel() {
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

	public String getType() {
		return type;
	}

	public LocalDateTime getExp() {
		return exp;
	}

	public LocalDateTime getIat() {
		return iat;
	}

	public String getChain() {
		return chain;
	}

	public String getPartiesInvolved() {
		return partiesInvolved;
	}

	public boolean isActive() {
		return active;
	}

	public String getLog() {
		return log;
	}

	public String getMetadata() {
		return metadata;
	}

	public LocalDateTime getProcessingStart() {
		return processingStart;
	}

	public long getTrustAnchorId() {
		return trustAnchorId;
	}

	public String getTrustMasks() {
		return trustMasks;
	}

	public String getStatus() {
		return status;
	}

	public boolean isExpired() {
		return exp.isBefore(LocalDateTime.now());
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

	public void setType(String type) {
		this.type = type;
	}

	public void setExp(LocalDateTime exp) {
		this.exp = exp;
	}

	public void setIat(LocalDateTime iat) {
		this.iat = iat;
	}

	public void setChain(String chain) {
		this.chain = chain;
	}

	public void setPartiesInvolved(String partiesInvolved) {
		this.partiesInvolved = partiesInvolved;
	}

	public void setActive(boolean active) {
		this.active = active;
	}

	public void setLog(String log) {
		this.log = log;
	}

	public void setMetadata(String metadata) {
		this.metadata = metadata;
	}

	public void setProcessingStart(LocalDateTime processingStart) {
		this.processingStart = processingStart;
	}

	public void setTrustAnchorId(long trustAnchorId) {
		this.trustAnchorId = trustAnchorId;
	}

	public void setTrustAnchor(String trustAnchor) {
		this.trustAnchor = trustAnchor;
	}

	public void setTrustMasks(String trustMasks) {
		this.trustMasks = trustMasks;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public TrustChain toTrustChain(EntityInfoModel trustAnchorModel) {
		TrustChain target = new TrustChain();

		target.setStorageId(getStorageId());
		target.setCreateDate(getCreated());
		target.setModifiedDate(getModified());
		target.setActive(isActive());
		target.setChain(getChain());
		target.setExpiresOn(getExp());
		target.setIssuedAt(getIat());
		target.setLog(getLog());
		target.setMetadata(getMetadata());
		target.setPartiesInvolved(getPartiesInvolved());
		target.setProcessingStart(getProcessingStart());
		target.setSubject(getSub());
		target.setStatus(getStatus());
		target.setTrustMarks(getTrustMasks());
		target.setType(getType());

		if (trustAnchorModel != null) {
			target.setTrustAnchor(trustAnchorModel.getSub());
		}

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

	@Column(name = "is_active", nullable = false)
	private boolean active;

	@Column(nullable = false)
	private String chain;

	@Column(nullable = false)
	private LocalDateTime exp;

	@Column(nullable = false)
	private LocalDateTime iat;

	@Column(nullable = false)
	private String log;

	@Column(nullable = true)
	private String metadata;

	@Column(name = "parties_involved", nullable = false)
	private String partiesInvolved;

	@Column(name = "processing_start", nullable = false)
	private LocalDateTime processingStart;

	@Column(nullable = false)
	private String sub;

	@Column(nullable = false)
	private String status;

	@Transient
	private String trustAnchor;

	@Column(name = "trust_anchor_id", nullable = false)
	private long trustAnchorId;

	@Column(name = "trust_masks", nullable = false)
	private String trustMasks;

	@Column(name = "type_", nullable = false)
	private String type;

}
