package it.spid.cie.oidc.spring.boot.relying.party.storage;

import java.time.LocalDateTime;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Transient;

import it.spid.cie.oidc.relying.party.model.EntityConfiguration;

@Entity
@Table(name = "trust_chain")
public class TrustChain {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false)
	private LocalDateTime created;

	@Column(nullable = false)
	private LocalDateTime modified;

	@Column(nullable = false)
	private String sub;

	@Column(name = "type_", nullable = false)
	private String type;

	@Column(nullable = false)
	private LocalDateTime exp;

	@Column(nullable = false)
	private LocalDateTime iat;

	@Column(nullable = false)
	private String chain;

	@Column(name = "parties_involved", nullable = false)
	private String partiesInvolved;

	@Column(name = "is_active", nullable = false)
	private boolean active;

	@Column(nullable = false)
	private String log;

	@Column(nullable = true)
	private String metadata;

	@Column(name = "processing_start", nullable = false)
	private LocalDateTime processingStart;

	@Column(name = "trust_anchor_id", nullable = false)
	private long trustAnchorId;

	@Transient
	private String trustAnchor;

	@Column(name = "trust_masks", nullable = false)
	private String trustMasks;

	@Column(nullable = false)
	private String status;

	public TrustChain(
		String sub, String type, LocalDateTime exp, LocalDateTime iat,
		String chain, String partiesInvolved, boolean active, String log,
		String metadata, LocalDateTime processingStart, long trustAnchorId,
		String trustMasks, String status, String trustAnchor) {

		this.created = LocalDateTime.now();
		this.modified = this.created;
		this.sub = sub;
		this.type = type;
		this.exp = exp;

		if (iat != null) {
			this.iat = iat;
		}
		else {
			this.iat = this.created;
		}

		this.chain = chain;
		this.partiesInvolved = partiesInvolved;
		this.active = active;
		this.log = log;
		this.metadata = metadata;
		this.processingStart = processingStart;
		this.trustAnchorId = trustAnchorId;
		this.trustMasks = trustMasks;
		this.status = status;
	}

	public static TrustChain of(
		String sub, EntityConfiguration trustAnchor,
		String[] requiredTrustMasks, String metadataType) {
		// TODO
		return null;
	}

	public TrustChain(String sub, String type) {
		this.sub = sub;
		this.type = type;
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

	protected TrustChain() {}

}
