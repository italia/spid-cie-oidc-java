package it.spid.cie.oidc.model;

import java.time.LocalDateTime;

public class TrustChain extends BaseModel {

	public LocalDateTime getExpiredOn() {
		return exp;
	}

	public String getMetadata() {
		return metadata;
	}

	public String getSubject() {
		return sub;
	}

	public boolean isActive() {
		return active;
	}

	public boolean isExpired() {
		return exp.isBefore(LocalDateTime.now());
	}

	public TrustChain setSubject(String subject) {
		this.sub = subject;

		return this;
	}

	private String sub;
	private String type;
	private LocalDateTime exp;
	private LocalDateTime iat;
	private String chain;
	private String partiesInvolved;
	private boolean active;
	private String log;
	private String metadata;
	private LocalDateTime processingStart;
	private String trustAnchor;
	private String trustMasks;
	private String status;

}
