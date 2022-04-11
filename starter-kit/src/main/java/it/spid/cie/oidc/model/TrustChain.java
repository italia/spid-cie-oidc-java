package it.spid.cie.oidc.model;

import java.time.LocalDateTime;

import org.json.JSONObject;

import it.spid.cie.oidc.exception.OIDCException;

public class TrustChain extends BaseModel {

	private boolean active;
	private String chain;
	private LocalDateTime exp;
	private LocalDateTime iat;
	private String log = "";
	private String metadata;
	private String partiesInvolved;
	private LocalDateTime processingStart;
	private String status = "unreachable";
	private String sub;
	private String trustAnchor;
	private String trustMarks;
	private String type;

	public TrustChain() {
		super();
		this.iat = LocalDateTime.now();
	}

	/**
	 * @return the string representation of a JSONArray with the list of entity statements
	 * collected during the metadata discovery
	 */
	public String getChain() {
		return chain;
	}

	public LocalDateTime getExpiresOn() {
		return exp;
	}

	public LocalDateTime getIssuedAt() {
		return iat;
	}

	public String getLog() {
		return log;
	}

	/**
	 * @return the string representation of a JSONObject with the final metadata applied
	 * with the metadata policy built over the chain
	 */
	public String getMetadata() {
		return metadata;
	}

	public JSONObject getMetadataAsJSON() {
		try {
			return new JSONObject(this.metadata);
		}
		catch (Exception e) {
			// Ignore
		}

		return new JSONObject();
	}

	public String getPartiesInvolved() {
		return partiesInvolved;
	}

	public LocalDateTime getProcessingStart() {
		return processingStart;
	}

	public String getSubject() {
		return sub;
	}

	public String getStatus() {
		return status;
	}

	public String getTrustAnchor() {
		return trustAnchor;
	}

	public String getTrustMarks() {
		return trustMarks;
	}

	public String getType() {
		return type;
	}

	public boolean isActive() {
		return active;
	}

	public boolean isExpired() {
		if (exp != null) {
			return exp.isBefore(LocalDateTime.now());
		}

		return true;
	}

	public TrustChain setActive(boolean active) {
		this.active = active;

		return this;
	}

	public TrustChain setChain(String chain) {
		this.chain = chain;

		return this;
	}

	public TrustChain setExpiresOn(LocalDateTime expiresOn) {
		this.exp = expiresOn;

		return this;
	}

	public TrustChain setIssuedAt(LocalDateTime issuedAt) {
		this.iat = issuedAt;

		return this;
	}

	public TrustChain setLog(String log) {
		this.log = log;

		return this;
	}

	public TrustChain setMetadata(String metadata) {
		this.metadata = metadata;

		return this;
	}

	public TrustChain setPartiesInvolved(String partiesInvolved) {
		this.partiesInvolved = partiesInvolved;

		return this;
	}

	public TrustChain setProcessingStart(LocalDateTime processingStart) {
		this.processingStart = processingStart;

		return this;
	}

	public TrustChain setStatus(String status) {
		this.status = status;

		return this;
	}

	public TrustChain setSubject(String subject) {
		this.sub = subject;

		return this;
	}

	public TrustChain setTrustAnchor(String trustAnchor) {
		this.trustAnchor = trustAnchor;

		return this;
	}

	public TrustChain setTrustMarks(String trustMarks) {
		this.trustMarks = trustMarks;

		return this;
	}

	public TrustChain setType(String type) {
		this.type = type;

		return this;
	}

}
