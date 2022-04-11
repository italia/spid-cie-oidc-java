package it.spid.cie.oidc.model;

import java.time.LocalDateTime;

/**
 * This model represent a "Fetched Entity Statement": a set of information (metadata)
 * about a federation Entity provided by a the entity itself or by a Trust Anchor.
 * <br/>
 * This model helps to interact with these information generally provided as json
 *
 * @author Mauro Mariuzzo
 */
public class CachedEntityInfo extends BaseModel {

	private String iss;
	private String sub;
	private LocalDateTime exp;
	private LocalDateTime iat;
	private String statement;
	private String jwt;

	public static CachedEntityInfo of(
		String iss, String sub, LocalDateTime exp, LocalDateTime iat, String statement,
		String jwt) {

		return new CachedEntityInfo()
			.setExpiresOn(exp)
			.setIssuedAt(iat)
			.setIssuer(iss)
			.setJwt(jwt)
			.setStatement(statement)
			.setSubject(sub);
	}

	public LocalDateTime getExpiresOn() {
		return exp;
	}

	public LocalDateTime getIssuedAt() {
		return iat;
	}

	public String getIssuer() {
		return iss;
	}

	public String getJwt() {
		return jwt;
	}

	public String getStatement() {
		return statement;
	}

	public String getSubject() {
		return sub;
	}

	public boolean isExpired() {
		if (exp != null) {
			return exp.isBefore(LocalDateTime.now());
		}

		return true;
	}

	public CachedEntityInfo setExpiresOn(LocalDateTime expiresOn) {
		this.exp = expiresOn;

		return this;
	}

	public CachedEntityInfo setIssuedAt(LocalDateTime issuedAt) {
		this.iat = issuedAt;

		return this;
	}

	public CachedEntityInfo setIssuer(String issuer) {
		this.iss = issuer;

		return this;
	}

	public CachedEntityInfo setJwt(String jwt) {
		this.jwt = jwt;

		return this;
	}

	public CachedEntityInfo setStatement(String statement) {
		this.statement = statement;

		return this;
	}

	public CachedEntityInfo setSubject(String subject) {
		this.sub = subject;

		return this;
	}

}
