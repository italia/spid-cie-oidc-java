package it.spid.cie.oidc.spring.boot.relying.party.storage;

import java.time.LocalDateTime;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.UniqueConstraint;

@Entity
@Table(
	name = "fetched_entity_statement",
	uniqueConstraints = {
		@UniqueConstraint(columnNames = {"iss", "sub"})
	}
)
public class EntityInfo {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false)
	private LocalDateTime created;

	@Column(nullable = false)
	private LocalDateTime modified;

	@Column(nullable = false)
	private String iss;

	@Column(nullable = false)
	private String sub;

	@Column(nullable = false)
	private LocalDateTime exp;

	@Column(nullable = false)
	private LocalDateTime iat;

	@Column(nullable = false)
	private String statement;

	@Column(nullable = false)
	private String jwt;

	public EntityInfo(
		String iss, String sub, LocalDateTime exp, LocalDateTime iat,
		String statement, String jwt) {

		this.iss = iss;
		this.sub = sub;
		this.exp = exp;
		this.iat = iat;
		this.statement = statement;
		this.jwt = jwt;
		this.created = LocalDateTime.now();
		this.modified = this.created;
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

	public String getIss() {
		return iss;
	}

	public String getSub() {
		return sub;
	}

	public LocalDateTime getExp() {
		return exp;
	}

	public LocalDateTime getIat() {
		return iat;
	}

	public String getStatement() {
		return statement;
	}

	public String getJwt() {
		return jwt;
	}

	public boolean isExpired() {
		return exp.isBefore(LocalDateTime.now());
	}

	public void setModified(LocalDateTime modified) {
		this.modified = modified;
	}

	public void setExp(LocalDateTime exp) {
		this.exp = exp;
	}

	public void setIat(LocalDateTime iat) {
		this.iat = iat;
	}

	public void setStatement(String statement) {
		this.statement = statement;
	}

	public void setJwt(String jwt) {
		this.jwt = jwt;
	}

	protected EntityInfo() {
		// Empty constructor
	}

}
