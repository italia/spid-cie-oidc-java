package it.spid.cie.oidc.spring.boot.relying.party.storage;

import java.time.LocalDateTime;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "oidc_authentication_token")
public class OidcAuthenticationToken {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false)
	private LocalDateTime created;

	@Column(nullable = false)
	private LocalDateTime modified;

	@Column(nullable = true)
	private String code;

	@Column(name = "access_token", nullable = true)
	private String accessToken;

	@Column(name = "id_token", nullable = true)
	private String idToken;

	@Column(nullable = true)
	private String scope;

	@Column(name = "token_type", nullable = true)
	private String tokenType;

	@Column(name = "expires_in", nullable = true)
	private int expiresIn;

	@Column(name = "authz_request_id", nullable = false)
	private long authzRequestId;

	@Column(name = "user_key", nullable = true)
	private String userKey;

	@Column(nullable = true)
	private LocalDateTime revoked;

	@Column(name = "refresh_token", nullable = true)
	private String refreshToken;

	public OidcAuthenticationToken() {
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

	public String getCode() {
		return code;
	}

	public String getAccessToken() {
		return accessToken;
	}

	public String getIdToken() {
		return idToken;
	}

	public String getScope() {
		return scope;
	}

	public String getTokenType() {
		return tokenType;
	}

	public int getExpiresIn() {
		return expiresIn;
	}

	public long getAuthzRequestId() {
		return authzRequestId;
	}

	public String getUserKey() {
		return userKey;
	}

	public LocalDateTime getRevoked() {
		return revoked;
	}

	public String getRefreshToken() {
		return refreshToken;
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

	public void setCode(String code) {
		this.code = code;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	public void setIdToken(String idToken) {
		this.idToken = idToken;
	}

	public void setScope(String scope) {
		this.scope = scope;
	}

	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}

	public void setExpiresIn(int expiresIn) {
		this.expiresIn = expiresIn;
	}

	public void setAuthzRequestId(long authzRequestId) {
		this.authzRequestId = authzRequestId;
	}

	public void setUserKey(String userKey) {
		this.userKey = userKey;
	}

	public void setRevoked(LocalDateTime revoked) {
		this.revoked = revoked;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}



}
