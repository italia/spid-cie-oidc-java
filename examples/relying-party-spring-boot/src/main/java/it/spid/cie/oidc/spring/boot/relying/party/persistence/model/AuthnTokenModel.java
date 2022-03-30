package it.spid.cie.oidc.spring.boot.relying.party.persistence.model;

import java.time.LocalDateTime;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import it.spid.cie.oidc.model.AuthnToken;
import it.spid.cie.oidc.util.GetterUtil;
import it.spid.cie.oidc.util.Validator;

@Entity
@Table(name = "oidc_authentication_token")
public class AuthnTokenModel {

	public static AuthnTokenModel of(AuthnToken source) {
		AuthnTokenModel target = new AuthnTokenModel();

		target.setId(source.getStorageId());
		target.setCreated(source.getCreateDate());
		target.setModified(source.getModifiedDate());
		target.setAccessToken(source.getAccessToken());
		target.setAuthzRequestId(source.getAuthnRequestId());
		target.setCode(source.getCode());
		target.setExpiresIn(source.getExpiresIn());
		target.setIdToken(source.getIdToken());
		target.setRefreshToken(source.getRefreshToken());
		target.setRevoked(source.getRevoked());
		target.setScope(source.getScope());
		target.setTokenType(source.getTokenType());
		target.setUserKey(source.getUserKey());

		return target;
	}

	public AuthnTokenModel() {
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

	public String getAccessToken() {
		return accessToken;
	}

	public long getAuthzRequestId() {
		return authzRequestId;
	}

	public String getCode() {
		return code;
	}

	public int getExpiresIn() {
		return expiresIn;
	}

	public String getIdToken() {
		return idToken;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public LocalDateTime getRevoked() {
		return revoked;
	}

	public String getScope() {
		return scope;
	}

	public String getTokenType() {
		return tokenType;
	}

	public String getUserKey() {
		return userKey;
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

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	public void setAuthzRequestId(long authzRequestId) {
		this.authzRequestId = authzRequestId;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public void setExpiresIn(int expiresIn) {
		this.expiresIn = expiresIn;
	}

	public void setIdToken(String idToken) {
		this.idToken = idToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	public void setRevoked(LocalDateTime revoked) {
		this.revoked = revoked;
	}

	public void setScope(String scope) {
		this.scope = scope;
	}

	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}

	public void setUserKey(String userKey) {
		this.userKey = userKey;
	}

	public AuthnToken toAuthnToken() {
		AuthnToken target = new AuthnToken();

		target.setStorageId(getStorageId());
		target.setCreateDate(getCreated());
		target.setModifiedDate(getModified());
		target.setAccessToken(getAccessToken());
		target.setAuthnRequestId(String.valueOf(getAuthzRequestId()));
		target.setCode(getCode());
		target.setExpiresIn(getExpiresIn());
		target.setIdToken(getIdToken());
		target.setRefreshToken(getRefreshToken());
		target.setRevoked(getRevoked());
		target.setScope(getScope());
		target.setTokenType(getTokenType());
		target.setUserKey(getUserKey());

		return target;
	}

	protected void setAuthzRequestId(String authnRequestId) {
		setAuthzRequestId(GetterUtil.getLong(authnRequestId));
	}

	protected void setId(String storageId) {
		if (!Validator.isNullOrEmpty(storageId)) {
			setId(GetterUtil.getLong(storageId));
		}
	}

	private String getStorageId() {
		if (id != null && id > 0) {
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


}
