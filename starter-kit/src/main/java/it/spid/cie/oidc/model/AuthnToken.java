package it.spid.cie.oidc.model;

import java.time.LocalDateTime;

public class AuthnToken extends BaseModel {

	private String code;
	private String accessToken;
	private String idToken;
	private String scope;
	private String tokenType;
	private int expiresIn;
	private String authnRequestId;
	private String userKey;
	private LocalDateTime revoked;
	private String refreshToken;

	public String getAccessToken() {
		return accessToken;
	}

	public String getAuthnRequestId() {
		return authnRequestId;
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

	public AuthnToken setAccessToken(String accessToken) {
		this.accessToken = accessToken;

		return this;
	}

	public AuthnToken setAuthnRequestId(String authnRequestId) {
		this.authnRequestId = authnRequestId;

		return this;
	}

	public AuthnToken setCode(String code) {
		this.code = code;

		return this;
	}

	public AuthnToken setExpiresIn(int expiresIn) {
		this.expiresIn = expiresIn;

		return this;
	}

	public AuthnToken setIdToken(String idToken) {
		this.idToken = idToken;

		return this;
	}

	public AuthnToken setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;

		return this;
	}

	public AuthnToken setRevoked(LocalDateTime revoked) {
		this.revoked = revoked;

		return this;
	}

	public AuthnToken setScope(String scope) {
		this.scope = scope;

		return this;
	}

	public AuthnToken setTokenType(String tokenType) {
		this.tokenType = tokenType;

		return this;
	}

	public AuthnToken setUserKey(String userKey) {
		this.userKey = userKey;

		return this;
	}

}
