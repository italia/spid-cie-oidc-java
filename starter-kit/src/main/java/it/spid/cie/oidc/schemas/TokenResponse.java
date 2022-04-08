package it.spid.cie.oidc.schemas;

import java.util.regex.Pattern;

import org.json.JSONObject;

import it.spid.cie.oidc.exception.OIDCException;
import it.spid.cie.oidc.exception.SchemaException;

public class TokenResponse {

	private static Pattern TOKEN_PATTERN = Pattern.compile(
		"^[a-zA-Z0-9_\\-]+\\.[a-zA-Z0-9_\\-]+\\.[a-zA-Z0-9_\\-]+");

	private final String accessToken;
	private final String tokenType;
	private final int expiresIn;
	private final String idToken;

	public static TokenResponse of(JSONObject json) throws OIDCException {
		if (json == null || json.isEmpty()) {
			throw new SchemaException.Validation("Empty source");
		}

		return new TokenResponse(
			json.optString("access_token"), json.optString("token_type"),
			json.optInt("espires_in"), json.optString("id_token"));
	}

	public String getAccessToken() {
		return accessToken;
	}

	public String getTokenType() {
		return tokenType;
	}

	public int getExpiresIn() {
		return expiresIn;
	}

	public String getIdToken() {
		return idToken;
	}

	public JSONObject toJSON() {
		return new JSONObject()
			.put("access_token", accessToken)
			.put("token_type", tokenType)
			.put("expiresIn", expiresIn)
			.put("id_token", idToken);
	}

	public String toString() {
		return toJSON().toString();
	}

	protected TokenResponse(
			String accessToken, String tokenType, int expiresIn, String idToken)
		throws OIDCException {

		if (!TOKEN_PATTERN.matcher(accessToken).matches()) {
			throw new SchemaException.Validation("Invalid access token");
		}
		if (!"Bearer".equals(tokenType)) {
			throw new SchemaException.Validation("Invalid token type");
		}
		if (!TOKEN_PATTERN.matcher(idToken).matches()) {
			throw new SchemaException.Validation("Invalid id token");
		}

		this.accessToken = accessToken;
		this.tokenType = tokenType;
		this.expiresIn = expiresIn;
		this.idToken = idToken;
	}

}
