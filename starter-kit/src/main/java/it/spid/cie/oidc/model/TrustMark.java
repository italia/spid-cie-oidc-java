package it.spid.cie.oidc.model;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.spid.cie.oidc.exception.OIDCException;
import it.spid.cie.oidc.exception.TrustMarkException;
import it.spid.cie.oidc.helper.EntityHelper;
import it.spid.cie.oidc.helper.JWTHelper;

public class TrustMark {

	private static final Logger logger = LoggerFactory.getLogger(TrustMark.class);

	private final JWTHelper jwtHelper;
	private final JSONObject header;
	private final String id;
	private final String iss;
	private final String jwt;
	private final String sub;
	private boolean valid = false;
	private EntityConfiguration issuerEC;

	public TrustMark(String jwt, JWTHelper jwtHelper) {
		JSONObject token = JWTHelper.fastParse(jwt);

		JSONObject header = token.getJSONObject("header");
		JSONObject payload = token.getJSONObject("payload");

		this.jwtHelper = jwtHelper;
		this.jwt = jwt;
		this.id = payload.getString("id");
		this.iss = payload.getString("iss");
		this.sub = payload.getString("sub");
		this.header = header;
	}

	public String getId() {
		return this.id;
	}

	public String getIssuer() {
		return this.iss;
	}

	public boolean isValid() {
		return valid;
	}

	public boolean validate(EntityConfiguration ec) throws OIDCException {
		String kid = header.optString("kid");

		if (!ec.hasJWK(kid)) {
			throw new TrustMarkException(
				"Trust Mark validation failed: %s not found in %s", kid, ec.getJwks());
		}

		valid = jwtHelper.verifyJWS(jwt, ec.getJWKSet());

		return valid;
	}

	public boolean validateByIssuer() throws OIDCException {
		if (issuerEC == null) {
			String ec = EntityHelper.getEntityConfiguration(iss);

			issuerEC = new EntityConfiguration(ec, jwtHelper);
		}

		if (!issuerEC.validateItself()) {
			valid = false;

			logger.warn("Issuer {} of trust mark {} is not valid.", iss, id);

			return false;
		}

		String kid = header.optString("kid");

		if (!issuerEC.hasJWK(kid)) {
			throw new TrustMarkException(
				"Trust Mark validation failed by its Issuer: %s not found in %s", kid,
				issuerEC.getJwks());
		}

		valid = jwtHelper.verifyJWS(jwt, issuerEC.getJWKSet());

		return valid;
	}

	public JSONObject toJSON() {
		return new JSONObject()
			.put("id", this.id)
			.put("trust_mark", this.jwt);
	}

	@Override
	public String toString() {
		return String.format("%s to %s issued by %s", id, sub, iss);
	}

}
