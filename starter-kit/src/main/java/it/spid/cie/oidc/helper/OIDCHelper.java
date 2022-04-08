package it.spid.cie.oidc.helper;

import com.nimbusds.jose.jwk.JWKSet;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.spid.cie.oidc.exception.OIDCException;

public class OIDCHelper {

	private static final Logger logger = LoggerFactory.getLogger(OIDCHelper.class);

	private final JWTHelper jwtHelper;

	public OIDCHelper(JWTHelper jwtHelper) {
		this.jwtHelper = jwtHelper;
	}

	public JSONObject getUserInfo(
			String state, String accessToken, JSONObject providerConf, boolean verify,
			JWKSet entityJwks)
		throws OIDCException {

		try {
			HttpRequest request = HttpRequest.newBuilder()
				.uri(new URI(providerConf.optString("userinfo_endpoint")))
				.header("Authorization", "Bearer " + accessToken)
				.GET()
				.build();

			HttpResponse<String> response = HttpClient.newBuilder()
				.followRedirects(HttpClient.Redirect.NORMAL)
				.build()
				.send(request, BodyHandlers.ofString());

			if (response.statusCode() != 200) {
				String msg = String.format(
					"Something went wrong with %s: %d", state, response.statusCode());

				throw new OIDCException(msg);
			}

			JWKSet providerJwks = JWTHelper.getJWKSetFromJSON(
				providerConf.optJSONObject("jwks"));

			JSONObject jwt = jwtHelper.getJWTFromJWE(
				response.body(), entityJwks, providerJwks);

			if (logger.isDebugEnabled()) {
				logger.debug("Userinfo endpoint result: " + jwt.toString(2));
			}

			return jwt.getJSONObject("payload");
		}
		catch (OIDCException e) {
			throw e;
		}
		catch (Exception e) {
			throw new OIDCException(e);
		}
	}

}
