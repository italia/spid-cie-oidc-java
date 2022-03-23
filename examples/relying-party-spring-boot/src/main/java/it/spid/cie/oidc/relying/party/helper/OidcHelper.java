package it.spid.cie.oidc.relying.party.helper;

import com.nimbusds.jose.jwk.JWKSet;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OidcHelper {

	public static JSONObject getUserInfo(
			String state, String accessToken, JSONObject providerConf, boolean verify,
			JWKSet entityJwks)
		throws Exception {

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

			throw new Exception(msg);
		}

		JWKSet providerJwks = JWTHelper.getJWKSetFromJSON(
			providerConf.optJSONObject("jwks"));

		JSONObject jwt = JWTHelper.getJWTFromJWE(
			response.body(), entityJwks, providerJwks);

		logger.info("Userinfo endpoint result: " + jwt.toString(2));

		return jwt.getJSONObject("payload");
	}

	private static final Logger logger = LoggerFactory.getLogger(OidcHelper.class);

}
