package it.spid.cie.oidc.relying.party.helper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.spid.cie.oidc.relying.party.model.OidcConstants;
import it.spid.cie.oidc.relying.party.util.StringUtil;

public class EntityHelper {

	private static Logger logger = LoggerFactory.getLogger(
		EntityHelper.class);

	public static String getEntityConfiguration(String subject)
		throws Exception {

		return getEntityConfiguration(subject, new HashMap<String, String>());
	}

	public static String getEntityConfiguration(
			String subject, Map<String, String> params)
		throws Exception {

		String url = StringUtil.ensureTrailingSlash(
				subject
			).concat(
				OidcConstants.OIDCFED_FEDERATION_WELLKNOWN_URL
			);

		logger.info("Starting Entity Configuration Request for " + url);

		HttpRequest request = HttpRequest.newBuilder()
			.uri(new URI(url))
			.GET()
			.build();

		HttpResponse<String> response = HttpClient.newBuilder()
			.followRedirects(HttpClient.Redirect.NORMAL)
			.build()
			.send(request, BodyHandlers.ofString());

		if (logger.isDebugEnabled()) {
			logger.info(url + " --> " + response.statusCode());
		}

		// TODO: Cheks status != 200

		return response.body();
	}

	/**
	 * Fetches an entity statement/configuration
	 *
	 * @param url
	 * @return
	 * @throws Exception
	 */
	public static String getEntityStatement(String url)
		throws Exception {

		// TODO: sync or async by conf

		// TODO: debug
		logger.info("Starting Entity Statement Request to " + url);

		HttpRequest request = HttpRequest.newBuilder()
			.uri(new URI(url))
			.GET()
			.build();

		HttpResponse<String> response = HttpClient.newBuilder()
			.followRedirects(HttpClient.Redirect.NORMAL)
			.build()
			.send(request, BodyHandlers.ofString());

		if (logger.isDebugEnabled()) {
			logger.debug(url + " --> " + response.statusCode());
		}

		if (response.statusCode() != 200) {
			throw new Exception(url + " gets " + response.statusCode());
		}

		return response.body();
	}
}
