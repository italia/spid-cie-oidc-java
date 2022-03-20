package it.spid.cie.oidc.relying.party.helper;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.JWKGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.JWSVerifierFactory;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.UUID;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.spid.cie.oidc.relying.party.util.ArrayUtil;
import it.spid.cie.oidc.relying.party.util.GetterUtil;

public class JWTHelper {

	public static final String[] ALLOWED_SIGNING_ALGS = new String[] {
		"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"};

	public static String decodeBase64(String encoded) {
		Base64 b = new Base64(encoded);

		return b.decodeToString();
	}

	public static JSONObject fastParse(String jwt) {
		String[] parts = jwt.split("\\.");

		JSONObject result = new JSONObject();

		result.put("header", new JSONObject(decodeBase64(parts[0])));
		result.put("payload", new JSONObject(decodeBase64(parts[1])));

		return result;
	}

	public static JSONObject fastParsePayload(String jwt) {
		String[] parts = jwt.split("\\.");

		return new JSONObject(decodeBase64(parts[1]));
	}

	/**
	 * Get the JSON Web Key (JWK) set from the provided JWT Token, or null if
	 * not present
	 *
	 * @param jwt the encoded JWT Token
	 * @return
	 * @throws ParseException
	 */
	public static JWKSet getJWKSetFromJWT(String jwt) throws ParseException {
		JSONObject token = fastParse(jwt);

		JSONObject payload = token.getJSONObject("payload");

		return getJWKSet(payload);
	}

	/**
	 * Get the JSON Web Key (JWK) set from the provided JSON string
	 *
	 * @param value a string representation of a JSONArray (array of keys) or of a
	 * JSONObject (complete jwks element)
	 * @return
	 * @throws Exception
	 */
	public static JWKSet getJWKSetFromJSON(String value) throws Exception {
		value = GetterUtil.getString(value, "{}").trim();

		JSONObject jwks;

		if (value.startsWith("[")) {
			jwks = new JSONObject()
				.put("keys", new JSONArray(value));
		}
		else {
			jwks = new JSONObject(value);
		}

		return JWKSet.parse(jwks.toMap());
	}

	public static JWKSet getMetadataJWKSet(JSONObject metadata) throws Exception {
		if (metadata.has("jwks")) {
			return JWKSet.parse(metadata.getJSONObject("jwks").toMap());
		}
		else if (metadata.has("jwks_uri")) {
			String url = metadata.getString("jwks_uri");

			try {
				return JWKSet.load(new URL(url));
			}
			catch (Exception e) {
				throw new Exception("Failed to download jwks from " + url);
			}
			/*
			try {
				HttpRequest request = HttpRequest.newBuilder()
					.uri(new URI(url))
					.GET()
					.build();

				HttpResponse<String> response = HttpClient.newBuilder()
					.followRedirects(HttpClient.Redirect.NORMAL)
					.build()
					.send(request, BodyHandlers.ofString());

				if (response.statusCode() == 200) {
					return JWKSet.parse(response.body());
				}

				throw new Exception("statusCode=" + response.statusCode());
			}
			catch (Exception e) {
				throw new Exception("Failed to download jwks from " + url);
			}
			*/
		}

		throw new Exception("No jwks in metadata");
	}

	public static RSAKey createRSAKey(JWSAlgorithm alg, KeyUse use) throws Exception {
		if (alg == null) {
			alg = JWSAlgorithm.RS256;
		}

		return new RSAKeyGenerator(2048)
			.algorithm(JWSAlgorithm.RS256)
			.keyUse(use)
			.keyIDFromThumbprint(true)
			.generate();
	}

	public static RSAKey parseRSAKey(String s) throws ParseException {
		return RSAKey.parse(s);
	}

	/*
	public static void selfCheck(String jws, JWK jwk) throws Exception {
		JSONObject token = fastParse(jws);

		JSONObject header = token.getJSONObject("header");
		JSONObject payload = token.getJSONObject("payload");

		String alg = header.optString("alg");

		KeyType type = jwk.getKeyType();

		if (KeyType.RSA.equals(type)) {
			jwk.toRSAKey();
		}
		lese

		JWSVerifierFactory factory = new DefaultJWSVerifierFactory();

		factory.createJWSVerifier(
				new JWSHeader(JWSAlgorithm.parse(alg)), jwk));

		String kid = header.getString("kid");

	}
	*/

	public static boolean isValidAlgorithm(JWSAlgorithm alg)
		throws Exception {

		return ArrayUtil.contains(ALLOWED_SIGNING_ALGS, alg.toString(), true);
	}

	public static boolean verifyJWS(String jws, JWKSet jwkSet)
		throws Exception {

		SignedJWT jwtToken = SignedJWT.parse(jws);

		String kid = jwtToken.getHeader().getKeyID();

		JWK jwk = jwkSet.getKeyByKeyId(kid);

		if (jwk == null) {
			// TODO UnknownKidException
			throw new Exception(
				String.format(
					"kid %s not found in jwks %s", kid, jwkSet.toString()));
		}

		JWSAlgorithm alg = jwtToken.getHeader().getAlgorithm();

		if (!isValidAlgorithm(alg)) {
			String msg = String.format(
				"%s has beed disabled for security reason", alg);

//			throw new UnsupportedAlgorithmException(msg);
			throw new Exception(msg);
		}

		JWSVerifier verifier = getJWSVerifier(alg, jwk);

		return jwtToken.verify(verifier);
	}

	public static void selfCheck2(String jwt, String[] supportedAlgs)
		throws Exception {

		JSONObject token = fastParse(jwt);

		JSONObject header = token.getJSONObject("header");
		JSONObject payload = token.getJSONObject("payload");

		String kid = header.getString("kid");

		JWKSet jwks = getJWKSet(payload);

		JWK jwk = jwks.getKeyByKeyId(kid);

		if (jwk == null) {
			// TODO UnknownKidException
			throw new Exception(
				String.format(
					"kid %s not found in jwks %s", kid, jwks.toString()));
		}

		String alg = header.optString("alg");

		if (!ArrayUtil.contains(supportedAlgs, alg, true)) {
			String msg = String.format(
				"%s has beed disabled for security reason", alg);

//			throw new UnsupportedAlgorithmException(msg);
			throw new Exception(msg);
		}

		JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(alg);

		if (RSASSAVerifier.SUPPORTED_ALGORITHMS.contains(jwsAlgorithm)) {
			KeyType type = jwk.getKeyType();

			RSAKey k1 = (RSAKey)jwk;

			PublicKey publicKey = k1.toPublicKey();

			System.out.println("type=" + type);

			JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey)publicKey);

			SignedJWT jwtToken = SignedJWT.parse(jwt);

//			jwtToken.getHeader().getAlgorithm();
//			jwtToken.getHeader().getJWK();
			//jwtToken.getJWTClaimsSet().

			System.out.println("state=" + jwtToken.getState());

			try {
				System.out.println("verify=" + jwtToken.verify(verifier));
			}
			catch (Exception e) {
				System.out.println("err " + e);
			}
		}


		String issuer = payload.optString("iss");

		selfCheck2(jwt, jwks, alg, issuer);
	}

	public static void selfCheck2(
			String jwt, JWKSet jwkSet, String alg, String issuer)
		throws Exception {

		try {
			doSelfCheck(jwt, jwkSet, alg, issuer);
		}
		catch (Exception e) {
			logger.debug(
				"%s for jwt=%s :jwkSet=%s :alg=%s :issuer=%s", e, jwt, jwkSet,
				alg, issuer);

			throw e;
		}
	}

	private static JWSVerifier getJWSVerifier(JWSAlgorithm alg, JWK jwk)
		throws Exception {

		if (RSASSAVerifier.SUPPORTED_ALGORITHMS.contains(alg)) {
			if (!KeyType.RSA.equals(jwk.getKeyType())) {
				throw new Exception("Not RSA key " + jwk.toString());
			}

			RSAKey rsaKey = (RSAKey)jwk;

			PublicKey publicKey = rsaKey.toPublicKey();

			return new RSASSAVerifier((RSAPublicKey)publicKey);
		}

		throw new Exception("Unsupported alg " + alg);
	}

	private static void doSelfCheck(
			String jwt, JWKSet jwkSet, String alg, String issuer)
		throws Exception {

		// Create a JWT processor for the access tokens
		ConfigurableJWTProcessor<SecurityContext> jwtProcessor =
			new DefaultJWTProcessor<>();

		// Set the required "typ" header "at+jwt" for access tokens issued by the
		// Connect2id server, may not be set by other servers
		jwtProcessor.setJWSTypeVerifier(
			new DefaultJOSEObjectTypeVerifier<>(
				new JOSEObjectType("entity-statement+jwt")));

		// The public RSA keys to validate the signatures will be sourced from the
		// OAuth 2.0 server's JWK set, published at a well-known URL. The RemoteJWKSet
		// object caches the retrieved keys to speed up subsequent look-ups and can
		// also handle key-rollover
		JWKSource<SecurityContext> keySource =
			new ImmutableJWKSet<SecurityContext>(jwkSet);
			//new RemoteJWKSet<>(new URL("https://demo.c2id.com/jwks.json"));

		// The expected JWS algorithm of the access tokens (agreed out-of-band)
		JWSAlgorithm expectedJWSAlg = JWSAlgorithm.parse(alg);

		// Configure the JWT processor with a key selector to feed matching public
		// RSA keys sourced from the JWK set URL
		JWSKeySelector<SecurityContext> keySelector =
			new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);

		jwtProcessor.setJWSKeySelector(keySelector);

		// Set the required JWT claims for access tokens issued by the Connect2id
		// server, may differ with other servers
		jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
			new JWTClaimsSet.Builder().issuer(issuer).build(),
			new HashSet<>(Arrays.asList("sub", "iat", "exp"))));

		// Process the token
		SecurityContext ctx = null; // optional context parameter, not required here
		JWTClaimsSet claimsSet = jwtProcessor.process(jwt, ctx);
	}

	/**
	 * Get the JSON Web Key (JWK) set from the provided payload, or null if
	 * not present
	 *
	 * @param payload
	 * @return
	 * @throws ParseException
	 */
	private static JWKSet getJWKSet(JSONObject payload) throws ParseException {
		JSONObject jwks = payload.optJSONObject("jwks");

		if (jwks != null) {
			return JWKSet.parse(jwks.toMap());
		}

		return null;
	}

	private static final Logger logger = LoggerFactory.getLogger(
		JWTHelper.class);

	private static JWSVerifierFactory jwsVerifierFactory =
		new DefaultJWSVerifierFactory();

}
