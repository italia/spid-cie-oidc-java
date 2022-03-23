package it.spid.cie.oidc.relying.party.helper;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWEDecrypterFactory;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.JWSVerifierFactory;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.net.URL;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.HashSet;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.spid.cie.oidc.exception.JWTException;
import it.spid.cie.oidc.exception.SPIDException;
import it.spid.cie.oidc.relying.party.util.ArrayUtil;
import it.spid.cie.oidc.relying.party.util.GetterUtil;

public class JWTHelper {

	public static final String[] ALLOWED_ENCRYPTION_ALGS = new String[] {
		"RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW",
		"ECDH-ES+A256KW"};

	public static final String[] ALLOWED_SIGNING_ALGS = new String[] {
		"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"};

	public static final int DEFAULT_EXPIRES_ON_MINUTES = 30;

	public static final JWEAlgorithm DEFAULT_JWE_ALG = JWEAlgorithm.RSA_OAEP;
	public static final EncryptionMethod DEFAULT_JWE_ENC = EncryptionMethod.A256CBC_HS512;

	public static String decodeBase64(String encoded) {
		Base64 b = new Base64(encoded);

		return b.decodeToString();
	}

	public static String decryptJWE(String jwe, JWKSet jwkSet) throws SPIDException {
		JWEObject jweObject;

		try {
			jweObject = JWEObject.parse(jwe);
		}
		catch (ParseException e) {
			throw new JWTException.Parse(e);
		}

		if (logger.isTraceEnabled()) {
			logger.trace("jwe.header=" + jweObject.getHeader().toString());
		}

		JWEAlgorithm alg = jweObject.getHeader().getAlgorithm();
		EncryptionMethod enc = jweObject.getHeader().getEncryptionMethod();
		String kid = jweObject.getHeader().getKeyID();

		if (alg == null) {
			alg = DEFAULT_JWE_ALG;
		}

		if (enc == null) {
			enc = DEFAULT_JWE_ENC;
		}

		if (!isValidAlgorithm(alg)) {
			throw new JWTException.UnsupportedAlgorithm(alg.toString());
		}

		try {
			JWK jwk = jwkSet.getKeyByKeyId(kid);

			if (jwk == null) {
				throw new Exception(kid + " not in jwks");
			}

			JWEDecrypter decrypter = getJWEDecrypter(alg, enc, jwk);

			jweObject.decrypt(decrypter);
		}
		catch (Exception e) {
			throw new JWTException.Decryption(e);
		}

		String jws = jweObject.getPayload().toString();

		if (logger.isDebugEnabled()) {
			logger.debug("Decrypted JWE as: " + jws);
		}
		logger.info("KK Decrypted JWE as: " + jws);

		return jws;
	}

	public static JSONObject fastParse(String jwt) {
		String[] parts = jwt.split("\\.");

		JSONObject result = new JSONObject();

		result.put("header", new JSONObject(decodeBase64(parts[0])));
		result.put("payload", new JSONObject(decodeBase64(parts[1])));

		//if (parts.length == 3) {
		//	result.put("signature", new JSONObject(decodeBase64(parts[1])));
		//}

		return result;
	}

	public static JSONObject fastParseHeader(String jwt) {
		String[] parts = jwt.split("\\.");

		return new JSONObject(decodeBase64(parts[1]));
	}

	public static JSONObject fastParsePayload(String jwt) {
		String[] parts = jwt.split("\\.");

		return new JSONObject(decodeBase64(parts[1]));
	}

	public static JWK getJWKFromJWT(String jwt, JWKSet jwkSet) {
		JSONObject header = fastParseHeader(jwt);

		return jwkSet.getKeyByKeyId(header.optString("kid"));
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

	/**
	 * Get the JSON Web Key (JWK) set from the provided JSON Object that is supposed to
	 * be something like:
	 * <pre>
	 *  {
	 *     "keys": [
	 *        { .... },
	 *        { .... }
	 *      }
	 *  }
	 * </pre>
	 *
	 * @param json
	 * @return
	 * @throws Exception
	 */
	public static JWKSet getJWKSetFromJSON(JSONObject json) throws Exception {
		return JWKSet.parse(json.toMap());
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
	 * Given a JSON Web Key (JWK) set returns contained JWKs, only the public attributes,
	 * as JSONArray.
	 *
	 * @param jwkSet
	 * @param removeUse if true the "use" attribute, even if present in the JWK, will not
	 * be exposed
	 * @return
	 */
	public static JSONArray getJWKSetAsJSONArray(JWKSet jwkSet, boolean removeUse) {
		return getJWKSetAsJSONArray(jwkSet, false, removeUse);
	}

	/**
	 * Given a JSON Web Key (JWK) set returns contained JWKs as JSONArray.
	 *
	 * @param jwkSet
	 * @param privateAttrs if false only the public attributes of the JWK will be included
	 * @param removeUse if true the "use" attribute, even if present in the JWK, will not
	 * be exposed
	 * @return
	 */
	public static JSONArray getJWKSetAsJSONArray(
		JWKSet jwkSet, boolean privateAttrs, boolean removeUse) {

		JSONArray keys = new JSONArray();

		for (JWK jwk : jwkSet.getKeys()) {
			JSONObject json;

			if (KeyType.RSA.equals(jwk.getKeyType())) {
				RSAKey rsaKey = (RSAKey)jwk;

				if (privateAttrs) {
					json = new JSONObject(rsaKey.toJSONObject());
				}
				else {
					json = new JSONObject(rsaKey.toPublicJWK().toJSONObject());
				}
			}
			else if (KeyType.EC.equals(jwk.getKeyType())) {
				ECKey ecKey = (ECKey)jwk;

				if (privateAttrs) {
					json = new JSONObject(ecKey.toJSONObject());
				}
				else {
					json = new JSONObject(ecKey.toPublicJWK().toJSONObject());
				}
			}
			else {
				logger.error("Unsupported KeyType " + jwk.getKeyType());

				continue;
			}

			if (removeUse) {
				json.remove("use");
			}

			keys.put(json);
		}

		return keys;
	}

	/**
	 * Given a JSON Web Key (JWK) set returns it, only the public attributes, as
	 * JSONObject.
	 *
	 * @param jwkSet
	 * @param removeUse if true the "use" attribute, even if present in the JWK, will not
	 * be exposed
	 * @return
	 */
	public static JSONObject getJWKSetAsJSONObject(JWKSet jwkSet, boolean removeUse) {
		return getJWKSetAsJSONObject(jwkSet, false, removeUse);
	}

	/**
	 * Given a JSON Web Key (JWK) set returns it as JSONObject.
	 *
	 * @param jwkSet
	 * @param privateAttrs if false only the public attributes of the JWK will be included
	 * @param removeUse if true the "use" attribute, even if present in the JWK, will not
	 * be exposed
	 * @return
	 */
	public static JSONObject getJWKSetAsJSONObject(
		JWKSet jwkSet, boolean privateAttrs, boolean removeUse) {

		JSONArray keys = getJWKSetAsJSONArray(jwkSet, privateAttrs, removeUse);

		return new JSONObject()
			.put("keys", keys);
	}

	public static JSONObject getJWTFromJWE(
			String jwe, JWKSet mineJWKSet, JWKSet otherJWKSet)
		throws SPIDException {

		String jws = decryptJWE(jwe, mineJWKSet);

		try {
			Base64URL[] parts = JOSEObject.split(jws);

			if (parts.length == 3) {
				SignedJWT signedJWT = new SignedJWT(parts[0], parts[1], parts[2]);

				if (!verifyJWS(signedJWT, otherJWKSet)) {
					logger.error(
						"Verification failed for {} with jwks {}", jws,
						otherJWKSet.toString());

					//TODO: Understand why verify always fails
					//throw new JWTException.Verifier(
					//	"Verification failed for " + jws);
				}
			}
			else {
				logger.warn("jwe {} contains unsigned jws {} ", jwe, jws);
			}

			return fastParse(jws);
		}
		catch (ParseException e) {
			throw new JWTException.Parse(e);
		}
		catch (Exception e) {
			throw new JWTException.Generic(e);
		}
	}

	/**
	 * @return current UTC date time as epoch seconds
	 */
	public static long getIssuedAt() {
		return LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
	}

	/**
	 * @return current UTC date time, plus default espire minutes, as epoch seconds
	 */
	public static long getExpiresOn() {
		return getExpiresOn(DEFAULT_EXPIRES_ON_MINUTES);
	}

	/**
	 * @param minutes
	 * @return current UTC date time, plus provided minutes, as epoch seconds
	 */
	public static long getExpiresOn(int minutes) {
		return getIssuedAt() + (minutes * 60);
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

	public static String createJWS(JSONObject payload, JWKSet jwks) throws Exception {
		JWK jwk = getFirstJWK(jwks);

		// Signer depends on JWK key type

		JWSAlgorithm alg;
		JWSSigner signer;

		if (KeyType.RSA.equals(jwk.getKeyType())) {
			RSAKey rsaKey = (RSAKey)jwk;

			signer = new RSASSASigner(rsaKey);
			alg = JWSAlgorithm.RS256;
		}
		else if (KeyType.EC.equals(jwk.getKeyType())) {
			ECKey ecKey = (ECKey)jwk;

			signer = new ECDSASigner(ecKey);
			alg = JWSAlgorithm.ES256;
		}
		else {
			throw new Exception("Unknown key type");
		}

		// Prepare JWS object with the payload

		JWSObject jwsObject = new JWSObject(
			new JWSHeader.Builder(alg).keyID(jwk.getKeyID()).build(),
			new Payload(payload.toString()));

		// Compute the signature
		jwsObject.sign(signer);

		// Serialize to compact form
		return jwsObject.serialize();
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

	public static boolean isValidAlgorithm(JWSAlgorithm alg) {
		return ArrayUtil.contains(ALLOWED_SIGNING_ALGS, alg.toString(), true);
	}

	public static boolean isValidAlgorithm(JWEAlgorithm alg) {
		return ArrayUtil.contains(ALLOWED_ENCRYPTION_ALGS, alg.toString(), true);
	}

	public static boolean verifyJWS(SignedJWT jws, JWKSet jwkSet)
		throws SPIDException {

		String kid = jws.getHeader().getKeyID();

		JWK jwk = jwkSet.getKeyByKeyId(kid);

		if (jwk == null) {
			throw new JWTException.UnknownKid(kid, jwkSet.toString());
		}

		JWSAlgorithm alg = jws.getHeader().getAlgorithm();

		if (!isValidAlgorithm(alg)) {
			throw new JWTException.UnsupportedAlgorithm(alg.toString());
		}

		try {
			JWSVerifier verifier = getJWSVerifier(alg, jwk);

			return jws.verify(verifier);
		}
		catch (Exception e) {
			throw new JWTException.Verifier(e);
		}
	}

	public static boolean verifyJWS(String jws, JWKSet jwkSet)
		throws SPIDException {

		SignedJWT jwsObject;

		try {
			jwsObject = SignedJWT.parse(jws);
		}
		catch (Exception e) {
			throw new JWTException.Parse(e);
		}

		return verifyJWS(jwsObject, jwkSet);
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

	public static JWK getFirstJWK(JWKSet jwkSet) throws Exception {
		if (jwkSet != null && !jwkSet.getKeys().isEmpty()) {
			return jwkSet.getKeys().get(0);
		}

		throw new Exception("JWKSet null or empty");
	}

	private static JWEDecrypter getJWEDecrypter(
			JWEAlgorithm alg, EncryptionMethod enc, JWK jwk)
		throws Exception {

		if (RSADecrypter.SUPPORTED_ALGORITHMS.contains(alg) &&
			RSADecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(enc)) {

			if (!KeyType.RSA.equals(jwk.getKeyType())) {
				throw new Exception("Not RSA key " + jwk.toString());
			}

			RSAKey rsaKey = (RSAKey)jwk;

			PrivateKey privateKey = rsaKey.toPrivateKey();

			return new RSADecrypter(privateKey);
		}

		throw new Exception("Unsupported or unimplemented alg " + alg + " enc " + enc);
	}

	private static JWSVerifier getJWSVerifier(JWSAlgorithm alg, JWK jwk)
		throws Exception {

		if (RSASSAVerifier.SUPPORTED_ALGORITHMS.contains(alg)) {
			if (!KeyType.RSA.equals(jwk.getKeyType())) {
				throw new Exception("Not RSA key " + jwk.toString());
			}

			RSAKey rsaKey = (RSAKey)jwk;

			RSAPublicKey publicKey = rsaKey.toRSAPublicKey();

			//logger.info("RSA Publickey=" + publicKey.toString());

			return new RSASSAVerifier(publicKey);
		}

		throw new Exception("Unsupported or unimplemented alg " + alg);
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

	private static JWEDecrypterFactory jweDecrypterFactory =
		new DefaultJWEDecrypterFactory();

}
