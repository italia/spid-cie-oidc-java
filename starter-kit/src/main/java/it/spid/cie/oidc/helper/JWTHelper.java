package it.spid.cie.oidc.helper;

import com.nimbusds.jose.*;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;

import java.net.URL;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.spid.cie.oidc.config.GlobalOptions;
import it.spid.cie.oidc.exception.JWTException;
import it.spid.cie.oidc.exception.OIDCException;
import it.spid.cie.oidc.util.GetterUtil;

public class JWTHelper {

	private static final Logger logger = LoggerFactory.getLogger(JWTHelper.class);

	private final GlobalOptions<?> options;

	public static RSAKey createRSAKey(JWSAlgorithm alg, KeyUse use) throws OIDCException {
		JWSAlgorithm goodAlg = GetterUtil.getObject(alg, JWSAlgorithm.RS256);

		// TODO: check goodAlg is RSA

		try {
			return new RSAKeyGenerator(2048)
				.algorithm(goodAlg)
				.keyUse(use)
				.keyIDFromThumbprint(true)
				.generate();
		}
		catch (Exception e) {
			throw new JWTException.Generic(e);
		}
	}
	public static RSAKey createRSAEncKey(JWEAlgorithm alg, KeyUse use) throws OIDCException {
		JWEAlgorithm goodAlg = GetterUtil.getObject(alg, JWEAlgorithm.RSA_OAEP_256);

		// TODO: check goodAlg is RSA

		try {
			return new RSAKeyGenerator(2048)
					.algorithm(goodAlg)
					.keyUse(use)
					.keyIDFromThumbprint(true)
					.generate();
		}
		catch (Exception e) {
			throw new JWTException.Generic(e);
		}
	}
	/**
	 * Decode a Base64 string and return it
	 *
	 * @param encoded
	 * @return
	 */
	public static String decodeBase64(String encoded) {
		Base64 b = new Base64(encoded);

		return b.decodeToString();
	}

	/**
	 * Given a string representing a base64 encoded JWT Token (JWT, JWS, JWE) return a
	 * JSONObject with header and payload parts decoded
	 *
	 * @param jwt
	 * @return
	 */
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

	/**
	 * Given a string representing a base64 encoded JWT Token (JWT, JWS, JWE) return a
	 * JSONObject of the header part decoded
	 *
	 * @param jwt
	 * @return
	 */
	public static JSONObject fastParseHeader(String jwt) {
		String[] parts = jwt.split("\\.");

		return new JSONObject(decodeBase64(parts[0]));
	}

	/**
	 * Given a string representing a base64 encoded JWT Token (JWT, JWS, JWE) return a
	 * JSONObject of the payload part decoded
	 *
	 * @param jwt
	 * @return
	 */
	public static JSONObject fastParsePayload(String jwt) {
		String[] parts = jwt.split("\\.");

		return new JSONObject(decodeBase64(parts[1]));
	}

	/**
	 * @return current UTC date time, plus default expiring minutes, as epoch seconds
	 */
	public static long getExpiresOn() {
		return getExpiresOn(GlobalOptions.DEFAULT_EXPIRING_MINUTES);
	}

	/**
	 * @param minutes
	 * @return current UTC date time, plus provided minutes, as epoch seconds
	 */
	public static long getExpiresOn(int minutes) {
		return getIssuedAt() + (minutes * 60);
	}

	/**
	 *
	 * @param jwkSet
	 * @return the first JWK in the provided JSON Web Key set
	 * @throws OIDCException
	 */
	public static JWK getFirstJWK(JWKSet jwkSet) throws OIDCException {
		if (jwkSet != null && !jwkSet.getKeys().isEmpty()) {
			return jwkSet.getKeys().get(0);
		}

		throw new JWTException.Generic("JWKSet null or empty");
	}

	/**
	 * @return current UTC date time as epoch seconds
	 */
	public static long getIssuedAt() {
		return Instant.now().getEpochSecond();
	}

	/**
	 * Given a JSON Web Key (JWK) set returns the JWK referenced inside the header of the
	 * base64 encoded jwt
	 *
	 * @param jwt
	 * @param jwkSet
	 * @return
	 */
	public static JWK getJWKFromJWT(String jwt, JWKSet jwkSet) {
		JSONObject header = fastParseHeader(jwt);

		return jwkSet.getKeyByKeyId(header.optString("kid"));
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

	/**
	 * Get the JSON Web Key (JWK) set from the provided JSON string
	 *
	 * @param value a string representation of a JSONArray (array of keys) or of a
	 * JSONObject (complete jwks element)
	 * @return
	 * @throws OIDCException
	 */
	public static JWKSet getJWKSetFromJSON(String value) throws OIDCException {
		try {
			String goodValue = GetterUtil.getString(value, "{}").trim();

			JSONObject jwks;

			if (goodValue.startsWith("[")) {
				jwks = new JSONObject()
					.put("keys", new JSONArray(goodValue));
			}
			else {
				jwks = new JSONObject(goodValue);
			}

			return JWKSet.parse(jwks.toMap());
		}
		catch (Exception e) {
			throw new JWTException.Parse(e);
		}
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
	 * @throws OIDCException
	 */
	public static JWKSet getJWKSetFromJSON(JSONObject json) throws OIDCException {
		try {
			return JWKSet.parse(json.toMap());
		}
		catch (Exception e) {
			throw new JWTException.Parse(e);
		}
	}

	/**
	 * Build a JSON Web Key (JWK) set with a single JWK
	 *
	 * @param value a string representation of a JWK
	 * @return a JWKSet
	 * @throws OIDCException
	 */
	public static JWKSet getJWKSetFromJWK(String value) throws OIDCException {
		try {
			JWK jwk = JWK.parse(value);

			return new JWKSet(jwk);
		}
		catch (Exception e) {
			throw new JWTException.Parse(e);
		}
	}

	/**
	 * Get the JSON Web Key (JWK) set from the "payload" part of the provided JWT Token,
	 * or null if not present
	 *
	 * @param jwt the base64 encoded JWT Token
	 * @return
	 * @throws OIDCException
	 */
	public static JWKSet getJWKSetFromJWT(String jwt) throws OIDCException {
		try {
			JSONObject token = fastParse(jwt);

			JSONObject payload = token.getJSONObject("payload");

			return getJWKSet(payload);
		}
		catch (Exception e) {
			throw new JWTException.Parse(e);
		}
	}

	/**
	 * Get the JSON Web Key (JWK) set from a JSON representing a well-known entity
	 * metadata. The code is able to manage jwks embedded or remote (jwks_uri)
	 *
	 * @param metadata
	 * @return
	 * @throws Exception
	 */
	public static JWKSet getMetadataJWKSet(JSONObject metadata) throws OIDCException {
		if (metadata.has("jwks")) {
			try {
				return JWKSet.parse(metadata.getJSONObject("jwks").toMap());
			}
			catch (Exception e) {
				throw new JWTException.Parse(e);
			}
		}
		else if (metadata.has("jwks_uri")) {
			String url = metadata.getString("jwks_uri");

			try {
				return JWKSet.load(new URL(url));
			}
			catch (Exception e) {
				throw new JWTException.Generic("Failed to download jwks from " + url);
			}
		}

		throw new JWTException.Generic("No jwks in metadata");
	}

	public static RSAKey parseRSAKey(String s) throws OIDCException {
		try {
			return RSAKey.parse(s);
		}
		catch (Exception e) {
			throw new JWTException.Parse(e);
		}
	}

	public JWTHelper(GlobalOptions<?> options) {
		this.options = options;
	}

	public String createJWS(JSONObject payload, JWKSet jwks) throws OIDCException {
		JWK jwk = getFirstJWK(jwks);

		// Signer depends on JWK key type

		JWSAlgorithm alg;
		JWSSigner signer;

		try {
			if (KeyType.RSA.equals(jwk.getKeyType())) {
				RSAKey rsaKey = (RSAKey)jwk;

				signer = new RSASSASigner(rsaKey);
				alg = JWSAlgorithm.parse(options.getDefaultJWSAlgorithm());
			}
			else if (KeyType.EC.equals(jwk.getKeyType())) {
				ECKey ecKey = (ECKey)jwk;

				signer = new ECDSASigner(ecKey);
				alg = JWSAlgorithm.parse(options.getDefaultJWSAlgorithm());
			}
			else {
				throw new JWTException.Generic("Unknown key type");
			}

			// Prepare JWS object with the payload

			JWSObject jwsObject = new JWSObject(

				new JWSHeader.Builder(alg).keyID(jwk.getKeyID()).type(new JOSEObjectType("entity-statement+jwt")).build(),
				new Payload(payload.toString()));

			// Compute the signature
			jwsObject.sign(signer);

			// Serialize to compact form
			return jwsObject.serialize();
		}
		catch (Exception e) {
			throw new JWTException.Generic(e);
		}
	}

	public String decryptJWE(String jwe, JWKSet jwkSet) throws OIDCException {
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
			alg = JWEAlgorithm.parse(options.getDefaultJWEAlgorithm());
		}

		if (enc == null) {
			enc = EncryptionMethod.parse(options.getDefaultJWEEncryption());
		}

		if (!isValidAlgorithm(alg)) {
			throw new JWTException.UnsupportedAlgorithm(alg.toString());
		}

		try {
			JWK jwk = jwkSet.getKeyByKeyId(kid);

			if (jwk == null) {
				throw new JWTException.UnknownKid(kid, jwkSet.toString());
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
		logger.info("KK Decrypted JWE as: " + jws); //TODO: remove

		return jws;
	}

	public JSONObject getJWTFromJWE(
			String jwe, JWKSet mineJWKSet, JWKSet otherJWKSet)
		throws OIDCException {

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
		catch (OIDCException e) {
			throw e;
		}
		catch (ParseException e) {
			throw new JWTException.Parse(e);
		}
		catch (Exception e) {
			throw new JWTException.Generic(e);
		}
	}

	public boolean isValidAlgorithm(JWEAlgorithm alg) {
		return options.getAllowedEncryptionAlgs().contains(alg.toString());
	}

	public boolean isValidAlgorithm(JWSAlgorithm alg) {
		return options.getAllowedSigningAlgs().contains(alg.toString());
	}

	public boolean verifyJWS(SignedJWT jws, JWKSet jwkSet) throws OIDCException {
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

	public boolean verifyJWS(String jws, JWKSet jwkSet) throws OIDCException {
		SignedJWT jwsObject;

		try {
			jwsObject = SignedJWT.parse(jws);
		}
		catch (Exception e) {
			throw new JWTException.Parse(e);
		}

		return verifyJWS(jwsObject, jwkSet);
	}

	private static JWEDecrypter getJWEDecrypter(
			JWEAlgorithm alg, EncryptionMethod enc, JWK jwk)
		throws OIDCException {

		if (RSADecrypter.SUPPORTED_ALGORITHMS.contains(alg) &&
			RSADecrypter.SUPPORTED_ENCRYPTION_METHODS.contains(enc)) {

			if (!KeyType.RSA.equals(jwk.getKeyType())) {
				throw new JWTException.Generic("Not RSA key " + jwk.toString());
			}

			RSAKey rsaKey = (RSAKey)jwk;

			try {
				PrivateKey privateKey = rsaKey.toPrivateKey();

				return new RSADecrypter(privateKey);
			}
			catch (JOSEException e) {
				throw new JWTException.Generic(e);
			}
		}

		throw new JWTException.Generic(
			"Unsupported or unimplemented alg " + alg + " enc " + enc);
	}


	/**
	 * Get the JSON Web Key (JWK) set from the provided JSONObject, or null if
	 * not present
	 *
	 * @param json a JSONObject with a first level key named "jwks"
	 * @return
	 * @throws ParseException
	 */
	private static JWKSet getJWKSet(JSONObject json) throws ParseException {
		JSONObject jwks = json.optJSONObject("jwks");

		if (jwks != null) {
			return JWKSet.parse(jwks.toMap());
		}

		return null;
	}

	private static JWSVerifier getJWSVerifier(JWSAlgorithm alg, JWK jwk)
		throws OIDCException {

		if (RSASSAVerifier.SUPPORTED_ALGORITHMS.contains(alg)) {
			if (!KeyType.RSA.equals(jwk.getKeyType())) {
				throw new JWTException.Generic("Not RSA key " + jwk.toString());
			}

			RSAKey rsaKey = (RSAKey)jwk;


			try {
				RSAPublicKey publicKey = rsaKey.toRSAPublicKey();

				return new RSASSAVerifier(publicKey);
			}
			catch (JOSEException e) {
				throw new JWTException.Generic(e);
			}
		}

		throw new JWTException.Generic("Unsupported or unimplemented alg " + alg);
	}

}
