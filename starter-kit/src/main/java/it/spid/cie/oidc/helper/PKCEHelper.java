package it.spid.cie.oidc.helper;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import org.json.JSONObject;

public class PKCEHelper {

	// TODO: Needed? public static final int CODE_CHALLENGE_LENGTH = 64;
	public static final String CODE_CHALLENGE_METHOD = "S256";
	public static final int CODE_VERIFIER_LENGTH = 40;

	public static JSONObject getPKCE() {
		try {
			String codeVerifier = generateCodeVerifier();
			String codeChallenge = generateCodeChallange(codeVerifier);

			return new JSONObject()
				.put("code_verifier", codeVerifier)
				.put("code_challenge", codeChallenge)
				.put("code_challenge_method", CODE_CHALLENGE_METHOD);
		}
		catch (Exception e) {
			return new JSONObject();
		}
	}

	private static String generateCodeVerifier() {
		SecureRandom secureRandom = new SecureRandom();

		byte[] codeVerifier = new byte[CODE_VERIFIER_LENGTH];

		secureRandom.nextBytes(codeVerifier);

		return Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier);
	}

	private static String generateCodeChallange(String codeVerifier)
		throws UnsupportedEncodingException, NoSuchAlgorithmException {

		byte[] bytes = codeVerifier.getBytes("US-ASCII");

		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

		messageDigest.update(bytes, 0, bytes.length);

		byte[] digest = messageDigest.digest();

		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

}
