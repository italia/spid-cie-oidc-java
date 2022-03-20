package it.spid.cie.oidc.relying.party.helper;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import org.json.JSONObject;

public class PKCEHelper {

	public static JSONObject getPKCE() {
		try {
			String codeVerifier = generateCodeVerifier();
			String codeChallenge = generateCodeChallange(codeVerifier);

			return new JSONObject()
				.put("code_verifier", codeVerifier)
				.put("code_challenge", codeChallenge)
				.put("code_challenge_method", "S256");
		}
		catch (Exception e) {
			return new JSONObject();
		}
	}

	private static String generateCodeVerifier() throws UnsupportedEncodingException {
		SecureRandom secureRandom = new SecureRandom();

		byte[] codeVerifier = new byte[32];

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
