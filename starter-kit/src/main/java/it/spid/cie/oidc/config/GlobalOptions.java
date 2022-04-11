package it.spid.cie.oidc.config;

import java.util.Collections;
import java.util.Set;

import it.spid.cie.oidc.exception.ConfigException;
import it.spid.cie.oidc.exception.OIDCException;
import it.spid.cie.oidc.util.ArrayUtil;
import it.spid.cie.oidc.util.Validator;

public class GlobalOptions<T extends GlobalOptions<T>> {

	public static final int DEFAULT_EXPIRING_MINUTES = 30;

	public static final String DEFAULT_SIGNING_ALG = "RS256";

	public static final String[] SUPPORTED_ENCRYPTION_ENCODINGS = new String[] {
		"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM",
		"A256GCM"};

	public static final String[] SUPPORTED_ENCRYPTION_ALGS = new String[] {
		"RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW",
		"ECDH-ES+A256KW"};

	public static final String[] SUPPORTED_SIGNING_ALGS = new String[] {
		"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"};

	private String jweDefaultAlgorithm = "RSA-OAEP";
	private String jweDefaultEncryption = "A256CBC-HS512";
	private String jwsDefaultAlgorithm = "RS256";
	private Set<String> allowedSigningAlgs = ArrayUtil.asSet(
		"RS256", "RS384", "RS512", "ES256", "ES384", "ES512");
	private Set<String> allowedEncryptionAlgs = ArrayUtil.asSet(
		"RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW",
		"ECDH-ES+A256KW");

	public int getDefaultExpiringMinutes() {
		return DEFAULT_EXPIRING_MINUTES;
	}

	public String getDefaultJWEAlgorithm() {
		return jweDefaultAlgorithm;
	}

	public String getDefaultJWEEncryption() {
		return jweDefaultEncryption;
	}

	public String getDefaultJWSAlgorithm() {
		return jwsDefaultAlgorithm;
	}

	public Set<String> getAllowedEncryptionAlgs() {
		return Collections.unmodifiableSet(allowedEncryptionAlgs);
	}

	public Set<String> getAllowedSigningAlgs() {
		return Collections.unmodifiableSet(allowedSigningAlgs);
	}

	@SuppressWarnings("unchecked")
	public T setAllowedEncryptionAlgs(String... values) {
		if (values.length > 0) {
			allowedEncryptionAlgs = ArrayUtil.asSet(values);
		}

		return (T)this;
	}

	@SuppressWarnings("unchecked")
	public T setAllowedSigningAlgs(String... values) {
		if (values.length > 0) {
			allowedSigningAlgs = ArrayUtil.asSet(values);
		}

		return (T)this;
	}

	@SuppressWarnings("unchecked")
	public T setDefaultJWEAlgorithm(String algorithm) {
		if (!Validator.isNullOrEmpty(algorithm)) {
			jweDefaultAlgorithm = algorithm;
		}

		return (T)this;
	}

	@SuppressWarnings("unchecked")
	public T setDefaultJWEEncryption(String encMethod) {
		if (!Validator.isNullOrEmpty(encMethod)) {
			jweDefaultEncryption = encMethod;
		}

		return (T)this;
	}

	@SuppressWarnings("unchecked")
	public T setDefaultJWSAlgorithm(String algorithm) {
		if (!Validator.isNullOrEmpty(algorithm)) {
			jwsDefaultAlgorithm = algorithm;
		}

		return (T)this;
	}

	protected void validate() throws OIDCException {
		for (String alg : allowedEncryptionAlgs) {
			if (!ArrayUtil.contains(SUPPORTED_ENCRYPTION_ALGS, alg)) {
				throw new ConfigException(
					"allowedEncryptionAlg %s is not supported", alg);
			}
		}

		if (!allowedEncryptionAlgs.contains(jweDefaultAlgorithm)) {
			throw new ConfigException(
				"Not allowed jweDefaultAlgorithm %s", jweDefaultAlgorithm);
		}

		if (!allowedSigningAlgs.contains(jwsDefaultAlgorithm)) {
			throw new ConfigException(
				"Not allowed jwsDefaultAlgorithm %s", jwsDefaultAlgorithm);
		}

	}

}
