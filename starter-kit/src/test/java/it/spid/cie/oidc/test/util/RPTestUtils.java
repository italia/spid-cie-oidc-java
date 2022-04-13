package it.spid.cie.oidc.test.util;

import java.io.File;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

import it.spid.cie.oidc.config.RelyingPartyOptions;
import it.spid.cie.oidc.helper.JWTHelper;
import it.spid.cie.oidc.util.ArrayUtil;
import it.spid.cie.oidc.util.JSONUtil;

public class RPTestUtils extends TestUtils {

	public static String TRUST_ANCHOR = "http://127.0.0.1:18000/";
	public static String SPID_PROVIDER = "http://127.0.0.1:18000/oidc/op/";
	public static String RELYING_PARTY = "http://127.0.0.1:18080/oidc/rp/";

	public static String createJWS(JSONObject payload, JSONObject jwks)
		throws Exception {

		JWKSet jwkSet = JWKSet.parse(jwks.toString());

		JWK jwk = JWTHelper.getFirstJWK(jwkSet);

		RSAKey rsaKey = (RSAKey)jwk;

		JWSSigner signer = new RSASSASigner(rsaKey);
		JWSAlgorithm alg = JWSAlgorithm.RS256;

		// Prepare JWS object with the payload

		JWSObject jwsObject = new JWSObject(
			new JWSHeader.Builder(alg).keyID(jwk.getKeyID()).build(),
			new Payload(payload.toString()));

		// Compute the signature
		jwsObject.sign(signer);

		// Serialize to compact form
		return jwsObject.serialize();
	}

	public static RelyingPartyOptions getOptions() throws Exception {
		Map<String, String> spidProviders = new HashMap<>();

		spidProviders.put(SPID_PROVIDER, TRUST_ANCHOR);

		RelyingPartyOptions options = new RelyingPartyOptions()
			.setDefaultTrustAnchor(TRUST_ANCHOR)
			.setClientId(RELYING_PARTY)
			.setSPIDProviders(spidProviders)
			.setTrustAnchors(ArrayUtil.asSet(TRUST_ANCHOR))
			.setApplicationName("JUnit RP")
			.setRedirectUris(ArrayUtil.asSet(RELYING_PARTY + "callback"))
			.setJWK(getContent("rp-jwks.json"))
			.setTrustMarks(getContent("rp-trust-marks.json"));

		return options;
	}

	public static String mockedSPIDProviderEntityConfiguration() throws Exception {
		JSONObject payload = new JSONObject()
			.put("iat", makeIssuedAt())
			.put("exp", makeExpiresOn())
			.put("iss", SPID_PROVIDER)
			.put("sub", SPID_PROVIDER)
			.put("jwks", mockedSPIDProviderPublicJWKS())
			.put("authority_hints", JSONUtil.asJSONArray(TRUST_ANCHOR));

		JSONObject providerMetadata = new JSONObject()
			.put("authorization_endpoint", SPID_PROVIDER + "authorization")
			.put("revocation_endpoint", SPID_PROVIDER + "revocation/")
			.put(
				"id_token_encryption_alg_values_supported",
				JSONUtil.asJSONArray("RSA-OAEP"))
			.put(
				"id_token_encryption_enc_values_supported",
				JSONUtil.asJSONArray("A128CBC-HS256"))
			.put("op_name", "Agenzia per Italia Digitale")
			.put("op_uri", "https://www.agid.gov.it")
			.put("token_endpoint", SPID_PROVIDER + "token/")
			.put("userinfo_endpoint", SPID_PROVIDER + "introspection/")
			.put("claims_parameter_supported", true)
			.put("contacts", JSONUtil.asJSONArray("ops@https://idp.it"))
			.put("client_registration_types_supported", JSONUtil.asJSONArray("automatic"))
			.put("code_challenge_methods_supported", JSONUtil.asJSONArray("S256"))
			.put(
				"request_authentication_methods_supported",
				new JSONObject().put("ar", JSONUtil.asJSONArray("request_object")))
			.put(
				"acr_values_supported", JSONUtil.asJSONArray(
					"https://www.spid.gov.it/SpidL1", "https://www.spid.gov.it/SpidL2",
					"https://www.spid.gov.it/SpidL3"))
			.put(
				"claims_supported", JSONUtil.asJSONArray(
					"https://attributes.spid.gov.it/spidCode",
					"https://attributes.spid.gov.it/name",
					"https://attributes.spid.gov.it/familyName",
					"https://attributes.spid.gov.it/placeOfBirth",
					"https://attributes.spid.gov.it/countyOfBirth",
					"https://attributes.spid.gov.it/dateOfBirth",
					"https://attributes.spid.gov.it/gender",
					"https://attributes.spid.gov.it/companyName",
					"https://attributes.spid.gov.it/registeredOffice",
					"https://attributes.spid.gov.it/fiscalNumber",
					"https://attributes.spid.gov.it/ivaCode",
					"https://attributes.spid.gov.it/idCard",
					"https://attributes.spid.gov.it/mobilePhone",
					"https://attributes.spid.gov.it/email",
					"https://attributes.spid.gov.it/address",
					"https://attributes.spid.gov.it/expirationDate",
					"https://attributes.spid.gov.it/digitalAddress"))
			.put(
				"grant_types_supported", JSONUtil.asJSONArray(
					"authorization_code", "refresh_token"))
			.put(
				"id_token_signing_alg_values_supported", JSONUtil.asJSONArray(
					"RS256", "ES256"))
			.put("issuer", SPID_PROVIDER)
			.put("jwks", mockedSPIDProviderPublicJWKS())
			.put("scopes_supported", JSONUtil.asJSONArray("openid", "offline_access"))
			.put("logo_uri", "http://127.0.0.1:8000/static/svg/spid-logo-c-lb.svg")
			.put("organization_name", "SPID OIDC identity provider")
			.put(
				"op_policy_uri",
				"http://127.0.0.1:8000/oidc/op/en/website/legal-information/")
			.put("request_parameter_supported", true)
			.put("request_uri_parameter_supported", true)
			.put("require_request_uri_registration", true)
			.put("response_types_supported", JSONUtil.asJSONArray("code"))
			.put("subject_types_supported", JSONUtil.asJSONArray("pairwise", "public"))
			.put(
				"token_endpoint_auth_methods_supported", JSONUtil.asJSONArray(
					"private_key_jwt"))
			.put(
				"token_endpoint_auth_signing_alg_values_supported", JSONUtil.asJSONArray(
					"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"))
			.put(
				"userinfo_encryption_alg_values_supported", JSONUtil.asJSONArray(
					"RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW",
					"ECDH-ES+A192KW", "ECDH-ES+A256KW"))
			.put(
				"userinfo_encryption_enc_values_supported", JSONUtil.asJSONArray(
					"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM",
					"A192GCM", "A256GCM"))
			.put(
				"userinfo_signing_alg_values_supported", JSONUtil.asJSONArray(
					"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"))
			.put(
				"request_object_encryption_alg_values_supported", JSONUtil.asJSONArray(
					"RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW",
					"ECDH-ES+A192KW", "ECDH-ES+A256KW"))
			.put(
				"request_object_encryption_enc_values_supported", JSONUtil.asJSONArray(
					"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM",
					"A192GCM", "A256GCM"))
			.put("request_object_signing_alg_values_supported", JSONUtil.asJSONArray(
				"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"));


		JSONObject metadata = new JSONObject()
			.put("openid_provider", providerMetadata);

		payload.put("metadata", metadata);

		JSONObject jwks = mockedSPIDProviderPrivateJWKS();

		return createJWS(payload, jwks);
	}

	public static String mockedSPIDProviderEntityStatement() throws Exception {
		JSONObject payload = new JSONObject()
			.put("iat", makeIssuedAt())
			.put("exp", makeExpiresOn())
			.put("iss", TRUST_ANCHOR)
			.put("sub", SPID_PROVIDER)
			.put("jwks", mockedSPIDProviderPublicJWKS());

		JSONObject providerPolicy = new JSONObject()
			.put(
				"subject_types_supported", new JSONObject()
					.put("value", JSONUtil.asJSONArray("pairwise")))
			.put(
				"id_token_signing_alg_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"RS256", "RS384", "RS512", "ES256", "ES384", "ES512")))
			.put(
				"userinfo_signing_alg_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"RS256", "RS384", "RS512", "ES256", "ES384", "ES512")))
			.put(
				"token_endpoint_auth_methods_supported", new JSONObject()
					.put("value", JSONUtil.asJSONArray("private_key_jwt")))
			.put(
				"userinfo_encryption_alg_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW",
							"ECDH-ES+A192KW", "ECDH-ES+A256KW")))
			.put(
				"userinfo_encryption_enc_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM",
							"A192GCM", "A256GCM")))
			.put(
				"request_object_encryption_alg_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW",
							"ECDH-ES+A192KW", "ECDH-ES+A256KW")))
			.put(
				"request_object_encryption_enc_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM",
							"A192GCM", "A256GCM")))
			.put(
				"request_object_signing_alg_values_supported", new JSONObject()
					.put(
						"subset_of", JSONUtil.asJSONArray(
							"RS256", "RS384", "RS512", "ES256", "ES384", "ES512")));

		payload.put(
			"metadata_policy", new JSONObject().put("openid_provider", providerPolicy));

		JSONArray trustMarks = new JSONArray(getContent("spid-op-trust-marks.json"));

		payload.put("trust_marks", trustMarks);

		JSONObject jwks = mockedSPIDProviderPrivateJWKS();

		return createJWS(payload, jwks);
	}

	public static JSONObject mockedSPIDProviderPublicJWKS() throws Exception {
		return new JSONObject(getContent("spid-op-public-jwks.json"));
	}

	public static JSONObject mockedSPIDProviderPrivateJWKS() throws Exception {
		return new JSONObject(getContent("spid-op-private-jwks.json"));
	}

	public static String mockedTrustAnchorEntityConfiguration() throws Exception {
		JSONObject payload = new JSONObject()
			.put("iat", makeIssuedAt())
			.put("exp", makeExpiresOn())
			.put("iss", TRUST_ANCHOR)
			.put("sub", TRUST_ANCHOR)
			.put("jwks", mockedTrustAnchorPublicJWKS());

		JSONObject trustAnchorMetadata = new JSONObject()
			.put("contacts", JSONUtil.asJSONArray("ta@localhost"))
			.put("federation_fetch_endpoint", TRUST_ANCHOR + "fetch/")
			.put("federation_resolve_endpoint", TRUST_ANCHOR + "resolve/")
			.put("federation_status_endpoint", TRUST_ANCHOR + "trust_mask_status/")
			.put("homepage_uri", TRUST_ANCHOR)
			.put("name", "example TA")
			.put("federation_list_endpoint", TRUST_ANCHOR + "list/");

		payload.put(
			"metadata", new JSONObject().put("federation_entity", trustAnchorMetadata));

		JSONObject trustMarksIssuers = new JSONObject()
			.put(
				"https://www.spid.gov.it/certification/rp/public", JSONUtil.asJSONArray(
					"https://registry.spid.agid.gov.it",
					"https://public.intermediary.spid.it"))
			.put(
				"https://www.spid.gov.it/certification/rp/private", JSONUtil.asJSONArray(
					"https://registry.spid.agid.gov.it",
					"https://private.other.intermediary.it"))
			.put(
				"https://sgd.aa.it/onboarding", JSONUtil.asJSONArray(
					"https://sgd.aa.it"));

		payload.put("trust_marks_issuers", trustMarksIssuers);
		payload.put("constraints", new JSONObject().put("max_path_length", 1));

		JSONObject jwks = mockedTrustAnchorPrivateJWKS();

		return createJWS(payload, jwks);
	}

	public static JSONObject mockedTrustAnchorPublicJWKS() throws Exception {
		return new JSONObject(getContent("ta-public-jwks.json"));
	}

	public static JSONObject mockedTrustAnchorPrivateJWKS() throws Exception {
		return new JSONObject(getContent("ta-private-jwks.json"));
	}


}
