package it.spid.cie.oidc.spring.boot.relying.party.controller;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import it.spid.cie.oidc.relying.party.helper.JWTHelper;
import it.spid.cie.oidc.relying.party.model.OidcConstants;
import it.spid.cie.oidc.relying.party.util.JSONUtil;
import it.spid.cie.oidc.relying.party.util.Validator;
import it.spid.cie.oidc.spring.boot.relying.party.config.OidcConfig;
import it.spid.cie.oidc.spring.boot.relying.party.config.OidcConfig.RelyingParty;
import it.spid.cie.oidc.spring.boot.relying.party.storage.FederationEntityConfiguration;
import it.spid.cie.oidc.spring.boot.relying.party.storage.FederationEntityConfigurationRepository;

@RestController
@RequestMapping("/oidc/rp")
public class WellKnownController {

	private static Logger logger = LoggerFactory.getLogger(SpidController.class);

	@Autowired
	private OidcConfig oidcConfig;

	@Autowired
	private FederationEntityConfigurationRepository _federationEntityRepository;

	@GetMapping("/" + OidcConstants.OIDCFED_FEDERATION_WELLKNOWN_URL)
	public ResponseEntity<String> wellKnownFederation(
			@RequestParam(required = false) String format,
			HttpServletRequest request, HttpServletResponse response)
		throws Exception {

		String sub = getSubject(request.getRequestURL().toString());

		if (!Objects.equals(sub, oidcConfig.getRelyingParty().getClientId())) {
			throw new Exception(
				String.format(
					"Sub doesn't match %s : %s", sub,
					oidcConfig.getRelyingParty().getClientId()));
		}

		FederationEntityConfiguration conf = _federationEntityRepository.fetchBySubActive(
			sub, true);

		boolean jsonMode = "json".equals(format);

		String body;

		if (conf == null) {
			body = prepareOnboardingData(sub, jsonMode);
		}
		else {
			body = getWellKnownData(conf, jsonMode);
		}

		if (jsonMode) {
			return ResponseEntity.ok()
				.contentType(MediaType.APPLICATION_JSON)
				.body(body);
		}
		else {
			return ResponseEntity.ok()
				.contentType(new MediaType("application", "entity-statement+jwt"))
				.body(body);
		}
	}

	private void addFederationEntityConfiguration(JSONObject json, JWKSet jwkSet)
		throws Exception {

		FederationEntityConfiguration entry = new FederationEntityConfiguration();

		System.out.println(json.toString(2));

		entry.setSub(json.getString("sub"));
		entry.setDefaultExpireMinutes(OidcConstants.FEDERATION_DEFAULT_EXP);
		entry.setDefaultSignatureAlg(JWSAlgorithm.RS256.toString());
		entry.setAuthorityHints(json.getJSONArray("authority_hints").toString());
		entry.setJwks(JWTHelper.getJWKSetAsJSONArray(jwkSet, true, false).toString());
		entry.setTrustMarks(json.getJSONArray("trust_marks").toString());
		entry.setTrustMarksIssuers("{}");
		entry.setMetadata(json.getJSONObject("metadata").toString());
		entry.setActive(true);
		entry.setConstraints("{}");
		entry.setEntityType(OidcConstants.OPENID_RELYING_PARTY);

		_federationEntityRepository.save(entry);
	}

	private String getWellKnownData(FederationEntityConfiguration entry, boolean jsonMode)
		throws Exception {

		JWKSet jwkSet = getJWKSet(entry);

		JSONObject metadataJson = new JSONObject(entry.getMetadata());

		long iat = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);

		JSONObject json = new JSONObject();

		json.put("exp", iat + (entry.getDefaultExpireMinutes() * 60));
		json.put("iat", iat);
		json.put("iss", entry.getSub());
		json.put("sub", entry.getSub());
		json.put("jwks", JWTHelper.getJWKSetAsJSONObject(jwkSet, true));
		json.put("metadata", metadataJson);
		json.put("authority_hints", new JSONArray(entry.getAuthorityHints()));
		json.put("trust_marks", new JSONArray(entry.getTrustMarks()));

		if (jsonMode) {
			return json.toString();
		}

		// TODO: Use entry jwkSet
		RSAKey jwk = JWTHelper.parseRSAKey(oidcConfig.getRelyingParty().getJwk());

		// Create RSA-signer with the private key
		JWSSigner signer = new RSASSASigner(jwk);

		// Prepare JWS object with the payload
		JWSObject jwsObject = new JWSObject(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwk.getKeyID()).build(),
			new Payload(json.toString()));

		// Compute the RSA signature
		jwsObject.sign(signer);

		// To serialize to compact form
		return jwsObject.serialize();
	}

	private String prepareOnboardingData(String sub, boolean jsonMode) throws Exception {
		String confJwk = oidcConfig.getRelyingParty().getJwk();

		if (Validator.isNullOrEmpty(confJwk)) {
			// Create a new one to be added to conf

			// TODO: Type has to be defined by configuration
			RSAKey jwk = JWTHelper.createRSAKey(JWSAlgorithm.RS256, KeyUse.SIGNATURE);

			JSONObject json = new JSONObject(jwk.toString());

			logger.info(
				"Generated jwk. Please add it into 'application.yaml'.\n" +
				json.toString(2));

			return new JSONObject()
				.put("ERROR", "Do OnBoarding configuration")
				.toString();
		}

		RSAKey jwk = JWTHelper.parseRSAKey(confJwk);

		logger.info("Configured jwk\n" + jwk.toJSONString());

		JSONArray jsonArray = new JSONArray()
			.put(new JSONObject(jwk.toPublicJWK().toJSONObject()));

		logger.info("Configured public jwk\n" + jsonArray.toString(2));

		JWKSet jwkSet = new JWKSet(jwk);

		JSONObject rpJson = new JSONObject();

		RelyingParty rpConf = oidcConfig.getRelyingParty();

		rpJson.put("jwks", JWTHelper.getJWKSetAsJSONObject(jwkSet, false));
		rpJson.put("application_type", rpConf.getApplicationType());
		rpJson.put("client_name", rpConf.getApplicationName());
		rpJson.put("client_id", sub);
		rpJson.put("client_registration_types", JSONUtil.asJSONArray("automatic"));
		rpJson.put("contacts", rpConf.getContacts());
		rpJson.put("grant_types", OidcConstants.RP_GRANT_TYPES);
		rpJson.put("response_types", OidcConstants.RP_RESPONSE_TYPES);
		rpJson.put("redirect_uris", rpConf.getRedirectUris());

		JSONObject metadataJson = new JSONObject();

		metadataJson.put("openid_relying_party", rpJson);

		long iat = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);

		JSONObject json = new JSONObject();

		json.put("exp", iat + (OidcConstants.FEDERATION_DEFAULT_EXP * 60));
		json.put("iat", iat);
		json.put("iss", sub);
		json.put("sub", sub);
		json.put("jwks", JWTHelper.getJWKSetAsJSONObject(jwkSet, true));
		json.put("metadata", metadataJson);
		json.put(
			"authority_hints", JSONUtil.asJSONArray(
				oidcConfig.getDefaultTrustAnchor()));

		if (!Validator.isNullOrEmpty(rpConf.getTrustMarks())) {
			JSONArray tm = new JSONArray(rpConf.getTrustMarks());

			json.put("trust_marks", tm);

			// With the trust marks I've all the elements to store this RelyingParty into
			// FederationEntryConfiguration table

			addFederationEntityConfiguration(json, jwkSet);
		}

		//logger.info("\n" + json.toString(2));

		if (jsonMode) {
			return json.toString();
		}

		// Create RSA-signer with the private key
		JWSSigner signer = new RSASSASigner(jwk);

		// Prepare JWS object with the payload
		JWSObject jwsObject = new JWSObject(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwk.getKeyID()).build(),
			new Payload(json.toString()));

		// Compute the RSA signature
		jwsObject.sign(signer);

		// To serialize to compact form
		return jwsObject.serialize();
	}

	private String getSubject(String url) {
		int x = url.indexOf(OidcConstants.OIDCFED_FEDERATION_WELLKNOWN_URL);

		return url.substring(0, x);
	}

	private JWKSet getJWKSet(FederationEntityConfiguration entry) throws Exception {
		JSONObject jwks = new JSONObject();

		jwks.put("keys", new JSONArray(entry.getJwks()));
//		JSONArray jwkArray = new JSONArray(entry.getJwks());
//
//		List<JWK> jwks = new ArrayList<>();

		JWKSet jwkSet = JWKSet.parse(jwks.toMap());

		return jwkSet;
	}


}
