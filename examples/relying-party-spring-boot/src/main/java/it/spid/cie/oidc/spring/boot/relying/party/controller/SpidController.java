package it.spid.cie.oidc.spring.boot.relying.party.controller;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import it.spid.cie.oidc.relying.party.helper.EntityHelper;
import it.spid.cie.oidc.relying.party.helper.JWTHelper;
import it.spid.cie.oidc.relying.party.helper.PKCEHelper;
import it.spid.cie.oidc.relying.party.model.EntityConfiguration;
import it.spid.cie.oidc.relying.party.model.OidcConstants;
import it.spid.cie.oidc.relying.party.model.TrustChainBuilder;
import it.spid.cie.oidc.relying.party.schemas.AcrValuesSpid;
import it.spid.cie.oidc.relying.party.util.ArrayUtil;
import it.spid.cie.oidc.relying.party.util.GetterUtil;
import it.spid.cie.oidc.relying.party.util.JSONUtil;
import it.spid.cie.oidc.relying.party.util.Validator;
import it.spid.cie.oidc.spring.boot.relying.party.config.OidcConfig;
import it.spid.cie.oidc.spring.boot.relying.party.exception.TrustChainException;
import it.spid.cie.oidc.spring.boot.relying.party.storage.EntityInfo;
import it.spid.cie.oidc.spring.boot.relying.party.storage.EntityInfoRepository;
import it.spid.cie.oidc.spring.boot.relying.party.storage.FederationEntityConfiguration;
import it.spid.cie.oidc.spring.boot.relying.party.storage.FederationEntityConfigurationRepository;
import it.spid.cie.oidc.spring.boot.relying.party.storage.TrustChain;
import it.spid.cie.oidc.spring.boot.relying.party.storage.TrustChainRepository;

@RestController
@RequestMapping("/oidc/rp")
public class SpidController {

	private static Logger logger = LoggerFactory.getLogger(SpidController.class);

	@Autowired
	private OidcConfig oidcConfig;

	@Autowired
	private TrustChainRepository trustChainRepository;

	@Autowired
	private EntityInfoRepository entityInfoRepository;

	@Autowired
	private FederationEntityConfigurationRepository _federationEntityRepository;

	@GetMapping("/authorize")
	public ResponseEntity<Void> authorize(
			@RequestParam String provider,
			@RequestParam(name = "redirect_uri", required = false) String redirectUri,
			@RequestParam(required = false) String scope,
			@RequestParam(required = false) String prompt,
			@RequestParam(name = "trust_anchor", required = false) String trustAnchor,
			@RequestParam(required = false) String profile)
		throws Exception {

		TrustChain tc = getOidcOP(provider, trustAnchor);

		if (tc == null) {
			throw new Exception("TrustChain is unavailable");
		}

		JSONObject providerMetadata;

		try {
			providerMetadata = new JSONObject(tc.getMetadata());

			if (providerMetadata.isEmpty()) {
				throw new Exception("Provider metadata is empty");
			}
		}
		catch (Exception e) {
			throw e;
		}

		FederationEntityConfiguration entityConf =
			_federationEntityRepository.fetchByEntityType(
				OidcConstants.OPENID_RELYING_PARTY);

		if (entityConf == null || !entityConf.isActive()) {
			throw new Exception("Missing configuration");
		}

		JSONObject entityMetadata;

		JWKSet entityJWKSet;

		try {
			entityMetadata = entityConf.getMetadataValue(
				OidcConstants.OPENID_RELYING_PARTY);

			if (entityMetadata.isEmpty()) {
				throw new Exception("Entity metadata is empty");
			}

			entityJWKSet = JWTHelper.getJWKSetFromJSON(entityConf.getJwks());

			if (entityJWKSet.getKeys().isEmpty()) {
				throw new Exception("Entity with invalid or empty jwks");
			}
		}
		catch (Exception e) {
			throw e;
		}

		JWKSet providerJWKSet = JWTHelper.getMetadataJWKSet(providerMetadata);

		String authzEndpoint = providerMetadata.getString("authorization_endpoint");

		JSONArray entityRedirectUris = entityMetadata.getJSONArray("redirect_uris");

		if (entityRedirectUris.isEmpty()) {
			throw new Exception("Entity has no redirect_uris");
		}

		if (!Validator.isNullOrEmpty(redirectUri)) {
			if (!JSONUtil.contains(entityRedirectUris, redirectUri)) {
				logger.warn(
					"Requested for unknown redirect uri '{}'. Reverted to default '{}'",
					redirectUri, entityRedirectUris.getString(0));

				redirectUri = entityRedirectUris.getString(0);
			}
		}
		else {
			redirectUri = entityRedirectUris.getString(0);
		}

		scope = GetterUtil.getString(scope, "openid");
		profile = GetterUtil.getString(profile, "spid");
		String acr = getACR(profile);
		String responseType = entityMetadata.getJSONArray("response_types").getString(0);
		String nonce = UUID.randomUUID().toString();
		String state = UUID.randomUUID().toString();
		String clientId = entityMetadata.getString("client_id");
		long issuedAt = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
		String[] aud = new String[] { tc.getSub(), authzEndpoint };
		JSONObject claims = getRequestedClaims(profile);
		prompt = GetterUtil.getString(prompt, "consent login");
		JSONObject pkce = PKCEHelper.getPKCE();

		// TODO: Store OidcAuthentication

		JSONObject authzData = new JSONObject()
			.put("scope", scope)
			.put("redirect_uri", redirectUri)
			.put("response_type", responseType)
			.put("nonce", nonce)
			.put("state", state)
			.put("client_id", clientId)
			.put("endpoint", authzEndpoint)
			.put("acr_values", acr)
			.put("iat", issuedAt)
			.put("aud", JSONUtil.asJSONArray(aud))
			.put("claims", claims)
			.put("prompt", prompt)
			.put("code_challenge", pkce.getString("code_challenge"))
			.put("code_challenge_method", pkce.getString("code_challenge_method"))
			.put("iss", entityMetadata.getString("client_id"))
			.put("sub", entityMetadata.getString("client_id"));

		String requestObj = createJWS(authzData, entityJWKSet);

		authzData.put("request", requestObj);

		String url = getAuthorizeURL(authzEndpoint, authzData);

		logger.info("Starting Authz request to {}", url);

		return ResponseEntity
			.status(HttpStatus.FOUND)
			.location(URI.create(url))
			.build();
	}

	protected TrustChain getOidcOP(String provider, String trustAnchor)
		throws Exception {

		if (Validator.isNullOrEmpty(provider)) {
			// TODO: check if log is enabled
			logger.warn(TrustChainException.MissingProvider.DEFAULT_MESSAGE);

			throw new TrustChainException.MissingProvider();
		}

		if (Validator.isNullOrEmpty(trustAnchor)) {
			// SDK will have it's own config object with an helper method
			trustAnchor = oidcConfig.getIdentityProviders().get(provider);

			if (Validator.isNullOrEmpty(trustAnchor)) {
				trustAnchor = oidcConfig.getDefaultTrustAnchor();
			}
		}

		if (!oidcConfig.getTrustAnchors().contains(trustAnchor)) {
			logger.warn(TrustChainException.InvalidTrustAnchor.DEFAULT_MESSAGE);

			throw new TrustChainException.InvalidTrustAnchor();
		}

		TrustChain trustChain = trustChainRepository.fetchBySub(provider);

		boolean discover = false;

		if (trustChain == null) {
			logger.info("TrustChain not found for %s", provider);

			discover = true;
		}
		else if (!trustChain.isActive()) {
			String message = String.format(
				"TrustChain found but DISABLED at %s",
				trustChain.getModified().toString());

			logger.warn(message);

			throw new TrustChainException.TrustChainDisabled(message);
		}
		else if (trustChain.isExpired()) {
			logger.warn(
				String.format(
					"TrustChain found but EXPIRED at %s.",
					trustChain.getExp().toString()));
			logger.warn("Try to renew the trust chain");

			discover = true;
		}

		if (discover) {
			trustChain = getOrCreateTrustChain(
				provider, trustAnchor, "openid_provider", true);
		}

		return trustChain;
	}


	protected TrustChain getOrCreateTrustChain(
			String subject, String trustAnchor, String metadataType,
			boolean force)
		throws Exception {

		EntityInfo trustAnchorEntity = entityInfoRepository.findEntity(
			trustAnchor, trustAnchor);

		EntityConfiguration taConf;

		if (trustAnchorEntity == null || trustAnchorEntity.isExpired() ||
			force) {

			// HTTPC_PARAMS ??
			Map<String, String> params = new HashMap<>();

			String jwt = EntityHelper.getEntityConfiguration(trustAnchor);

			logger.info("KK jwt -->" + jwt);

			taConf = new EntityConfiguration(jwt);

			LocalDateTime exp = LocalDateTime.ofEpochSecond(
				taConf.getPayloadLong("exp"), 0, ZoneOffset.UTC);

			LocalDateTime iat = LocalDateTime.ofEpochSecond(
				taConf.getPayloadLong("iat"), 0,ZoneOffset.UTC);

			//Map<String, Object> statement = taConf.getPayload().toString();

			if (trustAnchorEntity == null) {
				EntityInfo entityInfo = new EntityInfo(
					taConf.getPayloadString("iss"),
					taConf.getPayloadString("sub"),
					exp, iat, taConf.getPayload(), taConf.getJwt());

				trustAnchorEntity = entityInfoRepository.save(entityInfo);
			}
			else {
				trustAnchorEntity.setModified(LocalDateTime.now());
				trustAnchorEntity.setExp(exp);
				trustAnchorEntity.setIat(iat);
				trustAnchorEntity.setStatement(taConf.getPayload().toString());
				trustAnchorEntity.setJwt(taConf.getJwt());

				trustAnchorEntity = entityInfoRepository.save(
					trustAnchorEntity);
			}
		}
		else {
			taConf = EntityConfiguration.of(trustAnchorEntity);
		}

		TrustChain trustChain = trustChainRepository.fetchBySub_TASub(
			subject, trustAnchor);

		if (trustChain != null && !trustChain.isActive()) {
			return null;
		}
		else if (force || trustChain == null || trustChain.isExpired()) {
			// Verify trust chain
			TrustChainBuilder tcb = new TrustChainBuilder(subject, metadataType)
				.setTrustAnchor(taConf)
				.start();

			if (!tcb.isValid()) {
				String msg = String.format(
					"Trsut Chain for subject %s od trust_anchor %s is not valid",
					subject, trustAnchor);

				//throw new InvalidTrustchainException(msg);
				throw new Exception(msg);
			}
			else if (Validator.isNullOrEmpty(tcb.getFinalMetadata())) {
				String msg = String.format(
					"Trust chain for subject %s and trust_anchor %s doesn't have any " +
					"metadata of type '%s'", subject, trustAnchor, metadataType);

				//throw new TrustchainMissingMetadataException(msg);
				throw new Exception(msg);
			}
			else {
				logger.info("KK TCB is valid");
			}

			trustChain = trustChainRepository.fetchBySub_TASub_T(
				subject, trustAnchor, metadataType);

			trustChain = new TrustChain(
				subject, metadataType, tcb.getExpiration(), null, tcb.getChainAsString(),
				tcb.getPartiesInvolvedAsString(), true, null, tcb.getFinalMetadata(),
				null, trustAnchorEntity.getId(), tcb.getVerifiedTrustMarksAsString(),
				"valid", trustAnchor);

			// TODO: Store on DB

		}

		return trustChain;
	}

	// TODO: move to JWTHelper?
	private String getAuthorizeURL(String endpoint, JSONObject params) {
		StringBuilder sb = new StringBuilder();

		sb.append(endpoint);

		if (!params.isEmpty()) {
			boolean first = true;

			for (String key : params.keySet()) {
				if (first) {
					sb.append("?");
					first = false;
				}
				else {
					sb.append("&");
				}

				sb.append(key);
				sb.append("=");

				String value = params.get(key).toString();

				sb.append(URLEncoder.encode(value, StandardCharsets.UTF_8));
			}
		}

		return sb.toString();
	}

	// TODO: move to JWTHelper?
	private String createJWS(JSONObject payload, JWKSet jwks) throws Exception {
		RSAKey jwk = JWTHelper.parseRSAKey(oidcConfig.getRelyingParty().getJwk());

		// Create RSA-signer with the private key
		JWSSigner signer = new RSASSASigner(jwk);

		// Prepare JWS object with the payload
		JWSObject jwsObject = new JWSObject(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwk.getKeyID()).build(),
			new Payload(payload.toString()));

		// Compute the RSA signature
		jwsObject.sign(signer);

		// To serialize to compact form
		return jwsObject.serialize();
	}

	// TODO: have to be configurable
	private String getACR(String profile) {
		if ("spid".equals(profile)) {
			return AcrValuesSpid.L2.getValue();
		}

		return "";
	}

	// TODO: have to be configurable
	private JSONObject getRequestedClaims(String profile) {
		if ("spid".equals(profile)) {
			JSONObject result = new JSONObject();

			JSONObject idToken = new JSONObject()
				.put(
					"https://attributes.spid.gov.it/familyName",
					new JSONObject().put("essential", true))
				.put(
					"https://attributes.spid.gov.it/email",
					new JSONObject().put("essential", true));

			JSONObject userInfo = new JSONObject()
				.put("https://attributes.spid.gov.it/name", new JSONObject())
				.put("https://attributes.spid.gov.it/familyName", new JSONObject())
				.put("https://attributes.spid.gov.it/email", new JSONObject())
				.put("https://attributes.spid.gov.it/fiscalNumber", new JSONObject());

			result.put("id_token", idToken);
			result.put("userinfo", userInfo);

			return result;
		}

		return new JSONObject();
	}

	/*
	private String getEntityConfiguration(
			String subject, Map<String, String> params)
		throws Exception {

		String url;

		if (subject.endsWith("/")) {
			url = subject.concat(OidcConstants.OIDCFED_FEDERATION_WELLKNOWN_URL);
		}
		else {
			url = subject.concat("/").concat(OidcConstants.OIDCFED_FEDERATION_WELLKNOWN_URL);
		}

		logger.info("Starting Entity Configuration Request for " + url);

		HttpRequest request = HttpRequest.newBuilder()
			.uri(new URI(url))
			.GET()
			.build();

		HttpResponse<String> response = HttpClient.newBuilder()
			.build()
			.send(request, BodyHandlers.ofString());

		logger.info(url + " --> " + response.statusCode());

		// TODO: Cheks status != 200

		return response.body();
	}
	*/
}
