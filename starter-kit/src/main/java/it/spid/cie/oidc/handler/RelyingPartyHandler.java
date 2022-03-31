package it.spid.cie.oidc.handler;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.spid.cie.oidc.callback.RelyingPartyLogoutCallback;
import it.spid.cie.oidc.config.GlobalOptions;
import it.spid.cie.oidc.config.OIDCConstants;
import it.spid.cie.oidc.config.RelyingPartyOptions;
import it.spid.cie.oidc.exception.OIDCException;
import it.spid.cie.oidc.exception.RelyingPartyException;
import it.spid.cie.oidc.exception.SchemaException;
import it.spid.cie.oidc.exception.TrustChainException;
import it.spid.cie.oidc.helper.EntityHelper;
import it.spid.cie.oidc.helper.JWTHelper;
import it.spid.cie.oidc.helper.OAuth2Helper;
import it.spid.cie.oidc.helper.OIDCHelper;
import it.spid.cie.oidc.helper.PKCEHelper;
import it.spid.cie.oidc.model.AuthnRequest;
import it.spid.cie.oidc.model.AuthnToken;
import it.spid.cie.oidc.model.CachedEntityInfo;
import it.spid.cie.oidc.model.EntityConfiguration;
import it.spid.cie.oidc.model.FederationEntity;
import it.spid.cie.oidc.model.TrustChain;
import it.spid.cie.oidc.model.TrustChainBuilder;
import it.spid.cie.oidc.persistence.PersistenceAdapter;
import it.spid.cie.oidc.schemas.OIDCProfile;
import it.spid.cie.oidc.schemas.TokenResponse;
import it.spid.cie.oidc.schemas.WellKnownData;
import it.spid.cie.oidc.util.JSONUtil;
import it.spid.cie.oidc.util.ListUtil;
import it.spid.cie.oidc.util.Validator;

public class RelyingPartyHandler {

	public RelyingPartyHandler(
			RelyingPartyOptions options, PersistenceAdapter persistence)
		throws OIDCException {

		options.validate();

		if (persistence == null) {
			throw new OIDCException("persistence is mandatory");
		}

		this.options = options;
		this.persistence = persistence;
		this.jwtHelper = new JWTHelper(options);
		this.oauth2Helper = new OAuth2Helper(this.jwtHelper);
		this.oidcHelper = new OIDCHelper(this.jwtHelper);
	}

	/**
	 * Build the "authorize url": the URL a RelyingParty have to send to an OpenID
	 * Provider to start a SPID authorization flow
	 *
	 * @param spidProvider
	 * @param trustAnchor
	 * @param redirectUri
	 * @param scope
	 * @param profile
	 * @param prompt
	 * @return
	 * @throws OIDCException
	 */
	public String getAuthorizeURL(
			String spidProvider, String trustAnchor, String redirectUri, String scope,
			String profile, String prompt)
		throws OIDCException {

		// TODO: CIE could reuse this flow?
		if (Validator.isNullOrEmpty(profile)) {
			profile = OIDCProfile.SPID.getValue();
		}

		TrustChain tc = getSPIDProvider(spidProvider, trustAnchor);

		if (tc == null) {
			throw new OIDCException("TrustChain is unavailable");
		}

		JSONObject providerMetadata;

		try {
			providerMetadata = new JSONObject(tc.getMetadata());

			if (providerMetadata.isEmpty()) {
				throw new OIDCException("Provider metadata is empty");
			}
		}
		catch (Exception e) {
			throw e;
		}

		FederationEntity entityConf = persistence.fetchFederationEntity(
			OIDCConstants.OPENID_RELYING_PARTY);

		if (entityConf == null || !entityConf.isActive()) {
			throw new OIDCException("Missing configuration");
		}

		JSONObject entityMetadata;

		JWKSet entityJWKSet;

		try {
			entityMetadata = entityConf.getMetadataValue(
				OIDCConstants.OPENID_RELYING_PARTY);

			if (entityMetadata.isEmpty()) {
				throw new OIDCException("Entity metadata is empty");
			}

			entityJWKSet = JWTHelper.getJWKSetFromJSON(entityConf.getJwks());

			if (entityJWKSet.getKeys().isEmpty()) {
				throw new OIDCException("Entity with invalid or empty jwks");
			}
		}
		catch (OIDCException e) {
			throw e;
		}

		JWKSet providerJWKSet = JWTHelper.getMetadataJWKSet(providerMetadata);

		String authzEndpoint = providerMetadata.getString("authorization_endpoint");

		JSONArray entityRedirectUris = entityMetadata.getJSONArray("redirect_uris");

		if (entityRedirectUris.isEmpty()) {
			throw new OIDCException("Entity has no redirect_uris");
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

		if (Validator.isNullOrEmpty(scope)) {
			scope = OIDCConstants.SCOPE_OPENID;
		}

		if (Validator.isNullOrEmpty(profile)) {
			profile = options.getAcrValue(OIDCProfile.SPID);
		}

		if (Validator.isNullOrEmpty(prompt)) {
			prompt = "consent login";
		}

		String responseType = entityMetadata.getJSONArray("response_types").getString(0);
		String nonce = UUID.randomUUID().toString();
		String state = UUID.randomUUID().toString();
		String clientId = entityMetadata.getString("client_id");
		long issuedAt = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
		String[] aud = new String[] { tc.getSubject(), authzEndpoint };
		JSONObject claims = getRequestedClaims(profile);
		JSONObject pkce = PKCEHelper.getPKCE();

		String acr = options.getAcrValue(OIDCProfile.SPID);

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
			.put("code_verifier", pkce.getString("code_verifier"))
			.put("code_challenge", pkce.getString("code_challenge"))
			.put("code_challenge_method", pkce.getString("code_challenge_method"));

		AuthnRequest authzEntry = new AuthnRequest()
			.setClientId(clientId)
			.setState(state)
			.setEndpoint(authzEndpoint)
			.setProvider(tc.getSubject())
			.setProviderId(tc.getSubject())
			.setData(authzData.toString())
			.setProviderJwks(providerJWKSet.toString())
			.setProviderConfiguration(providerMetadata.toString());

		authzEntry = persistence.storeOIDCAuthnRequest(authzEntry);

		authzData.remove("code_verifier");
		authzData.put("iss", entityMetadata.getString("client_id"));
		authzData.put("sub", entityMetadata.getString("client_id"));

		String requestObj = jwtHelper.createJWS(authzData, entityJWKSet);

		authzData.put("request", requestObj);

		String url = buildURL(authzEndpoint, authzData);

		logger.info("Starting Authn request to {}", url);

		return url;
	}

	public JSONObject getUserInfo(String state, String code)
		throws OIDCException {

		try {
			return doGetUserInfo(state, code);
		}
		catch (OIDCException e) {
			throw e;
		}
		catch (Exception e) {
			throw new RelyingPartyException.Generic(e);
		}
	}

	/**
	 * Return the "Well Known" information of the current Relying Party. The completeness
	 * of these informations depends of the federation on-boarding status of the entity.
	 *
	 * @param requestURL
	 * @param jsonMode
	 * @return
	 * @throws OIDCException
	 */
	public WellKnownData getWellKnownData(String requestURL, boolean jsonMode)
		throws OIDCException {

		String sub = getSubjectFromURL(requestURL);

		if (!Objects.equals(sub, options.getClientId())) {
			throw new OIDCException(
				String.format(
					"Sub doesn't match %s : %s", sub, options.getClientId()));
		}

		FederationEntity conf = persistence.fetchFederationEntity(sub, true);

		if (conf == null) {
			return prepareOnboardingData(sub, jsonMode);
		}
		else {
			return getWellKnownData(conf, jsonMode);
		}
	}

	// TODO: userKey is not enough. We need a more unique element
	public String performLogout(String userKey, RelyingPartyLogoutCallback callback)
		throws OIDCException {

		try {
			return doPerformLogout(userKey, callback);
		}
		catch (OIDCException e) {
			throw e;
		}
		catch (Exception e) {
			throw new OIDCException(e);
		}
	}

	protected JSONObject doGetUserInfo(String state, String code)
		throws OIDCException {

		if (Validator.isNullOrEmpty(code) || Validator.isNullOrEmpty(state)) {
			throw new SchemaException.Validation(
				"Authn response object validation failed");
		}

		List<AuthnRequest> authnRequests = persistence.findAuthnRequests(state);

		if (authnRequests.isEmpty()) {
			throw new RelyingPartyException.Generic("No AuthnRequest");
		}

		AuthnRequest authnRequest = ListUtil.getLast(authnRequests);

		AuthnToken authnToken = new AuthnToken()
			.setAuthnRequestId(authnRequest.getStorageId())
			.setCode(code);

		authnToken = persistence.storeOIDCAuthnToken(authnToken);

		// Get clientId configuration. In this situation "clientId" refers this
		// RelyingParty

		FederationEntity entityConf = persistence.fetchFederationEntity(
			authnRequest.getClientId(), true);

		if (entityConf == null) {
			throw new RelyingPartyException.Generic(
				"RelyingParty %s not found", authnRequest.getClientId());
		}
		else if (!Objects.equals(options.getClientId(), authnRequest.getClientId())) {
			throw new RelyingPartyException.Generic(
				"Invalid RelyingParty %s", authnRequest.getClientId());
		}

		JSONObject authnData = new JSONObject(authnRequest.getData());

		JSONObject providerConfiguration = new JSONObject(
			authnRequest.getProviderConfiguration());

		JSONObject jsonTokenResponse = oauth2Helper.performAccessTokenRequest(
			authnData.optString("redirect_uri"), state, code,
			authnRequest.getProviderId(), entityConf,
			providerConfiguration.optString("token_endpoint"),
			authnData.optString("code_verifier"));

		TokenResponse tokenResponse = TokenResponse.of(jsonTokenResponse);

		if (logger.isDebugEnabled()) {
			logger.debug("TokenResponse=" + tokenResponse.toString());
		}

		JWKSet providerJwks = JWTHelper.getJWKSetFromJSON(
			providerConfiguration.optJSONObject("jwks"));

		try {
			jwtHelper.verifyJWS(tokenResponse.getAccessToken(), providerJwks);
		}
		catch (Exception e) {
			throw new RelyingPartyException.Authentication(
				"Authentication token validation error.");
		}

		try {
			jwtHelper.verifyJWS(tokenResponse.getIdToken(), providerJwks);
		}
		catch (Exception e) {
			throw new RelyingPartyException.Authentication("ID token validation error.");
		}

		// Update AuthenticationToken

		authnToken.setAccessToken(tokenResponse.getAccessToken());
		authnToken.setIdToken(tokenResponse.getIdToken());
		authnToken.setTokenType(tokenResponse.getTokenType());
		authnToken.setScope(jsonTokenResponse.optString("scope"));
		authnToken.setExpiresIn(tokenResponse.getExpiresIn());

		authnToken = persistence.storeOIDCAuthnToken(authnToken);

		JWKSet entityJwks = JWTHelper.getJWKSetFromJSON(entityConf.getJwks());

		JSONObject userInfo = oidcHelper.getUserInfo(
			state, tokenResponse.getAccessToken(), providerConfiguration, true,
			entityJwks);

		// TODO: userKey from options
		authnToken.setUserKey(userInfo.optString("https://attributes.spid.gov.it/email"));

		authnToken = persistence.storeOIDCAuthnToken(authnToken);

		return userInfo;
	}

	protected String doPerformLogout(
			String userKey, RelyingPartyLogoutCallback callback)
		throws Exception {
		if (Validator.isNullOrEmpty(userKey)) {
			throw new RelyingPartyException.Generic("UserKey null or empty");
		}

		List<AuthnToken> authnTokens = persistence.findAuthnTokens(userKey);

		if (authnTokens.isEmpty()) {
			return options.getLogoutRedirectURL();
		}

		AuthnToken authnToken = ListUtil.getLast(authnTokens);

		AuthnRequest authnRequest = persistence.fetchAuthnRequest(
			authnToken.getAuthnRequestId());

		if (authnRequest == null) {
			throw new RelyingPartyException.Generic(
				"No AuthnRequest with id " + authnToken.getAuthnRequestId());
		}

		JSONObject providerConfiguration = new JSONObject(
			authnRequest.getProviderConfiguration());

		String revocationUrl = providerConfiguration.optString("revocation_endpoint");

		// Do local logout

		if (callback != null) {
			callback.logout(userKey, authnRequest, authnToken);
		}

		if (Validator.isNullOrEmpty(revocationUrl)) {
			logger.warn(
				"{} doesn't expose the token revocation endpoint.",
				authnRequest.getProviderId());

			return options.getLogoutRedirectURL();
		}

		FederationEntity entityConf = persistence.fetchFederationEntity(
			authnRequest.getClientId(), true);

		JWKSet jwkSet = JWTHelper.getJWKSetFromJSON(entityConf.getJwks());

		authnToken.setRevoked(LocalDateTime.now());

		authnToken = persistence.storeOIDCAuthnToken(authnToken);

		try {
			oauth2Helper.sendRevocationRequest(
				authnToken.getAccessToken(), authnRequest.getClientId(), revocationUrl,
				entityConf);
		}
		catch (Exception e) {
			logger.error("Token revocation failed: {}", e.getMessage());
		}

		// Revoke older user's authnToken. Evaluate better

		authnTokens = persistence.findAuthnTokens(userKey);

		for (AuthnToken oldToken : authnTokens) {
			oldToken.setRevoked(authnToken.getRevoked());

			persistence.storeOIDCAuthnToken(oldToken);
		}

		return options.getLogoutRedirectURL();
	}

	protected TrustChain getOrCreateTrustChain(
			String subject, String trustAnchor, String metadataType, boolean force)
		throws OIDCException {

		CachedEntityInfo trustAnchorEntity = persistence.fetchEntityInfo(
			trustAnchor, trustAnchor);

		EntityConfiguration taConf;

		if (trustAnchorEntity == null || trustAnchorEntity.isExpired() || force) {
			String jwt = EntityHelper.getEntityConfiguration(trustAnchor);

			taConf = new EntityConfiguration(jwt, jwtHelper);

			if (trustAnchorEntity == null) {
				trustAnchorEntity = CachedEntityInfo.of(
					trustAnchor, subject, taConf.getExpiresOn(), taConf.getIssuedAt(),
					taConf.getPayload(), taConf.getJwt());

				trustAnchorEntity = persistence.storeEntityInfo(trustAnchorEntity);
			}
			else {
				trustAnchorEntity.setModifiedDate(LocalDateTime.now());
				trustAnchorEntity.setExpiresOn(taConf.getExpiresOn());
				trustAnchorEntity.setIssuedAt(taConf.getIssuedAt());
				trustAnchorEntity.setStatement(taConf.getPayload());
				trustAnchorEntity.setJwt(taConf.getJwt());

				trustAnchorEntity = persistence.storeEntityInfo(trustAnchorEntity);
			}
		}
		else {
			taConf = EntityConfiguration.of(trustAnchorEntity, jwtHelper);
		}

		TrustChain trustChain = persistence.fetchTrustChain(subject, trustAnchor);

		if (trustChain != null && !trustChain.isActive()) {
			return null;
		}
		else {
			TrustChainBuilder tcb =
				new TrustChainBuilder(subject, metadataType, jwtHelper)
					.setTrustAnchor(taConf)
					.start();

			if (!tcb.isValid()) {
				String msg = String.format(
					"Trust Chain for subject %s or trust_anchor %s is not valid",
					subject, trustAnchor);

				throw new TrustChainException.InvalidTrustChain(msg);
			}
			else if (Validator.isNullOrEmpty(tcb.getFinalMetadata())) {
				String msg = String.format(
					"Trust chain for subject %s and trust_anchor %s doesn't have any " +
					"metadata of type '%s'", subject, trustAnchor, metadataType);

				throw new TrustChainException.MissingMetadata(msg);
			}
			else {
				logger.info("KK TCB is valid");
			}

			trustChain = persistence.fetchTrustChain(subject, trustAnchor, metadataType);

			if (trustChain == null) {
				trustChain = new TrustChain()
					.setSubject(subject)
					.setType(metadataType)
					.setExpiresOn(tcb.getExpiresOn())
					.setChain(tcb.getChainAsString())
					.setPartiesInvolved(tcb.getPartiesInvolvedAsString())
					.setProcessingStart(LocalDateTime.now())
					.setActive(true)
					.setMetadata(tcb.getFinalMetadata())
					.setTrustAnchor(trustAnchor)
					.setTrustMarks(tcb.getVerifiedTrustMarksAsString())
					.setStatus("valid");
			}
			else {
				trustChain = trustChain
					.setExpiresOn(tcb.getExpiresOn())
					.setChain(tcb.getChainAsString())
					.setPartiesInvolved(tcb.getPartiesInvolvedAsString())
					.setProcessingStart(LocalDateTime.now())
					.setActive(true)
					.setMetadata(tcb.getFinalMetadata())
					.setTrustAnchor(trustAnchor)
					.setTrustMarks(tcb.getVerifiedTrustMarksAsString())
					.setStatus("valid");
			}

			trustChain = persistence.storeTrustChain(trustChain);
		}

		return trustChain;
	}

	protected TrustChain getSPIDProvider(String spidProvider, String trustAnchor)
		throws OIDCException {

		if (Validator.isNullOrEmpty(spidProvider)) {
			if (logger.isWarnEnabled()) {
				logger.warn(TrustChainException.MissingProvider.DEFAULT_MESSAGE);
			}

			throw new TrustChainException.MissingProvider();
		}

		if (Validator.isNullOrEmpty(trustAnchor)) {
			trustAnchor = options.getSPIDProviders().get(spidProvider);

			if (Validator.isNullOrEmpty(trustAnchor)) {
				trustAnchor = options.getDefaultTrustAnchor();
			}
		}

		if (!options.getTrustAnchors().contains(trustAnchor)) {
			logger.warn(TrustChainException.InvalidTrustAnchor.DEFAULT_MESSAGE);

			throw new TrustChainException.InvalidTrustAnchor();
		}

		TrustChain trustChain = persistence.fetchTrustChain(
			spidProvider, trustAnchor);

		boolean discover = false;

		if (trustChain == null) {
			logger.info("TrustChain not found for {}", spidProvider);

			discover = true;
		}
		else if (!trustChain.isActive()) {
			String msg = TrustChainException.TrustChainDisabled.getDefualtMessage(
				trustChain.getModifiedDate());

			if (logger.isWarnEnabled()) {
				logger.warn(msg);
			}

			throw new TrustChainException.TrustChainDisabled(msg);
		}
		else if (trustChain.isExpired()) {
			logger.warn(
				String.format(
					"TrustChain found but EXPIRED at %s.",
					trustChain.getExpiresOn().toString()));
			logger.warn("Try to renew the trust chain");

			discover = true;
		}

		if (discover) {
			trustChain = getOrCreateTrustChain(
				spidProvider, trustAnchor, OIDCConstants.OPENID_PROVIDER, true);
		}

		return trustChain;
	}

	// TODO: move to an helper?
	private String buildURL(String endpoint, JSONObject params) {
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

	// TODO: have to be configurable
	private JSONObject getRequestedClaims(String profile) {
		if (OIDCProfile.SPID.equalValue(profile)) {
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

	private String getSubjectFromURL(String url) {
		int x = url.indexOf(OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL);

		return url.substring(0, x);
	}

	private WellKnownData getWellKnownData(FederationEntity entity, boolean jsonMode)
		throws OIDCException {

		JWKSet jwkSet = JWTHelper.getJWKSetFromJSON(entity.getJwks());

		JSONObject metadataJson = new JSONObject(entity.getMetadata());

		long iat = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);

		JSONObject json = new JSONObject();

		json.put("exp", iat + (entity.getDefaultExpireMinutes() * 60));
		json.put("iat", iat);
		json.put("iss", entity.getSubject());
		json.put("sub", entity.getSubject());
		json.put("jwks", JWTHelper.getJWKSetAsJSONObject(jwkSet, true));
		json.put("metadata", metadataJson);
		json.put("authority_hints", new JSONArray(entity.getAuthorityHints()));
		json.put("trust_marks", new JSONArray(entity.getTrustMarks()));

		if (jsonMode) {
			return WellKnownData.of(WellKnownData.STEP_COMPLETE, json.toString());
		}

		String jws = jwtHelper.createJWS(json, jwkSet);

		return WellKnownData.of(WellKnownData.STEP_COMPLETE, jws);
	}

	private WellKnownData prepareOnboardingData(String sub, boolean jsonMode)
		throws OIDCException {

		// TODO: JWSAlgorithm via defualt?

		String confJwk = options.getJwk();

		// If not JSON Web Key is configured I have to create a new one

		if (Validator.isNullOrEmpty(confJwk)) {

			// TODO: Type has to be defined by configuration?
			RSAKey jwk = JWTHelper.createRSAKey(JWSAlgorithm.RS256, KeyUse.SIGNATURE);

			JSONObject json = new JSONObject(jwk.toString());

			return WellKnownData.of(WellKnownData.STEP_ONLY_JWKS, json.toString(2));
		}

		RSAKey jwk = JWTHelper.parseRSAKey(confJwk);

		logger.info("Configured jwk\n" + jwk.toJSONString());

		JSONArray jsonArray = new JSONArray()
			.put(new JSONObject(jwk.toPublicJWK().toJSONObject()));

		logger.info("Configured public jwk\n" + jsonArray.toString(2));

		JWKSet jwkSet = new JWKSet(jwk);

		JSONObject rpJson = new JSONObject();

		rpJson.put("jwks", JWTHelper.getJWKSetAsJSONObject(jwkSet, false));
		rpJson.put("application_type", options.getApplicationType());
		rpJson.put("client_name", options.getApplicationName());
		rpJson.put("client_id", sub);
		rpJson.put("client_registration_types", JSONUtil.asJSONArray("automatic"));
		rpJson.put("contacts", options.getContacts());
		rpJson.put("grant_types", RelyingPartyOptions.SUPPORTED_GRANT_TYPES);
		rpJson.put("response_types", RelyingPartyOptions.SUPPORTED_RESPONSE_TYPES);
		rpJson.put("redirect_uris", options.getRedirectUris());

		JSONObject metadataJson = new JSONObject();

		metadataJson.put(OIDCConstants.OPENID_RELYING_PARTY, rpJson);

		long iat = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);

		JSONObject json = new JSONObject();

		json.put("exp", iat + (GlobalOptions.DEFAULT_EXPIRING_MINUTES * 60));
		json.put("iat", iat);
		json.put("iss", sub);
		json.put("sub", sub);
		json.put("jwks", JWTHelper.getJWKSetAsJSONObject(jwkSet, true));
		json.put("metadata", metadataJson);
		json.put(
			"authority_hints", JSONUtil.asJSONArray(options.getDefaultTrustAnchor()));

		int step = WellKnownData.STEP_INTERMEDIATE;

		if (!Validator.isNullOrEmpty(options.getTrustMarks())) {
			JSONArray tm = new JSONArray(options.getTrustMarks());

			json.put("trust_marks", tm);

			// With the trust marks I've all the elements to store this RelyingParty into
			// FederationEntity table

			step = WellKnownData.STEP_COMPLETE;

			FederationEntity entity = new FederationEntity();

			entity.setSubject(json.getString("sub"));
			entity.setDefaultExpireMinutes(options.getDefaultExpiringMinutes());
			entity.setDefaultSignatureAlg(JWSAlgorithm.RS256.toString());
			entity.setAuthorityHints(json.getJSONArray("authority_hints").toString());
			entity.setJwks(
				JWTHelper.getJWKSetAsJSONArray(jwkSet, true, false).toString());
			entity.setTrustMarks(json.getJSONArray("trust_marks").toString());
			entity.setTrustMarksIssuers("{}");
			entity.setMetadata(json.getJSONObject("metadata").toString());
			entity.setActive(true);
			entity.setConstraints("{}");
			entity.setEntityType(OIDCConstants.OPENID_RELYING_PARTY);

			persistence.storeFederationEntity(entity);
		}

		if (jsonMode) {
			return WellKnownData.of(step, json.toString());
		}

		String jws = jwtHelper.createJWS(json, jwkSet);

		return WellKnownData.of(step, jws);
	}

	private static final Logger logger = LoggerFactory.getLogger(
		RelyingPartyHandler.class);

	private final RelyingPartyOptions options;
	private final PersistenceAdapter persistence;
	private final JWTHelper jwtHelper;
	private final OAuth2Helper oauth2Helper;
	private final OIDCHelper oidcHelper;

}
