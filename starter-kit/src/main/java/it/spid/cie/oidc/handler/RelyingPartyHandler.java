package it.spid.cie.oidc.handler;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;

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
import it.spid.cie.oidc.schemas.CIEClaimItem;
import it.spid.cie.oidc.schemas.ClaimItem;
import it.spid.cie.oidc.schemas.OIDCProfile;
import it.spid.cie.oidc.schemas.ProviderButtonInfo;
import it.spid.cie.oidc.schemas.SPIDClaimItem;
import it.spid.cie.oidc.schemas.Scope;
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
	 * Build the "authorize url": the URL a RelyingParty have to send to an OpenID Connect
	 * Provider to start a SPID/CIE authorization flow
	 *
	 * @param oidcProvider
	 * @param trustAnchor
	 * @param redirectUri
	 * @param scope
	 * @param profile {@code spid} or {@code cie}. If null or empty {@code spid} will be
	 * used
	 * @param prompt
	 * @return
	 * @throws OIDCException
	 */
	public String getAuthorizeURL(
			String oidcProvider, String trustAnchor, String redirectUri, String scope,
			String profile, String prompt)
		throws OIDCException {

		OIDCProfile oidcProfile = OIDCProfile.parse(profile);

		if (oidcProfile == null) {
			oidcProfile = OIDCProfile.SPID;
		}

		TrustChain tc = getOIDCProvider(oidcProvider, trustAnchor, oidcProfile);

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

		FederationEntity entityConf = getOrCreateFederationEntity(options.getClientId());

		if (entityConf == null || !entityConf.isActive()) {
			throw new OIDCException("Missing WellKnown configuration");
		}

		JSONObject entityMetadata;

		JWKSet entityJWKSet;

		try {
			entityMetadata = entityConf.getMetadataValue(
				OIDCConstants.OPENID_RELYING_PARTY);

			if (entityMetadata.isEmpty()) {
				throw new OIDCException("Entity metadata is empty");
			}

			entityJWKSet = JWTHelper.getJWKSetFromJSON(entityConf.getJwksCoreByUse(KeyUse.SIGNATURE));

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
			scope = Scope.OPEN_ID.value();
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
		JSONObject claims = getRequestedClaims(oidcProfile);
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
		//authzData.put("sub", entityMetadata.getString("client_id"));

		String requestObj = jwtHelper.createJWS(authzData, entityJWKSet);

		authzData.put("request", requestObj);

		String url = buildURL(authzEndpoint, authzData);

		logger.info("Starting Authn request to {}", url);

		return url;
	}

	/**
	 * Return the information needed to render the SignIn button with the OIDC Providers
	 * configured into {@link RelyingPartyOptions}.<br/>
	 * The list is randomized on every call.
	 *
	 * @param profile
	 * @return
	 * @throws OIDCException
	 */
	public List<ProviderButtonInfo> getProviderButtonInfos(OIDCProfile profile)
		throws OIDCException {

		List<ProviderButtonInfo> result = new ArrayList<>();

		Map<String, String> providers = options.getProviders(profile);

		for (Map.Entry<String, String> entry : providers.entrySet()) {
			try {
				TrustChain tc = getOIDCProvider(
					entry.getKey(), entry.getValue(), profile);

				JSONObject metadata = tc.getMetadataAsJSON();

				String logoUrl = metadata.optString("logo_uri", "");
				String organizationName = metadata.optString("organization_name", "");

				result.add(
					new ProviderButtonInfo(tc.getSubject(), organizationName, logoUrl));
			}
			catch (Exception e) {
				logger.warn(
					"Failed trust chain for {} to {}: {}", entry.getKey(),
					entry.getValue(), e.getMessage());
			}
		}

		Collections.shuffle(result);

		return Collections.unmodifiableList(result);
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
	 * <br/>
	 * Use this method only for the OnBoarding phase. For other scenarious use
	 * {@link #getWellKnownData(String, boolean)}
	 *
	 * @param jsonMode
	 * @return
	 * @throws OIDCException
	 */
	public WellKnownData getWellKnownData(boolean jsonMode) throws OIDCException {
		String sub = options.getClientId();

		FederationEntity conf = persistence.fetchFederationEntity(sub, true);

		if (conf == null) {
			return prepareOnboardingData(sub, jsonMode);
		}
		else {
			return getWellKnownData(conf, jsonMode);
		}
	}

	/**
	 * Return the "Well Known" information of the current Relying Party. The completeness
	 * of these informations depends of the federation on-boarding status of the entity.
	 *
	 * @param requestURL the requested url with the ".well-known" suffix
	 * @param jsonMode
	 * @return
	 * @throws OIDCException
	 */
	public WellKnownData getWellKnownData(String requestURL, boolean jsonMode)
		throws OIDCException {

		String sub = getSubjectFromWellKnownURL(requestURL);

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

		JWKSet entityJwks = JWTHelper.getJWKSetFromJSON(entityConf.getJwksCoreByUse(KeyUse.ENCRYPTION));

		JSONObject userInfo = oidcHelper.getUserInfo(
			state, tokenResponse.getAccessToken(), providerConfiguration, true,
			entityJwks);

		authnToken.setUserKey(getUserKeyFromUserInfo(userInfo));

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

		JWTHelper.getJWKSetFromJSON(entityConf.getJwksFed());

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
					trustAnchor, trustAnchor, taConf.getExpiresOn(), taConf.getIssuedAt(),
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
					.setChain(tcb.getChain())
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
					.setChain(tcb.getChain())
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

	protected TrustChain getOIDCProvider(
			String oidcProvider, String trustAnchor, OIDCProfile profile)
		throws OIDCException {

		if (Validator.isNullOrEmpty(oidcProvider)) {
			if (logger.isWarnEnabled()) {
				logger.warn(TrustChainException.MissingProvider.DEFAULT_MESSAGE);
			}

			throw new TrustChainException.MissingProvider();
		}

		if (Validator.isNullOrEmpty(trustAnchor)) {
			trustAnchor = options.getProviders(profile).get(oidcProvider);

			if (Validator.isNullOrEmpty(trustAnchor)) {
				trustAnchor = options.getDefaultTrustAnchor();
			}
		}

		if (!options.getTrustAnchors().contains(trustAnchor)) {
			logger.warn(TrustChainException.InvalidTrustAnchor.DEFAULT_MESSAGE);

			throw new TrustChainException.InvalidTrustAnchor();
		}

		TrustChain trustChain = persistence.fetchTrustChain(oidcProvider, trustAnchor);

		boolean discover = false;

		if (trustChain == null) {
			logger.info("TrustChain not found for {}", oidcProvider);

			discover = true;
		}
		else if (!trustChain.isActive()) {
			String msg = TrustChainException.TrustChainDisabled.getDefaultMessage(
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
				oidcProvider, trustAnchor, OIDCConstants.OPENID_PROVIDER, true);
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

	private FederationEntity getOrCreateFederationEntity(String subject)
		throws OIDCException {

		FederationEntity entityConf = persistence.fetchFederationEntity(
			subject, OIDCConstants.OPENID_RELYING_PARTY, true);

		if (entityConf != null) {
			return entityConf;
		}

		WellKnownData wellKnown = prepareOnboardingData(options.getClientId(), true);

		if (!wellKnown.isComplete()) {
			return null;
		}

		return persistence.fetchFederationEntity(
			subject, OIDCConstants.OPENID_RELYING_PARTY, true);
	}

	private JSONObject getRequestedClaims(OIDCProfile profile) {
		return options.getRequestedClaimsAsJSON(profile);
	}

	private String getSubjectFromWellKnownURL(String url) {
		int x = url.indexOf(OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL);
		if(!this.options.getClientId().endsWith("/"))
			x--;
		if (x > 0) {
			return url.substring(0, x);
		}

		return "";
	}

	private String getUserKeyFromUserInfo(JSONObject userInfo) {
		String userKey = userInfo.optString(options.getUserKeyClaim(), null);

		if (userKey != null) {
			return userKey;
		}

		ClaimItem spidClaim = SPIDClaimItem.get(options.getUserKeyClaim());

		if (spidClaim != null) {
			userKey = userInfo.optString(spidClaim.getAlias(), null);

			if (userKey != null) {
				return userKey;
			}
		}
		else {
			spidClaim = SPIDClaimItem.getByAlias(options.getUserKeyClaim());

			if (spidClaim != null) {
				userKey = userInfo.optString(spidClaim.getName(), null);

				if (userKey != null) {
					return userKey;
				}
			}
		}

		ClaimItem cieClaim = CIEClaimItem.get(options.getUserKeyClaim());

		if (cieClaim != null) {
			userKey = userInfo.optString(cieClaim.getAlias(), null);

			if (userKey != null) {
				return userKey;
			}
		}
		else {
			cieClaim = CIEClaimItem.getByAlias(options.getUserKeyClaim());

			if (cieClaim != null) {
				userKey = userInfo.optString(cieClaim.getName());

				if (userKey != null) {
					return userKey;
				}
			}
		}

		return null;
	}

	private WellKnownData getWellKnownData(FederationEntity entity, boolean jsonMode)
		throws OIDCException {

		JWKSet jwkSet = JWTHelper.getJWKSetFromJSON(entity.getJwksFed());

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

		// TODO: JWSAlgorithm via default?

		String confJwkFed = options.getJwkFed();

		String confJwkCore = options.getJwkCore();
		// If not JSON Web Key is configured I have to create a new one

		if (Validator.isNullOrEmpty(confJwkFed) || Validator.isNullOrEmpty(confJwkCore)) {

			// TODO: Type has to be defined by configuration?
			RSAKey jwkFed = JWTHelper.createRSAKey(JWSAlgorithm.RS256, KeyUse.SIGNATURE);
			RSAKey jwkCoreSig = JWTHelper.createRSAKey(JWSAlgorithm.RS256, KeyUse.SIGNATURE);
			RSAKey jwkCoreEnc = JWTHelper.createRSAEncKey(JWEAlgorithm.RSA_OAEP_256, KeyUse.ENCRYPTION);

			JSONObject jsonFed = new JSONObject(jwkFed.toString());

			JWKSet jwkCoreSet = new JWKSet(Arrays.asList(jwkCoreSig, jwkCoreEnc));

			JSONArray json = new JSONArray()
					.put(jsonFed)
					.put(jwkCoreSet.toJSONObject(false));

			return WellKnownData.of(WellKnownData.STEP_ONLY_JWKS, json.toString(2));
		}

		RSAKey jwkFed = JWTHelper.parseRSAKey(confJwkFed);

		logger.info("Configured jwkFed\n" + jwkFed.toJSONString());

		JSONArray jsonPublicJwk = new JSONArray()
			.put(new JSONObject(jwkFed.toPublicJWK().toJSONObject()));

		logger.info("Configured public jwkFed\n" + jsonPublicJwk.toString(2));

		logger.info("Configured jwkFed\n" + jwkFed.toJSONString());

		JWKSet jwkCoreSet = new JWKSet();
		try {
			jwkCoreSet = JWKSet.parse(confJwkCore.toString());
		}
		catch (Exception e) {
			logger.info("Error in parsing: " + e);
		}
		JWKSet jwkFedSet = new JWKSet(jwkFed);

		JSONObject rpJson = new JSONObject();

		rpJson.put("jwks", JWTHelper.getJWKSetAsJSONObject(jwkCoreSet.toPublicJWKSet(), false));
		rpJson.put("application_type", options.getApplicationType());
		rpJson.put("client_name", options.getApplicationName());
		rpJson.put("client_id", sub);
		rpJson.put("organization_name", options.getOrganizationName());
		rpJson.put("client_registration_types", JSONUtil.asJSONArray("automatic"));
		rpJson.put("contacts", options.getContacts());
		rpJson.put("grant_types", RelyingPartyOptions.SUPPORTED_GRANT_TYPES);
		rpJson.put("response_types", RelyingPartyOptions.SUPPORTED_RESPONSE_TYPES);
		rpJson.put("redirect_uris", options.getRedirectUris());
		rpJson.put("id_token_signed_response_alg", options.getIdTokenSignedResponseAlg());
		rpJson.put("userinfo_signed_response_alg", options.getUserinfoSignedResponseAlg());
		rpJson.put("userinfo_encrypted_response_alg", options.getUserinfoEncryptedResponseAlg());
		rpJson.put("userinfo_encrypted_response_enc", options.getUserinfoEncryptedResponseEnc());
		rpJson.put("token_endpoint_auth_method", options.getTokenEndpointAuthMethod());


		JSONObject fedJson = new JSONObject();

		fedJson.put("federation_resolve_endpoint", options.getFederationResolveEndpoint());
		fedJson.put("organization_name", options.getOrganizationName());
		fedJson.put("homepage_uri", options.getHomepageUri());
		fedJson.put("policy_uri", options.getPolicyUri());
		fedJson.put("logo_uri", options.getLogoUri());
		fedJson.put("contacts",options.getFederationContacts());


		JSONObject metadataJson = new JSONObject();

		metadataJson.put(OIDCConstants.OPENID_RELYING_PARTY, rpJson);

		metadataJson.put(OIDCConstants.FEDERATION_ENTITY, fedJson);

		long iat = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);

		JSONObject json = new JSONObject();

		json.put("exp", iat + (GlobalOptions.DEFAULT_EXPIRING_MINUTES * 60));
		json.put("iat", iat);
		json.put("iss", sub);
		json.put("sub", sub);
		json.put("jwks", JWTHelper.getJWKSetAsJSONObject(jwkFedSet, false));
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
			entity.setJwksFed(
				JWTHelper.getJWKSetAsJSONArray(jwkFedSet, true, false).toString());
			entity.setJwksCore(
					JWTHelper.getJWKSetAsJSONArray(jwkCoreSet,true,false).toString());
			entity.setTrustMarks(json.getJSONArray("trust_marks").toString());
			entity.settrustMarkIssuers("{}");
			entity.setMetadata(json.getJSONObject("metadata").toString());
			entity.setActive(true);
			entity.setConstraints("{}");
			entity.setEntityType(OIDCConstants.OPENID_RELYING_PARTY);

			persistence.storeFederationEntity(entity);
		}

		if (jsonMode) {
			return WellKnownData.of(step, json.toString(), jsonPublicJwk.toString(2));
		}

		String jws = jwtHelper.createJWS(json, jwkFedSet);

		return WellKnownData.of(step, jws, jsonPublicJwk.toString(2));
	}

	private static final Logger logger = LoggerFactory.getLogger(
		RelyingPartyHandler.class);

	private final RelyingPartyOptions options;
	private final PersistenceAdapter persistence;
	private final JWTHelper jwtHelper;
	private final OAuth2Helper oauth2Helper;
	private final OIDCHelper oidcHelper;

}
