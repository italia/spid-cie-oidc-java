package it.spid.cie.oidc.handler;

import com.nimbusds.jose.jwk.JWKSet;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.spid.cie.oidc.config.RelyingPartyOptions;
import it.spid.cie.oidc.exception.OIDCException;
import it.spid.cie.oidc.exception.TrustChainException;
import it.spid.cie.oidc.helper.EntityHelper;
import it.spid.cie.oidc.helper.JWTHelper;
import it.spid.cie.oidc.helper.PKCEHelper;
import it.spid.cie.oidc.model.CachedEntityInfo;
import it.spid.cie.oidc.model.EntityConfiguration;
import it.spid.cie.oidc.model.FederationEntityConfiguration;
import it.spid.cie.oidc.model.OIDCAuthRequest;
import it.spid.cie.oidc.model.OIDCConstants;
import it.spid.cie.oidc.model.TrustChain;
import it.spid.cie.oidc.model.TrustChainBuilder;
import it.spid.cie.oidc.persistence.PersistenceAdapter;
import it.spid.cie.oidc.schemas.OIDCProfile;
import it.spid.cie.oidc.util.JSONUtil;
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
	}

	/**
	 * Build the "authorize url": the URL a RelyingParty have to send to an OpenID
	 * Provider to start an SPID authorization flow
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

		FederationEntityConfiguration entityConf = persistence.fetchFederationEntity(
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

		OIDCAuthRequest authzEntry = new OIDCAuthRequest()
			.setClientId(clientId)
			.setState(state)
			.setEndpoint(authzEndpoint)
			.setProvider(tc.getSubject())
			.setProviderId(tc.getSubject())
			.setData(authzData.toString())
			.setProviderJwks(providerJWKSet.toString())
			.setProviderConfiguration(providerMetadata.toString());

		authzEntry = persistence.storeOIDCAuthRequest(authzEntry);

		authzData.remove("code_verifier");
		authzData.put("iss", entityMetadata.getString("client_id"));
		authzData.put("sub", entityMetadata.getString("client_id"));

		String requestObj = jwtHelper.createJWS(authzData, entityJWKSet);

		authzData.put("request", requestObj);

		String url = buildURL(authzEndpoint, authzData);

		logger.info("Starting Authz request to {}", url);

		return url;
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

		TrustChain trustChain = persistence.fetchOIDCProvider(
			spidProvider, OIDCProfile.SPID);

		boolean discover = false;

		if (trustChain == null) {
			logger.info("TrustChain not found for %s", spidProvider);

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
					trustChain.getExpiredOn().toString()));
			logger.warn("Try to renew the trust chain");

			discover = true;
		}

		if (discover) {
			trustChain = getOrCreateTrustChain(
				spidProvider, trustAnchor, "openid_provider", true);
		}

		return trustChain;
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
			trustChain = new TrustChain();
//				subject, metadataType, tcb.getExpiration(), null, tcb.getChainAsString(),
//				tcb.getPartiesInvolvedAsString(), true, null, tcb.getFinalMetadata(),
//				null, trustAnchorEntity.getId(), tcb.getVerifiedTrustMarksAsString(),
//				"valid", trustAnchor);
			}
			else {
				// TODO: Update TrustChain
			}

			trustChain = persistence.storeTrustChain(trustChain);
		}

		return trustChain;
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

	private static final Logger logger = LoggerFactory.getLogger(
		RelyingPartyHandler.class);

	private final RelyingPartyOptions options;
	private final PersistenceAdapter persistence;
	private final JWTHelper jwtHelper;

}
