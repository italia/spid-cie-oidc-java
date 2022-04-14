package it.spid.cie.oidc.handler.extras;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import it.spid.cie.oidc.exception.PersistenceException;
import it.spid.cie.oidc.model.AuthnRequest;
import it.spid.cie.oidc.model.AuthnToken;
import it.spid.cie.oidc.model.CachedEntityInfo;
import it.spid.cie.oidc.model.FederationEntity;
import it.spid.cie.oidc.model.TrustChain;
import it.spid.cie.oidc.persistence.PersistenceAdapter;

public class MemoryStorage implements PersistenceAdapter {

	@Override
	public AuthnRequest fetchAuthnRequest(String storageId) throws PersistenceException {
		return authnRequests.get(storageId);
	}

	public AuthnToken fetchAuthnToken(String authnRequestId) {
		return authnTokens.get(authnRequestId);
	}

	@Override
	public CachedEntityInfo fetchEntityInfo(String subject, String issuer)
		throws PersistenceException {

		CachedEntityInfo entityInfo = cachedEntities.get(subject);

		if (entityInfo != null && Objects.equals(issuer, entityInfo.getIssuer())) {
			return entityInfo;
		}

		return null;
	}

	@Override
	public FederationEntity fetchFederationEntity(
			String subject, String entityType, boolean active)
		throws PersistenceException {

		FederationEntity entity = fetchFederationEntity(subject, active);

		if (entity != null && Objects.equals(entity.getEntityType(), entityType)) {
			return entity;
		}

		return null;
	}

	@Override
	public FederationEntity fetchFederationEntity(String subject, boolean active)
		throws PersistenceException {

		FederationEntity entity = doFetchFederationEntity(subject);

		if (entity != null && entity.isActive() == active) {
			return entity;
		}

		return null;
	}

	@Override
	public TrustChain fetchTrustChain(String subject, String trustAnchor)
		throws PersistenceException {

		String key = subject + "|" + trustAnchor;

		return trustChains.get(key);
	}

	@Override
	public TrustChain fetchTrustChain(
			String subject, String trustAnchor, String metadataType)
		throws PersistenceException {

		TrustChain trustChain = fetchTrustChain(subject, trustAnchor);

		if (trustChain != null && Objects.equals(trustChain.getType(), metadataType)) {
			return trustChain;
		}

		return null;
	}

	@Override
	public List<AuthnRequest> findAuthnRequests(String state)
		throws PersistenceException {

		AuthnRequest authnRequest = authnRequests.get(state);

		if (authnRequest != null) {
			return Arrays.asList(authnRequest);
		}
		else {
			return Collections.emptyList();
		}
	}

	@Override
	public List<AuthnToken> findAuthnTokens(String userKey) throws PersistenceException {
		List<AuthnToken> result = new ArrayList<>();

		for (AuthnToken authnToken : authnTokens.values()) {
			if (Objects.equals(authnToken.getUserKey(), userKey)) {
				result.add(authnToken);
			}
		}

		return result;
	}

	@Override
	public CachedEntityInfo storeEntityInfo(CachedEntityInfo entityInfo)
		throws PersistenceException {

		cachedEntities.put(entityInfo.getSubject(), entityInfo);

		return entityInfo;
	}

	@Override
	public FederationEntity storeFederationEntity(FederationEntity federationEntity)
		throws PersistenceException {

		federationEntities.put(federationEntity.getSubject(), federationEntity);

		return federationEntity;
	}

	@Override
	public AuthnRequest storeOIDCAuthnRequest(AuthnRequest authnRequest)
		throws PersistenceException {

		authnRequest.setStorageId(authnRequest.getState());

		authnRequests.put(authnRequest.getState(), authnRequest);

		return authnRequest;
	}

	@Override
	public AuthnToken storeOIDCAuthnToken(AuthnToken authnToken)
		throws PersistenceException {

		authnTokens.put(authnToken.getAuthnRequestId(), authnToken);

		return authnToken;
	}

	@Override
	public TrustChain storeTrustChain(TrustChain trustChain) throws PersistenceException {
		String key = trustChain.getSubject() + "|" + trustChain.getTrustAnchor();

		trustChains.put(key, trustChain);

		return trustChain;
	}

	protected FederationEntity doFetchFederationEntity(String subject)
		throws PersistenceException {

		return federationEntities.get(subject);
	}

	private Map<String, FederationEntity> federationEntities = new HashMap<>();
	private Map<String, TrustChain> trustChains = new HashMap<>();
	private Map<String, CachedEntityInfo> cachedEntities = new HashMap<>();
	private Map<String, AuthnRequest> authnRequests = new HashMap<>();
	private Map<String, AuthnToken> authnTokens = new HashMap<>();

}
