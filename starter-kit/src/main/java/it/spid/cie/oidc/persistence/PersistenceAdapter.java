package it.spid.cie.oidc.persistence;

import java.util.List;

import it.spid.cie.oidc.exception.PersistenceException;
import it.spid.cie.oidc.model.AuthnRequest;
import it.spid.cie.oidc.model.AuthnToken;
import it.spid.cie.oidc.model.CachedEntityInfo;
import it.spid.cie.oidc.model.FederationEntity;
import it.spid.cie.oidc.model.TrustChain;

public interface PersistenceAdapter {

	public AuthnRequest fetchAuthnRequest(String storageId)
		throws PersistenceException;

	public CachedEntityInfo fetchEntityInfo(String subject, String issuer)
		throws PersistenceException;

	public FederationEntity fetchFederationEntity(
			String subject, String entityType, boolean active)
		throws PersistenceException;

	public FederationEntity fetchFederationEntity(String subject, boolean active)
		throws PersistenceException;

	public TrustChain fetchTrustChain(String subject, String trustAnchor)
		throws PersistenceException;

	public TrustChain fetchTrustChain(
			String subject, String trustAnchor, String metadataType)
		throws PersistenceException;

	public List<AuthnRequest> findAuthnRequests(String state)
		throws PersistenceException;

	public List<AuthnToken> findAuthnTokens(String userKey)
		throws PersistenceException;

	public CachedEntityInfo storeEntityInfo(CachedEntityInfo entityInfo)
		throws PersistenceException;

	public FederationEntity storeFederationEntity(FederationEntity federationEntity)
		throws PersistenceException;

	public AuthnRequest storeOIDCAuthnRequest(AuthnRequest authnRequest)
		throws PersistenceException;

	public AuthnToken storeOIDCAuthnToken(AuthnToken authnToken)
		throws PersistenceException;

	public TrustChain storeTrustChain(TrustChain trustChain)
		throws PersistenceException;

}
