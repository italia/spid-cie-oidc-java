package it.spid.cie.oidc.persistence;

import it.spid.cie.oidc.exception.PersistenceException;
import it.spid.cie.oidc.model.CachedEntityInfo;
import it.spid.cie.oidc.model.FederationEntity;
import it.spid.cie.oidc.model.OIDCAuthRequest;
import it.spid.cie.oidc.model.TrustChain;
import it.spid.cie.oidc.schemas.OIDCProfile;

public interface PersistenceAdapter {

	public CachedEntityInfo fetchEntityInfo(String subject, String issuer)
		throws PersistenceException;

	public FederationEntity fetchFederationEntity(String entityType)
		throws PersistenceException;

	public FederationEntity fetchFederationEntity(String subject, boolean active)
		throws PersistenceException;

	public TrustChain fetchOIDCProvider(String subject, OIDCProfile profile)
		throws PersistenceException;

	public TrustChain fetchTrustChain(String subject, String trustAnchor)
		throws PersistenceException;

	public TrustChain fetchTrustChain(
			String subject, String trustAnchor, String metadataType)
		throws PersistenceException;

	public CachedEntityInfo storeEntityInfo(CachedEntityInfo entityInfo)
		throws PersistenceException;

	public FederationEntity storeFederationEntity(FederationEntity federationEntity)
		throws PersistenceException;

	public OIDCAuthRequest storeOIDCAuthRequest(OIDCAuthRequest authRequest)
		throws PersistenceException;

	public TrustChain storeTrustChain(TrustChain trustChain)
		throws PersistenceException;

}
