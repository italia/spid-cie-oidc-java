package it.spid.cie.oidc.spring.boot.relying.party.persistence;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import it.spid.cie.oidc.exception.PersistenceException;
import it.spid.cie.oidc.model.CachedEntityInfo;
import it.spid.cie.oidc.model.FederationEntity;
import it.spid.cie.oidc.model.OIDCAuthRequest;
import it.spid.cie.oidc.model.TrustChain;
import it.spid.cie.oidc.persistence.PersistenceAdapter;
import it.spid.cie.oidc.schemas.OIDCProfile;
import it.spid.cie.oidc.spring.boot.relying.party.persistence.model.FederationEntityModel;
import it.spid.cie.oidc.spring.boot.relying.party.persistence.model.FederationEntityRepository;

@Component
public class H2PersistenceImpl implements PersistenceAdapter {

	@Override
	public CachedEntityInfo fetchEntityInfo(String subject, String issuer) throws PersistenceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public FederationEntity fetchFederationEntity(String entityType)
		throws PersistenceException {

		try {
			FederationEntityModel model = federationEntityRepository.fetchByEntityType(
				entityType);

			if (model != null) {
				return model.toFederationEntity();
			}
		}
		catch (Exception e) {
			throw new PersistenceException(e);
		}

		return null;
	}

	@Override
	public FederationEntity fetchFederationEntity(String subject, boolean active)
		throws PersistenceException {

		try {
			FederationEntityModel model = federationEntityRepository.fetchBySubActive(
				subject, active);

			if (model != null) {
				return model.toFederationEntity();
			}
		}
		catch (Exception e) {
			throw new PersistenceException(e);
		}

		return null;
	}

	@Override
	public TrustChain fetchOIDCProvider(String subject, OIDCProfile profile) throws PersistenceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public TrustChain fetchTrustChain(String subject, String trustAnchor) throws PersistenceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public TrustChain fetchTrustChain(String subject, String trustAnchor, String metadataType)
			throws PersistenceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CachedEntityInfo storeEntityInfo(CachedEntityInfo entityInfo) throws PersistenceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public FederationEntity storeFederationEntity(FederationEntity federationEntity)
		throws PersistenceException {

		try {
			FederationEntityModel model = FederationEntityModel.of(federationEntity);

			model = federationEntityRepository.save(model);

			return model.toFederationEntity();
		}
		catch (Exception e) {
			throw new PersistenceException(e);
		}
	}

	@Override
	public OIDCAuthRequest storeOIDCAuthRequest(OIDCAuthRequest authRequest) throws PersistenceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public TrustChain storeTrustChain(TrustChain trustChain) throws PersistenceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Autowired
	private FederationEntityRepository federationEntityRepository;

}
