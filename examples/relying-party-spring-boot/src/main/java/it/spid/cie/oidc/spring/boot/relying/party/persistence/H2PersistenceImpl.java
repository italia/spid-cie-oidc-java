package it.spid.cie.oidc.spring.boot.relying.party.persistence;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import it.spid.cie.oidc.exception.PersistenceException;
import it.spid.cie.oidc.model.AuthnRequest;
import it.spid.cie.oidc.model.AuthnToken;
import it.spid.cie.oidc.model.CachedEntityInfo;
import it.spid.cie.oidc.model.FederationEntity;
import it.spid.cie.oidc.model.TrustChain;
import it.spid.cie.oidc.persistence.PersistenceAdapter;
import it.spid.cie.oidc.spring.boot.relying.party.persistence.model.AuthnRequestModel;
import it.spid.cie.oidc.spring.boot.relying.party.persistence.model.AuthnRequestRepository;
import it.spid.cie.oidc.spring.boot.relying.party.persistence.model.AuthnTokenModel;
import it.spid.cie.oidc.spring.boot.relying.party.persistence.model.AuthnTokenRepository;
import it.spid.cie.oidc.spring.boot.relying.party.persistence.model.EntityInfoModel;
import it.spid.cie.oidc.spring.boot.relying.party.persistence.model.EntityInfoRepository;
import it.spid.cie.oidc.spring.boot.relying.party.persistence.model.FederationEntityModel;
import it.spid.cie.oidc.spring.boot.relying.party.persistence.model.FederationEntityRepository;
import it.spid.cie.oidc.spring.boot.relying.party.persistence.model.TrustChainModel;
import it.spid.cie.oidc.spring.boot.relying.party.persistence.model.TrustChainRepository;
import it.spid.cie.oidc.util.GetterUtil;

@Component
public class H2PersistenceImpl implements PersistenceAdapter {

	@Override
	public AuthnRequest fetchAuthnRequest(String storageId) throws PersistenceException {
		try {
			long id = GetterUtil.getLong(storageId);

			Optional<AuthnRequestModel> model = authnRequestRepository.findById(id);

			if (model.isPresent()) {
				return model.get().toAuthnRequest();
			}
		}
		catch (Exception e) {
			throw new PersistenceException(e);
		}

		return null;
	}

	@Override
	public CachedEntityInfo fetchEntityInfo(String subject, String issuer)
		throws PersistenceException {

		try {
			EntityInfoModel model = entityInfoRepository.fetchEntity(
				subject, issuer);

			if (model != null) {
				return model.toCachedEntityInfo();
			}
		}
		catch (Exception e) {
			throw new PersistenceException(e);
		}

		return null;
	}

	@Override
	public FederationEntity fetchFederationEntity(
			String subject, String entityType, boolean active)
		throws PersistenceException {

		try {
			FederationEntityModel model = federationEntityRepository.fetchBySubActive(
				subject, true);

			if (model != null && Objects.equals(entityType, model.getEntityType())) {
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

	/*
	@Override
	public TrustChain fetchOIDCProvider(String subject, OIDCProfile profile)
		throws PersistenceException {
		logger.info("TODO fetchOIDCProvider");
		// TODO Auto-generated method stub
		return null;
	}
	*/

	@Override
	public TrustChain fetchTrustChain(String subject, String trustAnchor)
		throws PersistenceException {

		try {
			TrustChainModel model = trustChainRepository.fetchBySub_TASub(
				subject, trustAnchor);

			if (model != null) {
				EntityInfoModel trustAnchorModel = entityInfoRepository.fetchEntity(
					trustAnchor, trustAnchor);

				return model.toTrustChain(trustAnchorModel);
			}
		}
		catch (Exception e) {
			throw new PersistenceException(e);
		}

		return null;
	}

	@Override
	public TrustChain fetchTrustChain(
			String subject, String trustAnchor, String metadataType)
		throws PersistenceException {

		try {
			TrustChainModel model = trustChainRepository.fetchBySub_TASub_T(
				subject, trustAnchor, metadataType);

			if (model != null) {
				EntityInfoModel trustAnchorModel = entityInfoRepository.fetchEntity(
					trustAnchor, trustAnchor);

				return model.toTrustChain(trustAnchorModel);
			}
		}
		catch (Exception e) {
			throw new PersistenceException(e);
		}

		return null;
	}

	@Override
	public List<AuthnRequest> findAuthnRequests(String state)
		throws PersistenceException {

		List<AuthnRequest> result = new ArrayList<>();

		try {
			List<AuthnRequestModel> models = authnRequestRepository.findByState(state);

			for (AuthnRequestModel model : models) {
				result.add(model.toAuthnRequest());
			}

			return result;
		}
		catch (Exception e) {
			throw new PersistenceException(e);
		}
	}

	@Override
	public List<AuthnToken> findAuthnTokens(String userKey) throws PersistenceException {
		List<AuthnToken> result = new ArrayList<>();

		try {
			List<AuthnTokenModel> models = authnTokenRepository.findUserTokens(userKey);

			for (AuthnTokenModel model : models) {
				result.add(model.toAuthnToken());
			}

			return result;
		}
		catch (Exception e) {
			throw new PersistenceException(e);
		}
	}

	@Override
	public CachedEntityInfo storeEntityInfo(CachedEntityInfo entityInfo)
		throws PersistenceException {

		try {
			EntityInfoModel model = EntityInfoModel.of(entityInfo);

			if (model.getId() != null && model.getId() > 0) {
				model.setModified(LocalDateTime.now());
			}

			model = entityInfoRepository.save(model);

			return model.toCachedEntityInfo();
		}
		catch (Exception e) {
			throw new PersistenceException(e);
		}
	}

	@Override
	public FederationEntity storeFederationEntity(FederationEntity federationEntity)
		throws PersistenceException {

		try {
			FederationEntityModel model = FederationEntityModel.of(federationEntity);

			if (model.getId() != null && model.getId() > 0) {
				model.setModified(LocalDateTime.now());
			}

			model = federationEntityRepository.save(model);

			return model.toFederationEntity();
		}
		catch (Exception e) {
			throw new PersistenceException(e);
		}
	}

	@Override
	public AuthnRequest storeOIDCAuthnRequest(AuthnRequest authnRequest)
		throws PersistenceException {

		try {
			AuthnRequestModel model = AuthnRequestModel.of(authnRequest);

			if (model.getId() != null && model.getId() > 0) {
				model.setModified(LocalDateTime.now());
			}

			model = authnRequestRepository.save(model);

			return model.toAuthnRequest();
		}
		catch (Exception e) {
			throw new PersistenceException(e);
		}
	}

	@Override
	public AuthnToken storeOIDCAuthnToken(AuthnToken authnToken)
		throws PersistenceException {

		try {
			AuthnTokenModel model = AuthnTokenModel.of(authnToken);

			if (model.getId() != null && model.getId() > 0) {
				model.setModified(LocalDateTime.now());
			}

			model = authnTokenRepository.save(model);

			return model.toAuthnToken();
		}
		catch (Exception e) {
			throw new PersistenceException(e);
		}
	}

	@Override
	public TrustChain storeTrustChain(TrustChain trustChain) throws PersistenceException {
		try {
			EntityInfoModel trustAnchorModel = entityInfoRepository.fetchEntity(
				trustChain.getTrustAnchor(), trustChain.getTrustAnchor());

			TrustChainModel model = TrustChainModel.of(trustChain, trustAnchorModel);

			if (model.getId() != null && model.getId() > 0) {
				model.setModified(LocalDateTime.now());
			}

			model = trustChainRepository.save(model);

			return model.toTrustChain(trustAnchorModel);
		}
		catch (Exception e) {
			throw new PersistenceException(e);
		}
	}

	@SuppressWarnings("unused")
	private static final Logger logger = LoggerFactory.getLogger(H2PersistenceImpl.class);

	@Autowired
	private AuthnRequestRepository authnRequestRepository;

	@Autowired
	private AuthnTokenRepository authnTokenRepository;

	@Autowired
	private EntityInfoRepository entityInfoRepository;

	@Autowired
	private FederationEntityRepository federationEntityRepository;

	@Autowired
	private TrustChainRepository trustChainRepository;

}
