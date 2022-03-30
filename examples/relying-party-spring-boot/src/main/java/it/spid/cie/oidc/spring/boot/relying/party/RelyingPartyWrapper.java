package it.spid.cie.oidc.spring.boot.relying.party;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import it.spid.cie.oidc.config.RelyingPartyOptions;
import it.spid.cie.oidc.exception.OIDCException;
import it.spid.cie.oidc.handler.RelyingPartyHandler;
import it.spid.cie.oidc.schemas.WellKnownData;
import it.spid.cie.oidc.spring.boot.relying.party.config.OidcConfig;
import it.spid.cie.oidc.spring.boot.relying.party.persistence.H2PersistenceImpl;

@Component
public class RelyingPartyWrapper {

	public String getAuthorizeURL(
			String spidProvider, String trustAnchor, String redirectUri, String scope,
			String profile, String prompt)
		throws OIDCException {

		return relyingPartyHandler.getAuthorizeURL(
			spidProvider, trustAnchor, redirectUri, scope, profile, prompt);
	}

	public WellKnownData getWellKnownData(String requestURL, boolean jsonMode)
		throws OIDCException {

		return relyingPartyHandler.getWellKnownData(requestURL, jsonMode);
	}

	@PostConstruct
	private void postConstruct() throws OIDCException {
		RelyingPartyOptions options = new RelyingPartyOptions()
			.setDefaultTrustAnchor(oidcConfig.getDefaultTrustAnchor())
			.setSPIDProviders(oidcConfig.getIdentityProviders())
			.setTrustAnchors(oidcConfig.getTrustAnchors())
			.setApplicationName(oidcConfig.getRelyingParty().getApplicationName())
			.setClientId(oidcConfig.getRelyingParty().getClientId())
			.setRedirectUris(oidcConfig.getRelyingParty().getRedirectUris())
			.setContacts(oidcConfig.getRelyingParty().getContacts())
			.setJWK(oidcConfig.getRelyingParty().getJwk())
			.setTrustMarks(oidcConfig.getRelyingParty().getTrustMarks());

		relyingPartyHandler = new RelyingPartyHandler(options, persistenceImpl);
	}

	private static Logger logger = LoggerFactory.getLogger(RelyingPartyWrapper.class);

	@Autowired
	private OidcConfig oidcConfig;

	@Autowired
	private H2PersistenceImpl persistenceImpl;

	private RelyingPartyHandler relyingPartyHandler;

}
