package it.spid.cie.oidc.callback;

import it.spid.cie.oidc.model.AuthnRequest;
import it.spid.cie.oidc.model.AuthnToken;

public interface RelyingPartyLogoutCallback {

	public void logout(String userKey, AuthnRequest authnRequest, AuthnToken authnToken);

}
