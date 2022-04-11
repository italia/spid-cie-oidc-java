package it.spid.cie.oidc.handler.extras;

import it.spid.cie.oidc.callback.RelyingPartyLogoutCallback;
import it.spid.cie.oidc.model.AuthnRequest;
import it.spid.cie.oidc.model.AuthnToken;

public class MockRelyingPartyLogoutCallback implements RelyingPartyLogoutCallback {

	@Override
	public void logout(String userKey, AuthnRequest authnRequest, AuthnToken authnToken) {
		// TODO Auto-generated method stub
	}

}
