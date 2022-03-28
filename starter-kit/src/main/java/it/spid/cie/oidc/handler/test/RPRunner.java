package it.spid.cie.oidc.handler.test;

import it.spid.cie.oidc.config.RelyingPartyOptions;
import it.spid.cie.oidc.handler.RelyingPartyHandler;

public class RPRunner {

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub

		RelyingPartyOptions options = new RelyingPartyOptions()
			.setDefaultJWEAlgorithm("")
			.setAllowedEncryptionAlgs("pippo");

		RelyingPartyHandler handler = new RelyingPartyHandler(options, null);

	}

}
