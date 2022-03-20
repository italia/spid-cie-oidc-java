package it.spid.cie.oidc.relying.party.model;

public class OidcConstants {

	public static final String OPENID_RELYING_PARTY = "openid_relying_party";

	public static final String OIDCFED_FEDERATION_WELLKNOWN_URL =
		".well-known/openid-federation";

	public static final int FEDERATION_DEFAULT_EXP = 2880;

	public static final String[] RP_GRANT_TYPES = new String[] {
		"refresh_token", "authorization_code" };

	public static final String[] RP_RESPONSE_TYPES = new String[] { "code" };

}
