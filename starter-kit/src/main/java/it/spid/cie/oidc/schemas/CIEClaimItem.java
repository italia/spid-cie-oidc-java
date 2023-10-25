package it.spid.cie.oidc.schemas;

import java.util.HashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;

@Immutable
public final class CIEClaimItem extends ClaimItem {

	private static final long serialVersionUID = 4863754291794923639L;

	private static final Map<String, ClaimItem> claims = new HashMap<>();
	private static final Map<String, String> aliasMap = new HashMap<>();

	public static final ClaimItem GIVEN_NAME = withDefaults("given_name");
	public static final ClaimItem FAMILY_NAME = withDefaults("family_name");
	public static final ClaimItem PLACE_OF_BIRTH = withDefaults("place_of_birth");
	public static final ClaimItem DATE_OF_BIRTH = withDefaults("birthdate");
	public static final ClaimItem GENDER = withDefaults("gender");
	public static final ClaimItem FISCAL_NUMBER = withDefaultURI("fiscal_number", "fiscal_number");
	public static final ClaimItem ID_CARD = withDefaults("document_details");
	public static final ClaimItem MOBILE_PHONE = withDefaults("phone_number");
	public static final ClaimItem MOBILE_PHONE_VERIFIED = withDefaults("phone_number_verified");
	public static final ClaimItem LANDLINE_NUMBER = withDefaultURI("landline_number", "landline_number");
	public static final ClaimItem EMAIL = withDefaults("email");
	public static final ClaimItem EMAIL_VERIFIED = withDefaults("email_verified");
	public static final ClaimItem DIGITAL_ADDRESS = withDefaultURI("e_delivery_service", "e_delivery_service");
	public static final ClaimItem ADDRESS = withDefaults("address");

	public static ClaimItem get(String name) {
		return claims.get(name);
	}

	public static ClaimItem getByAlias(String alias) {
		String name = aliasMap.get(alias);

		if (name != null) {
			return get(name);
		}

		return null;
	}

	public static ClaimItem registerItem(String name, String alias) {
		return new CIEClaimItem(name, alias);
	}

	protected CIEClaimItem(String name, String alias) {
		super(name, alias, claims, aliasMap);
	}

	private static CIEClaimItem withDefaults(String name) {
		return new CIEClaimItem(name, name);
	}

	private static CIEClaimItem withDefaultURI(String name, String aliasSuffix) {
		return new CIEClaimItem(name, ATTRIBUTE_BASE_URI + aliasSuffix);
	}

}
