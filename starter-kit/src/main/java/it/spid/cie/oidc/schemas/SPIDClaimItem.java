package it.spid.cie.oidc.schemas;

import java.util.HashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;

@Immutable
public final class SPIDClaimItem extends ClaimItem {

	private static final long serialVersionUID = -5057584026789547391L;

	private static final Map<String, ClaimItem> claims = new HashMap<>();
	private static final Map<String, String> aliasMap = new HashMap<>();

	public static final ClaimItem SPID_CODE = withDefaultURI("spid_code");
	public static final ClaimItem NAME = withDefaults("given_name");
	public static final ClaimItem FAMILY_NAME = withDefaults("family_name");
	public static final ClaimItem PLACE_OF_BIRTH = withDefaults("place_of_birth");
	public static final ClaimItem DATE_OF_BIRTH = withDefaults("birthdate");
	public static final ClaimItem GENDER = withDefaults("gender");
	public static final ClaimItem COMPANY_NAME = withDefaultURI(
			"company_name", "company_name");
	public static final ClaimItem REGISTERED_OFFICE = withDefaultURI(
			"registered_office", "registered_office");
	public static final ClaimItem FISCAL_NUMBER = withDefaultURI(
			"fiscal_number", "fiscal_number");
	public static final ClaimItem COMPANY_FISCAL_NUMBER = withDefaultURI(
			"company_fiscal_number", "company_fiscal_number");
	public static final ClaimItem VAT_NUMBER = withDefaultURI("vat_number", "vat_number");
	public static final ClaimItem ID_CARD = withDefaults("document_details");
	public static final ClaimItem MOBILE_PHONE = withDefaults("phone_number");
	public static final ClaimItem EMAIL = withDefaults("email");
	public static final ClaimItem DIGITAL_ADDRESS = withDefaultURI(
			"e_delivery_service", "e_delivery_service");
	public static final ClaimItem EXPIRATION_DATE = withDefaultURI(
			"eid_exp_date", "eid_exp_date");
	public static final ClaimItem ADDRESS = withDefaults("address");

	public static final ClaimItem get(String name) {
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
		return new SPIDClaimItem(name, alias);
	}

	protected SPIDClaimItem(String name, String alias) {
		super(name, alias, claims, aliasMap);
	}

	private static ClaimItem withDefaultURI(String name) {
		return new SPIDClaimItem(name, ATTRIBUTE_BASE_URI + name);
	}

	private static ClaimItem withDefaultURI(String name, String aliasSuffix) {
		return new SPIDClaimItem(name, ATTRIBUTE_BASE_URI + aliasSuffix);
	}
	private static ClaimItem withDefaults(String name) {
		return new SPIDClaimItem(name, name);
	}
}
