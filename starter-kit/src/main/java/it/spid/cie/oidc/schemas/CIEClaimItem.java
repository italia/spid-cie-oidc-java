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
	public static final ClaimItem FISCAL_NUMBER = withDefaults("fiscal_number");
	public static final ClaimItem EMAIL = withDefaults("email");
	public static final ClaimItem DIGITAL_ADDRESS = withDefaults("digital_address");
	public static final ClaimItem MAIL = withDefaults("mail");
	public static final ClaimItem ADDRESS = withDefaults("address");
	public static final ClaimItem COMPANY_NAME = withDefaults("company_name");
	public static final ClaimItem COUNTRY_OF_BIRTH = withDefaults("county_of_birth");
	public static final ClaimItem DATE_OF_BIRTH = withDefaults("date_of_birth");
	public static final ClaimItem PLACE_OF_BIRTH = withDefaults("place_of_birth");
	public static final ClaimItem EXPIRATION_DATE = withDefaults("expiration_date");
	public static final ClaimItem GENDER = withDefaults("gender");
	public static final ClaimItem ID_CARD = withDefaults("id_card");
	public static final ClaimItem IVA_CODE = withDefaults("iva_code");
	public static final ClaimItem MOBILE_PHONE = withDefaults("mobile_phone");
	public static final ClaimItem REGISTERED_OFFICE = withDefaults("registered_office");
	public static final ClaimItem SPID_CODE = withDefaults("spid_code");
	public static final ClaimItem COMPANY_FISCAL_NUMBER = withDefaults(
		"company_fiscal_number");
	public static final ClaimItem DOMICILE_STREET_ADDRESS = withDefaults(
		"domicile_street_address");
	public static final ClaimItem DOMICILE_POSTAL_CODE = withDefaults(
		"domicile_postal_code");
	public static final ClaimItem DOMICILE_MUNICIPALITY = withDefaults(
		"domicile_municipality");
	public static final ClaimItem DOMICILE_PROVINCE = withDefaults("domicile_province");
	public static final ClaimItem DOMICILE_NATION = withDefaults("domicile_nation");

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

}
