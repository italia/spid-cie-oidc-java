package it.spid.cie.oidc.schemas;

import java.util.HashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;

@Immutable
public final class SPIDClaimItem extends ClaimItem {

	// These private elements have to stay here to be initialized before any other
	// static element

	private static final Map<String, ClaimItem> claims = new HashMap<>();
	private static final Map<String, String> aliasMap = new HashMap<>();

	public static final ClaimItem NAME = withDefaultURI("name");
	public static final ClaimItem FAMILY_NAME = withDefaultURI(
		"family_name", "familyName");
	public static final ClaimItem FISCAL_NUMBER = withDefaultURI(
		"fiscal_number", "fiscalNumber");
	public static final ClaimItem EMAIL = withDefaultURI("email");
	public static final ClaimItem DIGITAL_ADDRESS = withDefaultURI(
		"digital_address", "digitalAddress");
	public static final ClaimItem MAIL = withDefaultURI("mail");
	public static final ClaimItem ADDRESS = withDefaultURI("address");
	public static final ClaimItem COMPANY_NAME = withDefaultURI(
		"company_name", "companyName");
	public static final ClaimItem COUNTRY_OF_BIRTH = withDefaultURI(
		"county_of_birth", "countyOfBirth");
	public static final ClaimItem DATE_OF_BIRTH = withDefaultURI(
		"date_of_birth", "dateOfBirth");
	public static final ClaimItem PLACE_OF_BIRTH = withDefaultURI(
		"place_of_birth", "placeOfBirth");
	public static final ClaimItem EXPIRATION_DATE = withDefaultURI(
		"expiration_date", "expirationDate");
	public static final ClaimItem GENDER = withDefaultURI("gender");
	public static final ClaimItem ID_CARD = withDefaultURI("id_card", "idcard");
	public static final ClaimItem IVA_CODE = withDefaultURI("iva_code", "ivaCode");  //TODO: VAT Code?
	public static final ClaimItem MOBILE_PHONE = withDefaultURI(
		"mobile_phone", "mobilePhone");
	public static final ClaimItem REGISTERED_OFFICE = withDefaultURI(
		"registered_office", "registeredOffice");
	public static final ClaimItem SPID_CODE = withDefaultURI("spid_code", "spidCode");
	public static final ClaimItem COMPANY_FISCAL_NUMBER = withDefaultURI(
		"company_fiscal_number", "companyFiscalNumber");
	public static final ClaimItem DOMICILE_STREET_ADDRESS = withDefaultURI(
		"domicile_street_address", "domicileStreetAddress");
	public static final ClaimItem DOMICILE_POSTAL_CODE = withDefaultURI(
		"domicile_postal_code", "domicilePostalCode");
	public static final ClaimItem DOMICILE_MUNICIPALITY = withDefaultURI(
		"domicile_municipality", "domicileMunicipality");
	public static final ClaimItem DOMICILE_PROVINCE = withDefaultURI(
		"domicile_province", "domicileProvince");
	public static final ClaimItem DOMICILE_NATION = withDefaultURI(
		"domicile_nation", "domicileNation");

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

	private static final long serialVersionUID = -5057584026789547391L;

}
