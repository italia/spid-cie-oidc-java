package it.spid.cie.oidc.schemas;

import it.spid.cie.oidc.util.Validator;

/**
 * This class contains the mandatory informations needed to render an OIDC Provider inside
 * the list connected to "SignIn with SPID" and "SignIn with CIE" buttons
 *
 * @author Mauro Mariuzzo
 */
public class ProviderButtonInfo {

	private final String subject;
	private final String organizationName;
	private final String logoUrl;

	public ProviderButtonInfo(String subject, String organizationName, String logoUrl) {
		this.subject = subject;
		this.organizationName = organizationName;
		this.logoUrl = logoUrl;
	}

	public String getSubject() {
		return subject;
	}

	public String getOrganizationName() {
		return organizationName;
	}

	public String getLogoUrl() {
		return logoUrl;
	}

	public String getTitle() {
		if (Validator.isNullOrEmpty(organizationName)) {
			return subject;
		}

		return organizationName;
	}

}
