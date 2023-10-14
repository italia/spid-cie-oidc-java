package it.spid.cie.oidc.schemas;

import java.io.Serializable;
import java.util.Map;

import it.spid.cie.oidc.util.Validator;
import net.jcip.annotations.Immutable;

@Immutable
public abstract class ClaimItem implements Serializable {

	public static final String ATTRIBUTE_BASE_URI = "https://attributes.eid.gov.it/";

	private static final long serialVersionUID = 7770619618195001323L;

	private final String name;
	private final String alias;

	public final String getAlias() {
		return alias;
	}

	public final String getName() {
		return name;
	}

	protected ClaimItem(
		String name, String alias, Map<String, ClaimItem> claims,
		Map<String, String> aliasMap) {

		if (Validator.isNullOrEmpty(name) || Validator.isNullOrEmpty(alias)) {
			throw new IllegalArgumentException("name or alias cannot be null");
		}

		if (aliasMap.containsKey(alias)) {
			throw new IllegalArgumentException("alias already configured");
		}

		if (claims.containsKey(name)) {
			throw new IllegalArgumentException("name already configured");
		}

		aliasMap.put(alias, name);

		this.name = name;
		this.alias = alias;

		claims.put(name, this);
	}

}
