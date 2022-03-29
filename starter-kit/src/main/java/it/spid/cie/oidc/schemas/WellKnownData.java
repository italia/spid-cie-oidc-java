package it.spid.cie.oidc.schemas;

import net.jcip.annotations.Immutable;

/**
 * Each Federation Entity expose its information via the ".well-known/openid-federation"
 * endpoint.<br/>
 * These informations required a registration flow to become complete. This object allows
 * to identity the status of this flow
 *
 * @author Mmauro Mariuzzo
 */
@Immutable
public class WellKnownData {

	public static final int STEP_ONLY_JWKS = 0;
	public static final int STEP_INTERMEDIATE = 1;
	public static final int STEP_COMPLETE = 2;

	public static WellKnownData of(int step, String value) {
		return new WellKnownData(step, value);
	}

	private WellKnownData(int step, String value) {
		this.step = step;
		this.value = value;
	}

	public int getStep() {
		return step;
	}

	public String getValue() {
		return value;
	}

	private final int step;
	private final String value;

}
