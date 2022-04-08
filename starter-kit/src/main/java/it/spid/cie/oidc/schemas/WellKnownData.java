package it.spid.cie.oidc.schemas;

import net.jcip.annotations.Immutable;

/**
 * Each Federation Entity expose its information via the ".well-known/openid-federation"
 * endpoint.<br/>
 * These informations required a registration flow to become complete. This object allows
 * to identity the status of this flow
 *
 * @author Mauro Mariuzzo
 */
@Immutable
public class WellKnownData {

	public static final int STEP_ONLY_JWKS = 0;
	public static final int STEP_INTERMEDIATE = 1;
	public static final int STEP_COMPLETE = 2;

	private final int step;
	private final String value;
	private final String publicJwks;

	public static WellKnownData of(int step, String value) {
		return new WellKnownData(step, value, "[]");
	}

	public static WellKnownData of(int step, String value, String publicJwks) {
		return new WellKnownData(step, value, publicJwks);
	}

	private WellKnownData(int step, String value, String publicJwks) {
		this.step = step;
		this.value = value;
		this.publicJwks = publicJwks;
	}

	public int getStep() {
		return step;
	}

	public String getValue() {
		return value;
	}

	public String getPublicJwks() {
		return publicJwks;
	}

	public boolean hasOnlyJwks() {
		return step == STEP_ONLY_JWKS;
	}

	public boolean isComplete() {
		return step == STEP_COMPLETE;
	}

	public boolean isIntermediate() {
		return step == STEP_INTERMEDIATE;
	}

}
