package it.spid.cie.oidc.spring.boot.relying.party.config;

import org.json.JSONObject;

public abstract class BaseConfig {

	public abstract JSONObject toJSON();

	public String toJSONString() {
		return toJSON().toString();
	}

	public String toJSONString(int indentFactor) {
		return toJSON().toString(indentFactor);
	}

}
