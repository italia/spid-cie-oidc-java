package it.spid.cie.oidc.model;

public class AuthnRequest extends BaseModel {

	private String clientId;
	private String state;
	private String endpoint;
	private String data;
	private boolean successful;
	private String providerConfiguration;
	private String provider;
	private String providerId;
	private String providerJwks;

	public String getClientId() {
		return clientId;
	}

	public String getEndpoint() {
		return endpoint;
	}

	public String getData() {
		return data;
	}

	public String getProvider() {
		return provider;
	}

	public String getProviderConfiguration() {
		return providerConfiguration;
	}

	public String getProviderId() {
		return providerId;
	}

	public String getProviderJwks() {
		return providerJwks;
	}

	public String getState() {
		return state;
	}

	public boolean isSuccessful() {
		return successful;
	}

	public AuthnRequest setClientId(String clientId) {
		this.clientId = clientId;

		return this;
	}

	public AuthnRequest setEndpoint(String endpoint) {
		this.endpoint = endpoint;

		return this;
	}

	public AuthnRequest setData(String data) {
		this.data = data;

		return this;
	}

	public AuthnRequest setProvider(String provider) {
		this.provider = provider;

		return this;
	}

	public AuthnRequest setProviderConfiguration(String providerConfiguration) {
		this.providerConfiguration = providerConfiguration;

		return this;
	}

	public AuthnRequest setProviderId(String providerId) {
		this.providerId = providerId;

		return this;
	}

	public AuthnRequest setProviderJwks(String providerJwks) {
		this.providerJwks = providerJwks;

		return this;
	}

	public AuthnRequest setState(String state) {
		this.state = state;

		return this;
	}

	public AuthnRequest setSuccessful(boolean successful) {
		this.successful = successful;

		return this;
	}

}
