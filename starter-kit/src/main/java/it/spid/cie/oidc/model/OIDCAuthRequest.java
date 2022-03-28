package it.spid.cie.oidc.model;

public class OIDCAuthRequest extends BaseModel {

	public OIDCAuthRequest() {
		super();
	}

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

	public OIDCAuthRequest setClientId(String clientId) {
		this.clientId = clientId;

		return this;
	}

	public OIDCAuthRequest setEndpoint(String endpoint) {
		this.endpoint = endpoint;

		return this;
	}

	public OIDCAuthRequest setData(String data) {
		this.data = data;

		return this;
	}

	public OIDCAuthRequest setProvider(String provider) {
		this.provider = provider;

		return this;
	}

	public OIDCAuthRequest setProviderConfiguration(String providerConfiguration) {
		this.providerConfiguration = providerConfiguration;

		return this;
	}

	public OIDCAuthRequest setProviderId(String providerId) {
		this.providerId = providerId;

		return this;
	}

	public OIDCAuthRequest setProviderJwks(String providerJwks) {
		this.providerJwks = providerJwks;

		return this;
	}

	public OIDCAuthRequest setState(String state) {
		this.state = state;

		return this;
	}

	public OIDCAuthRequest setSuccessful(boolean successful) {
		this.successful = successful;

		return this;
	}



	private String clientId;
	private String state;
	private String endpoint;
	private String data;
	private boolean successful;
	private String providerConfiguration;
	private String provider;
	private String providerId;
	private String providerJwks;

}
