package it.spid.cie.oidc.spring.boot.relying.party.storage;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import org.json.JSONObject;

@Entity
@Table(name = "oidc_authentication")
public class OidcAuthentication {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false)
	private LocalDateTime created;

	@Column(nullable = false)
	private LocalDateTime modified;

	@Column(name = "client_id", nullable = false)
	private String clientId;

	@Column(nullable = false)
	private String state;

	@Column(nullable = true)
	private String endpoint;

	@Column(nullable = true)
	private String data;

	@Column(nullable = false)
	private boolean successful;

	@Column(name = "provider_configuration", nullable = true)
	private String providerConfiguration;

	@Column(nullable = true)
	private String provider;

	@Column(name = "provider_id", nullable = true)
	private String providerId;

	@Column(name = "provider_jwks", nullable = true)
	private String providerJwks;

	public OidcAuthentication() {
		this.created = LocalDateTime.now();
		this.modified = this.created;
	}

	public Long getId() {
		return id;
	}

	public LocalDateTime getCreated() {
		return created;
	}

	public LocalDateTime getModified() {
		return modified;
	}

	public String getClientId() {
		return clientId;
	}

	public String getState() {
		return state;
	}

	public String getEndpoint() {
		return endpoint;
	}

	public String getData() {
		return data;
	}

	public boolean isSuccessful() {
		return successful;
	}

	public String getProviderConfiguration() {
		return providerConfiguration;
	}

	public String getProvider() {
		return provider;
	}

	public String getProviderId() {
		return providerId;
	}

	public String getProviderJwks() {
		return providerJwks;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public void setCreated(LocalDateTime created) {
		this.created = created;
	}

	public void setModified(LocalDateTime modified) {
		this.modified = modified;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public void setState(String state) {
		this.state = state;
	}

	public void setEndpoint(String endpoint) {
		this.endpoint = endpoint;
	}

	public void setData(String data) {
		this.data = data;
	}

	public void setSuccessful(boolean successful) {
		this.successful = successful;
	}

	public void setProviderConfiguration(String providerConfiguration) {
		this.providerConfiguration = providerConfiguration;
	}

	public void setProvider(String provider) {
		this.provider = provider;
	}

	public void setProviderId(String providerId) {
		this.providerId = providerId;
	}

	public void setProviderJwks(String providerJwks) {
		this.providerJwks = providerJwks;
	}

}
