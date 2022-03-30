package it.spid.cie.oidc.spring.boot.relying.party.persistence.model;

import java.time.LocalDateTime;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import it.spid.cie.oidc.model.AuthnRequest;
import it.spid.cie.oidc.util.GetterUtil;
import it.spid.cie.oidc.util.Validator;

@Entity
@Table(name = "oidc_authentication")
public class AuthnRequestModel {

	public static AuthnRequestModel of(AuthnRequest source) {
		AuthnRequestModel target = new AuthnRequestModel();

		target.setId(source.getStorageId());
		target.setCreated(source.getCreateDate());
		target.setModified(source.getModifiedDate());
		target.setClientId(source.getClientId());
		target.setData(source.getData());
		target.setEndpoint(source.getEndpoint());
		target.setProvider(source.getProvider());
		target.setProviderConfiguration(source.getProviderConfiguration());
		target.setProviderId(source.getProviderId());
		target.setProviderJwks(source.getProviderJwks());
		target.setState(source.getState());
		target.setSuccessful(source.isSuccessful());

		return target;
	}

	public AuthnRequestModel() {
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

	public String getData() {
		return data;
	}

	public String getEndpoint() {
		return endpoint;
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

	public void setData(String data) {
		this.data = data;
	}

	public void setEndpoint(String endpoint) {
		this.endpoint = endpoint;
	}

	public void setProvider(String provider) {
		this.provider = provider;
	}

	public void setProviderConfiguration(String providerConfiguration) {
		this.providerConfiguration = providerConfiguration;
	}

	public void setProviderId(String providerId) {
		this.providerId = providerId;
	}

	public void setProviderJwks(String providerJwks) {
		this.providerJwks = providerJwks;
	}

	public void setState(String state) {
		this.state = state;
	}

	public void setSuccessful(boolean successful) {
		this.successful = successful;
	}

	public AuthnRequest toAuthnRequest() {
		AuthnRequest target = new AuthnRequest();

		target.setStorageId(getStorageId());
		target.setCreateDate(getCreated());
		target.setModifiedDate(getModified());
		target.setClientId(getClientId());
		target.setData(getData());
		target.setEndpoint(getEndpoint());
		target.setProvider(getProvider());
		target.setProviderConfiguration(getProviderConfiguration());
		target.setProviderId(getProviderId());
		target.setProviderJwks(getProviderJwks());
		target.setState(getState());
		target.setSuccessful(isSuccessful());

		return target;
	}

	protected void setId(String storageId) {
		if (!Validator.isNullOrEmpty(storageId)) {
			setId(GetterUtil.getLong(storageId));
		}
	}

	private String getStorageId() {
		if (id != null && id > 0) {
			return String.valueOf(id);
		}

		return null;
	}

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

}
