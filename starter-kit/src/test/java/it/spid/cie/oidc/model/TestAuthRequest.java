package it.spid.cie.oidc.model;

import static org.junit.Assert.assertEquals;

import java.time.LocalDateTime;

import org.junit.Test;
import org.mockito.Mockito;

public class TestAuthRequest {

	@Test
	public void testAuthnRequestClass() {
		AuthnRequest model = Mockito.spy(new AuthnRequest());

		model.getStorageId();
		model.getCreateDate();
		model.getModifiedDate();

		model.getClientId();
		model.getData();
		model.getEndpoint();
		model.getProvider();
		model.getProviderConfiguration();
		model.getProviderId();
		model.getProviderJwks();
		model.getState();
		model.isSuccessful();

		LocalDateTime now = LocalDateTime.now();

		model.setStorageId("0");
		model.setCreateDate(now);
		model.setModifiedDate(now);
		model.setClientId("testClientId");
		model.setData("testData");
		model.setEndpoint("testEndpoint");
		model.setProvider("testProvider");
		model.setProviderConfiguration("testProviderConfiguration");
		model.setProviderId("testProviderId");
		model.setProviderJwks("testProviderJwks");
		model.setState("testState");
		model.setSuccessful(false);

		assertEquals("0", model.getStorageId());
		assertEquals(now, model.getCreateDate());
		assertEquals(now, model.getModifiedDate());

	}

}
