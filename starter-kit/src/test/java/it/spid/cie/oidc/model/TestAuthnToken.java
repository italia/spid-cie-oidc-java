package it.spid.cie.oidc.model;

import static org.junit.Assert.assertEquals;

import java.time.LocalDateTime;

import org.junit.Test;
import org.mockito.Mockito;

public class TestAuthnToken {

	@Test
	public void testAuthnTokenClass() {
		AuthnToken model = Mockito.spy(new AuthnToken());

		model.getStorageId();
		model.getCreateDate();
		model.getModifiedDate();

		model.getAccessToken();
		model.getAuthnRequestId();
		model.getCode();
		model.getExpiresIn();
		model.getIdToken();
		model.getRefreshToken();
		model.getRevoked();
		model.getScope();
		model.getTokenType();
		model.getUserKey();

		LocalDateTime now = LocalDateTime.now();

		model.setStorageId("0");
		model.setCreateDate(now);
		model.setModifiedDate(now);
		model.setAccessToken("testAccessToken");
		model.setAuthnRequestId("testAuthnRequestId");
		model.setCode("testCode");
		model.setExpiresIn(30);
		model.setIdToken("testIdToken");
		model.setRefreshToken("testRefreshToken");
		model.setRevoked(now);
		model.setScope("testScope");
		model.setTokenType("testTokenType");
		model.setUserKey("testUserKey");

		assertEquals("0", model.getStorageId());
		assertEquals(now, model.getCreateDate());
		assertEquals(now, model.getModifiedDate());
	}

}
