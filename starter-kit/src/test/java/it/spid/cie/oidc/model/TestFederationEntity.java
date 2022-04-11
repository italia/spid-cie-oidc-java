package it.spid.cie.oidc.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.time.LocalDateTime;

import org.json.JSONObject;
import org.junit.Test;
import org.mockito.Mockito;

public class TestFederationEntity {

	@Test
	public void testFederationEntityClass() {
		FederationEntity model = Mockito.spy(new FederationEntity());

		model.getStorageId();
		model.getCreateDate();
		model.getModifiedDate();

		model.getAuthorityHints();
		model.getConstraints();
		model.getDefaultExpireMinutes();
		model.getDefaultSignatureAlg();
		model.getEntityType();
		model.getJwks();
		model.getMetadata();
		model.getSubject();
		model.getTrustMarks();
		model.getTrustMarksIssuers();
		model.isActive();

		LocalDateTime now = LocalDateTime.now();

		model.setStorageId("0");
		model.setCreateDate(now);
		model.setModifiedDate(now);

		model.setActive(true);
		model.setAuthorityHints("testAuthorityHints");
		model.setConstraints("testConstraints");
		model.setDefaultExpireMinutes(30);
		model.setDefaultSignatureAlg("testAlg");
		model.setEntityType("testEntityType");
		model.setJwks("testJwks");
		model.setSubject("testSubject");
		model.setTrustMarks("testTrustMarks");
		model.setTrustMarksIssuers("testIssuer");

		JSONObject metadata = new JSONObject()
			.put("testKey", new JSONObject().put("test", "ok"));

		model.setMetadata(metadata.toString());

		assertEquals("0", model.getStorageId());
		assertEquals(now, model.getCreateDate());
		assertEquals(now, model.getModifiedDate());
		assertTrue(model.isActive());
		assertNotNull(model.getMetadataValue("testKey"));
	}

	@Test
	public void testFederationEntityMetadata() {
		FederationEntity model = new FederationEntity();

		model.setMetadata("invalid-json");

		assertNull(model.getMetadataValue("testKey"));
	}

}
