package it.spid.cie.oidc.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.time.LocalDateTime;

import org.json.JSONObject;
import org.junit.Test;
import org.mockito.Mockito;

public class TestTrustChain {

	@Test
	public void testTrustChainClass() {
		TrustChain model = Mockito.spy(new TrustChain());

		model.getStorageId();
		model.getCreateDate();
		model.getModifiedDate();

		model.getChain();
		model.getExpiresOn();
		model.getIssuedAt();
		model.getLog();
		model.getMetadata();
		model.getPartiesInvolved();
		model.getProcessingStart();
		model.getStatus();
		model.getSubject();
		model.getTrustAnchor();
		model.getTrustMarks();
		model.getType();
		model.isActive();
		model.isExpired();

		LocalDateTime now = LocalDateTime.now();

		model.setStorageId("0");
		model.setCreateDate(now);
		model.setModifiedDate(now);
		model.setActive(true);
		model.setChain("testChain");
		model.setExpiresOn(now.minusSeconds(1));
		model.setIssuedAt(now);
		model.setLog("testLog");
		model.setMetadata(new JSONObject().put("test", "test").toString());
		model.setPartiesInvolved("testPartiesInvolved");
		model.setProcessingStart(now);
		model.setStatus("testStatus");
		model.setSubject("testSubject");
		model.setTrustAnchor("testTrustAnchor");
		model.setTrustMarks("testTrustMarks");
		model.setType("testType");

		assertEquals("0", model.getStorageId());
		assertEquals(now, model.getCreateDate());
		assertEquals(now, model.getModifiedDate());
		assertTrue(model.isActive());
		assertTrue(model.isExpired());
		assertFalse(model.getMetadataAsJSON().isEmpty());
	}

	@Test
	public void testTrustChain() {
		TrustChain model = new TrustChain();

		model.setMetadata("invalid-json");

		assertTrue(model.getMetadataAsJSON().isEmpty());
	}

}
