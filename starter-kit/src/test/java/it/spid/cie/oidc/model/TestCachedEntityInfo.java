package it.spid.cie.oidc.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.time.LocalDateTime;

import org.junit.Test;
import org.mockito.Mockito;

public class TestCachedEntityInfo {

	@Test
	public void testCachedEntityInfoClass() {
		CachedEntityInfo model = Mockito.spy(new CachedEntityInfo());

		model.getStorageId();
		model.getCreateDate();
		model.getModifiedDate();

		model.getExpiresOn();
		model.getIssuedAt();
		model.getIssuer();
		model.getJwt();
		model.getStatement();
		model.getSubject();
		model.isExpired();

		LocalDateTime now = LocalDateTime.now();

		model.setStorageId("0");
		model.setCreateDate(now);
		model.setModifiedDate(now);

		model.setExpiresOn(now.minusSeconds(1));
		model.setIssuedAt(now);
		model.setIssuer("testIssuer");
		model.setJwt("testJwt");
		model.setStatement("testStatement");
		model.setSubject("testSubject");

		assertEquals("0", model.getStorageId());
		assertEquals(now, model.getCreateDate());
		assertEquals(now, model.getModifiedDate());
		assertTrue(model.isExpired());
	}

	@Test
	public void testCachedEntityInfo2() {
		LocalDateTime now = LocalDateTime.now().minusSeconds(1);

		CachedEntityInfo model = CachedEntityInfo.of(
			"testIss", "testSub", now, now, "testStatement", "testJwt");

		assertNull(model.getStorageId());
		assertTrue(model.isExpired());
	}

}
