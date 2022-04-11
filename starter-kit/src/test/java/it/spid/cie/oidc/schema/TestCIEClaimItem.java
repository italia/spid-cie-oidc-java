package it.spid.cie.oidc.schema;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import it.spid.cie.oidc.schemas.CIEClaimItem;

public class TestCIEClaimItem {

	@Test
	public void testClass1a() {
		assertNotNull(CIEClaimItem.get(CIEClaimItem.FAMILY_NAME.getName()));
	}

	@Test
	public void testClass1b() {
		assertNull(CIEClaimItem.get("familyname"));
	}

	@Test
	public void testClass2a() {
		assertNotNull(CIEClaimItem.getByAlias(CIEClaimItem.FAMILY_NAME.getAlias()));
	}

	@Test
	public void testClass2b() {
		assertNull(CIEClaimItem.getByAlias("familyname"));
	}

	@Test
	public void testClass3() {
		assertNotNull(CIEClaimItem.registerItem("test_name", "testAlias"));
	}

}
