package it.spid.cie.oidc.config;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.json.JSONObject;
import org.junit.Test;

import it.spid.cie.oidc.schemas.ClaimSection;
import it.spid.cie.oidc.schemas.SPIDClaimItem;

public class TestClaimOptions {

	@Test
	public void testClass1() {
		ClaimOptions res = new ClaimOptions();

		assertNotNull(res);
		assertTrue(res.isEmpty());
	}

	@Test
	public void testClass2a() {
		boolean catched = false;
		ClaimOptions res = new ClaimOptions();

		try {
			res.addSectionItem(ClaimSection.ID_TOKEN, SPIDClaimItem.DATE_OF_BIRTH, null);
			res.addSectionItem(ClaimSection.USER_INFO, SPIDClaimItem.FAMILY_NAME, null);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(res);
		assertFalse(res.isEmpty());
		assertFalse(res.hasEssentialItem(SPIDClaimItem.DATE_OF_BIRTH.getName()));
		assertFalse(res.hasEssentialItem(SPIDClaimItem.DATE_OF_BIRTH.getAlias()));
		assertFalse(res.hasEssentialItem(SPIDClaimItem.FAMILY_NAME.getName()));
		assertFalse(res.hasEssentialItem(SPIDClaimItem.FAMILY_NAME.getAlias()));
		assertFalse(res.hasEssentialItem(SPIDClaimItem.COMPANY_NAME.getName()));
		assertFalse(res.hasEssentialItem(SPIDClaimItem.COMPANY_NAME.getAlias()));
	}

	@Test
	public void testClass2b() {
		boolean catched = false;
		ClaimOptions res = new ClaimOptions();

		try {
			res.addSectionItem(ClaimSection.ID_TOKEN, SPIDClaimItem.DATE_OF_BIRTH, true);
			res.addSectionItem(ClaimSection.USER_INFO, SPIDClaimItem.FAMILY_NAME, true);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(res);
		assertFalse(res.isEmpty());
		assertTrue(res.hasEssentialItem(SPIDClaimItem.DATE_OF_BIRTH.getName()));
		assertTrue(res.hasEssentialItem(SPIDClaimItem.DATE_OF_BIRTH.getAlias()));
		assertTrue(res.hasEssentialItem(SPIDClaimItem.FAMILY_NAME.getName()));
		assertTrue(res.hasEssentialItem(SPIDClaimItem.FAMILY_NAME.getAlias()));
		assertFalse(res.hasEssentialItem(SPIDClaimItem.COMPANY_NAME.getName()));
		assertFalse(res.hasEssentialItem(SPIDClaimItem.COMPANY_NAME.getAlias()));
	}

	@Test
	public void testClass2c() {
		boolean catched = false;
		ClaimOptions res = new ClaimOptions();

		try {
			res.addSectionItem(ClaimSection.ID_TOKEN, SPIDClaimItem.DATE_OF_BIRTH, false);
			res.addSectionItem(ClaimSection.USER_INFO, SPIDClaimItem.FAMILY_NAME, false);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(res);
		assertFalse(res.isEmpty());
		assertFalse(res.hasEssentialItem(SPIDClaimItem.DATE_OF_BIRTH.getName()));
		assertFalse(res.hasEssentialItem(SPIDClaimItem.DATE_OF_BIRTH.getAlias()));
		assertFalse(res.hasEssentialItem(SPIDClaimItem.FAMILY_NAME.getName()));
		assertFalse(res.hasEssentialItem(SPIDClaimItem.FAMILY_NAME.getAlias()));
		assertFalse(res.hasEssentialItem(SPIDClaimItem.COMPANY_NAME.getName()));
		assertFalse(res.hasEssentialItem(SPIDClaimItem.COMPANY_NAME.getAlias()));
	}

	@Test
	public void testClass3() {
		boolean catched = false;
		ClaimOptions res = new ClaimOptions();

		try {
			res.addSectionItem(ClaimSection.ID_TOKEN, SPIDClaimItem.NAME, null);
			res.addSectionItem(ClaimSection.ID_TOKEN, SPIDClaimItem.FAMILY_NAME, false);
			res.addSectionItem(ClaimSection.USER_INFO, SPIDClaimItem.COMPANY_NAME, null);
			res.addSectionItem(ClaimSection.USER_INFO, SPIDClaimItem.EMAIL, true);
		}
		catch (Exception e) {
			catched = true;
		}

		JSONObject json = res.toJSON();

		JSONObject idToken = json.optJSONObject("id_token");
		JSONObject userInfo = json.optJSONObject("userinfo");

		assertFalse(catched);
		assertNotNull(idToken);
		assertNotNull(userInfo);
		assertNotNull(idToken.optString(SPIDClaimItem.NAME.getAlias()));
		assertNotNull(userInfo.optString(SPIDClaimItem.COMPANY_NAME.getAlias()));
	}

	@Test
	public void testClass4a() {
		boolean catched = false;
		ClaimOptions res = new ClaimOptions();

		try {
			res.addSectionItem(ClaimSection.ID_TOKEN, SPIDClaimItem.NAME, true);
			res.addSectionItem(ClaimSection.ID_TOKEN, null, false);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testClass4b() {
		boolean catched = false;
		ClaimOptions res = new ClaimOptions();

		try {
			res.addSectionItem(ClaimSection.USER_INFO, SPIDClaimItem.FAMILY_NAME, true);
			res.addSectionItem(ClaimSection.USER_INFO, null, false);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

}
