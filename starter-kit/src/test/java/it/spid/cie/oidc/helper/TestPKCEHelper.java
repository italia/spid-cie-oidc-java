package it.spid.cie.oidc.helper;

import static org.junit.Assert.assertFalse;

import org.json.JSONObject;
import org.junit.Test;

public class TestPKCEHelper {

	@Test
	public void testClass() {
		JSONObject json = PKCEHelper.getPKCE();

		assertFalse(json.isEmpty());
	}

}
