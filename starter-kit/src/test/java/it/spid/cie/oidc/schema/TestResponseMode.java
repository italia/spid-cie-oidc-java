package it.spid.cie.oidc.schema;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import it.spid.cie.oidc.schemas.ResponseMode;

public class TestResponseMode {

	@Test
	public void testParse1() {
		ResponseMode res = ResponseMode.parse(ResponseMode.QUERY.name());

		assertNull(res);
	}

	@Test
	public void testParse2() {
		ResponseMode res = ResponseMode.parse(ResponseMode.QUERY.value());

		assertTrue(ResponseMode.QUERY.equals(res));
	}

	@Test
	public void testParse3() {
		ResponseMode res = ResponseMode.parse("ko");

		assertNull(res);
	}

	@Test
	public void testParse4() {
		boolean catched = false;

		try {
			ResponseMode.parse("ko", true);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void testParse4b() {
		boolean catched = false;
		ResponseMode res = null;

		try {
			res = ResponseMode.parse("ko", false);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNull(res);
	}

	@Test
	public void testParse5() {
		ResponseMode res = ResponseMode.parse(null);

		assertNull(res);
	}

	@Test
	public void testParse6a() {
		boolean catched = false;
		ResponseMode res = null;

		try {
			res = ResponseMode.parse(ResponseMode.QUERY.value(), true);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(res);
	}

	@Test
	public void testParse6b() {
		boolean catched = false;
		ResponseMode res = null;

		try {
			res = ResponseMode.parse(ResponseMode.QUERY.value(), false);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertNotNull(res);
	}

	@Test
	public void testParse7() {
		assertEquals(ResponseMode.FORM_POST.toString(), ResponseMode.FORM_POST.value());
	}

}
