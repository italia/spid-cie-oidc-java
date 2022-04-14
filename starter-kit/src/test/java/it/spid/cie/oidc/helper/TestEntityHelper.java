package it.spid.cie.oidc.helper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;

import it.spid.cie.oidc.config.OIDCConstants;
import it.spid.cie.oidc.config.RelyingPartyOptions;

public class TestEntityHelper {

	private static WireMockServer wireMockServer;

	@BeforeClass
	public static void setUp() throws IOException {
		wireMockServer = new WireMockServer();

		wireMockServer.start();

		System.out.println("mock=" + wireMockServer.baseUrl());
	}

	@AfterClass
	public static void tearDown() throws IOException {
		wireMockServer.stop();
	}

	@SuppressWarnings("static-access")
	@Test
	public void testClass1a() {
		RelyingPartyOptions options = new RelyingPartyOptions();

		EntityHelper helper = new EntityHelper(options);

		assertNotNull(helper);

		wireMockServer.resetAll();

		String url = getBaseHttpURL();
		boolean catched = false;
		String fakeResponse = "fake-response";
		String res = "";

		wireMockServer.stubFor(
			WireMock.get(
				"/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
			).willReturn(
				WireMock.ok(fakeResponse)
			));

		try {
			res = helper.getEntityConfiguration(url);
		}
		catch (Exception e) {
			System.out.println(e);
			catched = true;
		}

		assertFalse(catched);
		assertEquals(fakeResponse, res);
	}

	@SuppressWarnings("static-access")
	@Test
	public void testClass1b() {
		RelyingPartyOptions options = new RelyingPartyOptions();

		EntityHelper helper = new EntityHelper(options);

		assertNotNull(helper);

		wireMockServer.resetAll();

		String url = getBaseHttpURL();
		boolean catched = false;

		wireMockServer.stubFor(
			WireMock.get(
				"/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL
			).willReturn(
				WireMock.forbidden()
			));

		try {
			helper.getEntityConfiguration(url);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@SuppressWarnings("static-access")
	@Test
	public void testClass2a() {
		RelyingPartyOptions options = new RelyingPartyOptions();

		EntityHelper helper = new EntityHelper(options);

		assertNotNull(helper);

		wireMockServer.resetAll();

		String url = getBaseHttpURL();
		boolean catched = false;
		String fakeResponse = "fake-response";
		String res = "";

		wireMockServer.stubFor(
			WireMock.get(
				"/"
			).willReturn(
				WireMock.ok(fakeResponse)
			));

		try {
			res = helper.getEntityStatement(url);
		}
		catch (Exception e) {
			catched = true;
		}

		assertFalse(catched);
		assertEquals(fakeResponse, res);
	}

	@SuppressWarnings("static-access")
	@Test
	public void testClass2b() {
		RelyingPartyOptions options = new RelyingPartyOptions();

		EntityHelper helper = new EntityHelper(options);

		assertNotNull(helper);

		wireMockServer.resetAll();

		String url = getBaseHttpURL();
		boolean catched = false;

		wireMockServer.stubFor(
			WireMock.get(
				"/"
			).willReturn(
				WireMock.forbidden()
			));

		try {
			helper.getEntityStatement(url);
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	@Test
	public void test_getEntityStatement() {
		boolean catched = false;

		try {
			EntityHelper.getEntityStatement("bad-url");
		}
		catch (Exception e) {
			catched = true;
		}

		assertTrue(catched);
	}

	private String getBaseHttpURL() {
		return "http://127.0.0.1:" + wireMockServer.port() + "/";
	}

}
