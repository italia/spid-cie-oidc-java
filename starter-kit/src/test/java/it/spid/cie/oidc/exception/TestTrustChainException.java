package it.spid.cie.oidc.exception;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import it.spid.cie.oidc.model.TrustChain;

public class TestTrustChainException extends BaseTestException {

	@Test
	public void testMissingProvider() {
		OIDCException e = new TrustChainException.MissingProvider();

		assertNotNull(e);
	}

	@Test
	public void testInvalidRequiredTrustMark() {
		OIDCException e = new TrustChainException.InvalidRequiredTrustMark(MSG);

		assertNotNull(e);
	}

	@Test
	public void testInvalidTrustAnchor() {
		OIDCException e = new TrustChainException.InvalidTrustAnchor();

		assertNotNull(e);
	}

	@Test
	public void testInvalidTrustChain() {
		OIDCException e = new TrustChainException.InvalidTrustChain(MSG);

		assertNotNull(e);
	}

	@Test
	public void testMissingMetadata() {
		OIDCException e = new TrustChainException.MissingMetadata(MSG);

		assertNotNull(e);
	}

	@Test
	public void testTrustAnchorNeeded() {
		OIDCException e = new TrustChainException.TrustAnchorNeeded(MSG);

		assertNotNull(e);
	}

	@Test
	public void testTrustChainDisabled1() {
		TrustChain tc = new TrustChain();

		OIDCException e = new TrustChainException.TrustChainDisabled(tc);

		assertNotNull(e);
	}

	@Test
	public void testTrustChainDisabled2() {
		OIDCException e = new TrustChainException.TrustChainDisabled(MSG);

		assertNotNull(e);
	}

}
