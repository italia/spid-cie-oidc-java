package it.spid.cie.oidc.spring.boot.relying.party.exception;

import it.spid.cie.oidc.spring.boot.relying.party.storage.TrustChain;

// TODO: create common anchestor SpidExcpetion
public class TrustChainException extends Exception {

	private static final long serialVersionUID = 602471019127315717L;

	@SuppressWarnings("serial")
	public static class MissingProvider extends TrustChainException {

		public static final String DEFAULT_MESSAGE =
			"Missing provider url. Please try '?provider=https://provider-subject/'";

		public MissingProvider() {
			super(DEFAULT_MESSAGE);
		}

	}

	@SuppressWarnings("serial")
	public static class InvalidTrustAnchor extends TrustChainException {

		public static final String DEFAULT_MESSAGE = "Unallowed Trust Anchor";

		public InvalidTrustAnchor() {
			super(DEFAULT_MESSAGE);
		}

	}

	@SuppressWarnings("serial")
	public static class TrustChainDisabled extends TrustChainException {

		public static final String DEFAULT_MESSAGE_FORMAT =
			"TrustChain DISABLED at %s";

		public TrustChainDisabled(TrustChain trustChain) {
			super(
				String.format(
					DEFAULT_MESSAGE_FORMAT,
					trustChain.getModified().toString()));
		}

		public TrustChainDisabled(String message) {
			super(message);
		}
	}

	private TrustChainException(String message) {
		super(message);
	}

	private TrustChainException(String message, Throwable cause) {
		super(message, cause);
	}

}
