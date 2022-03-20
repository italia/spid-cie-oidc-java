package it.spid.cie.oidc.spring.boot.relying.party.util;

import java.util.Arrays;
import java.util.HashSet;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

public class Test01 {

	public static void test(String jwt, JWKSet jwkSet, String alg, String issuer)
		throws Exception {

		// Create a JWT processor for the access tokens
		ConfigurableJWTProcessor<SecurityContext> jwtProcessor =
			new DefaultJWTProcessor<>();

		// Set the required "typ" header "at+jwt" for access tokens issued by the
		// Connect2id server, may not be set by other servers
		jwtProcessor.setJWSTypeVerifier(
			new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("entity-statement+jwt")));

		// The public RSA keys to validate the signatures will be sourced from the
		// OAuth 2.0 server's JWK set, published at a well-known URL. The RemoteJWKSet
		// object caches the retrieved keys to speed up subsequent look-ups and can
		// also handle key-rollover
		JWKSource<SecurityContext> keySource =
			new ImmutableJWKSet<SecurityContext>(jwkSet);
			//new RemoteJWKSet<>(new URL("https://demo.c2id.com/jwks.json"));

		// The expected JWS algorithm of the access tokens (agreed out-of-band)
		JWSAlgorithm expectedJWSAlg = JWSAlgorithm.parse(alg);

		// Configure the JWT processor with a key selector to feed matching public
		// RSA keys sourced from the JWK set URL
		JWSKeySelector<SecurityContext> keySelector =
			new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);

		jwtProcessor.setJWSKeySelector(keySelector);

		// Set the required JWT claims for access tokens issued by the Connect2id
		// server, may differ with other servers
		jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
			new JWTClaimsSet.Builder().issuer("Http://a.b.c.local").build(),
			new HashSet<>(Arrays.asList("sub", "iat", "exp"))));

		// Process the token
		SecurityContext ctx = null; // optional context parameter, not required here
		JWTClaimsSet claimsSet = jwtProcessor.process(jwt, ctx);

		// Print out the token claims set
		System.out.println(claimsSet.toJSONObject());
	}
}
