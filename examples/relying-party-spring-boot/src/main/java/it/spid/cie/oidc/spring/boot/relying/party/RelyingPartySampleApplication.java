package it.spid.cie.oidc.spring.boot.relying.party;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import it.spid.cie.oidc.spring.boot.relying.party.config.OidcConfig;

@SpringBootApplication
public class RelyingPartySampleApplication implements CommandLineRunner {

	@Autowired
	private OidcConfig oidcConfig;

	public static void main(String[] args) {
		SpringApplication.run(RelyingPartySampleApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		System.out.println("Configuration:\n" + oidcConfig.toJSONString(2));
		//test1();
	}

	public void test1() throws Exception {
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.algorithm(JWSAlgorithm.RS256)
			.keyID(UUID.randomUUID().toString())
			.keyUse(KeyUse.SIGNATURE)
			.generate();

		// Output the private and public RSA JWK parameters
		System.out.println("\n" + rsaJWK);

		RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();
		System.out.println("\n" + rsaPublicJWK);

		// Create RSA-signer with the private key
		JWSSigner signer = new RSASSASigner(rsaJWK);

		// Prepare JWS object with simple string as payload
		JWSObject jwsObject = new JWSObject(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
			new Payload("In RSA we trust!"));

		System.out.println("\n" + jwsObject.getHeader().toString());
		System.out.println("\n" + jwsObject.getPayload().toString());

	}
}
