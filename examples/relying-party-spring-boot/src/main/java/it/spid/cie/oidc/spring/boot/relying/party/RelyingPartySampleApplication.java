package it.spid.cie.oidc.spring.boot.relying.party;

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
	}

}
