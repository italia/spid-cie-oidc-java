package it.spid.cie.oidc.spring.boot.relying.party.controller;

import java.net.URI;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import it.spid.cie.oidc.spring.boot.relying.party.RelyingPartyWrapper;

@RestController
@RequestMapping("/oidc/rp")
public class SpidController {

	@GetMapping("/authorize")
	public ResponseEntity<Void> authorize(
			@RequestParam String provider,
			@RequestParam(name = "redirect_uri", required = false) String redirectUri,
			@RequestParam(required = false) String scope,
			@RequestParam(required = false) String prompt,
			@RequestParam(name = "trust_anchor", required = false) String trustAnchor,
			@RequestParam(required = false) String profile)
		throws Exception {

		String url = relyingPartyWrapper.getAuthorizeURL(
			provider, trustAnchor, redirectUri, scope, profile, prompt);

		logger.info("Starting Authn request to {}", url);

		return ResponseEntity
			.status(HttpStatus.FOUND)
			.location(URI.create(url))
			.build();
	}

	private static Logger logger = LoggerFactory.getLogger(SpidController.class);

	@Autowired
	private RelyingPartyWrapper relyingPartyWrapper;


}
