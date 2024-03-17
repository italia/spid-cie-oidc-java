package it.spid.cie.oidc.spring.boot.relying.party.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import it.spid.cie.oidc.config.OIDCConstants;
import it.spid.cie.oidc.schemas.WellKnownData;
import it.spid.cie.oidc.spring.boot.relying.party.RelyingPartyWrapper;
import it.spid.cie.oidc.spring.boot.relying.party.config.OidcConfig;

@RestController
@RequestMapping("/oidc/rp")
public class WellKnownController {

	@GetMapping("/" + OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL)
	public ResponseEntity<String> wellKnownFederation(
			@RequestParam(required = false) String format,
			HttpServletRequest request, HttpServletResponse response)
		throws Exception {

		boolean jsonMode = "json".equals(format);

		WellKnownData wellKnown = relyingPartyWrapper.getWellKnownData(
			request.getRequestURL().toString(), jsonMode);

		if (wellKnown.getStep() == WellKnownData.STEP_ONLY_JWKS) {
			logger.info(
				"Generated jwk. Please add it into 'application.yaml' or save as '" +
				oidcConfig.getRelyingParty().getJwkFedFilePath() + "'.\n" +
				wellKnown.getValue());

			String body = new JSONObject()
				.put("ERROR", "Do OnBoarding configuration")
				.toString();

			return ResponseEntity.ok()
				.contentType(MediaType.APPLICATION_JSON)
				.body(body);
		}

		if (jsonMode) {
			return ResponseEntity.ok()
				.contentType(MediaType.APPLICATION_JSON)
				.body(wellKnown.getValue());
		}
		else {
			return ResponseEntity.ok()
				.contentType(new MediaType("application", "entity-statement+jwt"))
				.body(wellKnown.getValue());
		}
	}

	private static Logger logger = LoggerFactory.getLogger(WellKnownController.class);

	@Autowired
	private OidcConfig oidcConfig;

	@Autowired
	private RelyingPartyWrapper relyingPartyWrapper;

}
