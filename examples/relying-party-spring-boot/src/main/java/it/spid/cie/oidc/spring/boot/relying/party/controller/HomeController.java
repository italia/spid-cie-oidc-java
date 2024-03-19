package it.spid.cie.oidc.spring.boot.relying.party.controller;

import javax.servlet.http.HttpServletRequest;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import it.spid.cie.oidc.schemas.WellKnownData;
import it.spid.cie.oidc.spring.boot.relying.party.RelyingPartyWrapper;
import it.spid.cie.oidc.spring.boot.relying.party.config.OidcConfig;

@RestController
public class HomeController {

	@GetMapping(path = { "/", "/home" })
	public ModelAndView home(HttpServletRequest request)
		throws Exception {

		ModelAndView mav = new ModelAndView("home");

		WellKnownData wellKnow = rpWrapper.getFederationEntityData();

		mav.addObject("onlyJwks", wellKnow.hasOnlyJwks());
		mav.addObject("intermediate", wellKnow.isIntermediate());
		mav.addObject("showLanding", wellKnow.isComplete());
		mav.addObject("trustAnchorHost", oidcConfig.getHosts().getTrustAnchor());

		if (wellKnow.hasOnlyJwks()) {
			JSONArray json = new JSONArray(wellKnow.getValue());

			mav.addObject("fedJwks", json.get(0).toString());
			mav.addObject("coreJwks", json.get(1).toString());

			mav.addObject("configFile", oidcConfig.getRelyingParty().getJwkFedFilePath());
			mav.addObject("configCoreFile", oidcConfig.getRelyingParty().getJwkCoreFilePath());
		}

		if (wellKnow.isIntermediate()) {
			mav.addObject("rpName", oidcConfig.getRelyingParty().getApplicationName());
			mav.addObject("rpClientId", oidcConfig.getRelyingParty().getClientId());
			mav.addObject("rpPublicJwks", wellKnow.getPublicJwks());
			mav.addObject(
				"configFile", oidcConfig.getRelyingParty().getTrustMarksFilePath());
		}

		return mav;
	}

	@GetMapping("/reload-handler")
	public RedirectView reloadConfig(HttpServletRequest request)
		throws Exception {

		rpWrapper.reloadHandler();

		return new RedirectView("home");
	}


	@Autowired
	private OidcConfig oidcConfig;

	@Autowired
	private RelyingPartyWrapper rpWrapper;

}
