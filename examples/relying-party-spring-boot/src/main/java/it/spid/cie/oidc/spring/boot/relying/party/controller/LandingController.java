package it.spid.cie.oidc.spring.boot.relying.party.controller;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import it.spid.cie.oidc.schemas.OIDCProfile;
import it.spid.cie.oidc.spring.boot.relying.party.config.OidcConfig;

@RestController
@RequestMapping("/oidc/rp")
public class LandingController {

	@GetMapping("/landing")
	public ModelAndView home(HttpServletRequest request)
		throws Exception {

		ModelAndView mav = new ModelAndView("landing");

		Map<String, String> spidProviders = oidcConfig.getIdentityProviders(
			OIDCProfile.SPID);

		mav.addObject("spidProviders", spidProviders.keySet());

		Map<String, String> cieProviders = oidcConfig.getIdentityProviders(
			OIDCProfile.CIE);

		mav.addObject("cieProviders", cieProviders.keySet());

		return mav;
	}

	@Autowired
	private OidcConfig oidcConfig;

}
