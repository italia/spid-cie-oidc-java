package it.spid.cie.oidc.spring.boot.relying.party.controller;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import it.spid.cie.oidc.schemas.OIDCProfile;
import it.spid.cie.oidc.schemas.ProviderButtonInfo;
import it.spid.cie.oidc.spring.boot.relying.party.RelyingPartyWrapper;

@RestController
@RequestMapping("/oidc/rp")
public class LandingController {

	@GetMapping("/landing")
	public ModelAndView home(HttpServletRequest request)
		throws Exception {

		ModelAndView mav = new ModelAndView("landing");

		List<ProviderButtonInfo> spidProviders =
			relyingPartyWrapper.getProviderButtonInfos(OIDCProfile.SPID);

		mav.addObject("spidProviders", spidProviders);

		List<ProviderButtonInfo> cieProviders =
			relyingPartyWrapper.getProviderButtonInfos(OIDCProfile.CIE);

		mav.addObject("cieProviders", cieProviders);

		return mav;
	}

	@Autowired
	private RelyingPartyWrapper relyingPartyWrapper;

}
