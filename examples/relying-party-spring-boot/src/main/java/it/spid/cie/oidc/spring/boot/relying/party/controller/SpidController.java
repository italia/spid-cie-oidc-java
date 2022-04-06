package it.spid.cie.oidc.spring.boot.relying.party.controller;

import java.net.URI;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

import it.spid.cie.oidc.callback.RelyingPartyLogoutCallback;
import it.spid.cie.oidc.model.AuthnRequest;
import it.spid.cie.oidc.model.AuthnToken;
import it.spid.cie.oidc.spring.boot.relying.party.RelyingPartyWrapper;
import it.spid.cie.oidc.util.GetterUtil;
import it.spid.cie.oidc.util.Validator;

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

	@GetMapping("/callback")
	public RedirectView callback(
			@RequestParam Map<String,String> params,
			HttpServletRequest request, HttpServletResponse response)
		throws Exception {

		if (params.containsKey("error")) {
			String msg = new JSONObject(params).toString(2);

			logger.error(msg);

			throw new Exception(msg);
		}

		String state = params.get("state");
		String code = params.get("code");

		JSONObject userInfo = relyingPartyWrapper.getUserInfo(state, code);

		request.getSession().setAttribute(
			"USER", relyingPartyWrapper.getUserKey(userInfo));
		request.getSession().setAttribute("USER_INFO", userInfo.toMap());

		return new RedirectView("echo_attributes");
	}

	@GetMapping("/logout")
	public RedirectView logout(
			@RequestParam Map<String,String> params,
			final HttpServletRequest request, HttpServletResponse response)
		throws Exception {

		String userKey = GetterUtil.getString(request.getSession().getAttribute("USER"));

		String redirectURL = relyingPartyWrapper.performLogout(
			userKey, new RelyingPartyLogoutCallback() {

				@Override
				public void logout(
					String userKey, AuthnRequest authnRequest, AuthnToken authnToken) {

					request.getSession().removeAttribute("USER");
					request.getSession().removeAttribute("USER_INFO");
				}

			});

		if (!Validator.isNullOrEmpty(redirectURL)) {
			return new RedirectView(redirectURL);
		}

		return new RedirectView("landing");
	}

	private static Logger logger = LoggerFactory.getLogger(SpidController.class);

	@Autowired
	private RelyingPartyWrapper relyingPartyWrapper;


}
