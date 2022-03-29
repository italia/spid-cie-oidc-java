package it.spid.cie.oidc.spring.boot.relying.party.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/oidc/rp")
public class SpidController {

	private static Logger logger = LoggerFactory.getLogger(SpidController.class);

}
