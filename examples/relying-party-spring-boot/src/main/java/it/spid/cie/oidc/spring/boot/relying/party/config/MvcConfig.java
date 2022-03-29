package it.spid.cie.oidc.spring.boot.relying.party.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class MvcConfig implements WebMvcConfigurer {

	public void addViewControllers(ViewControllerRegistry registry) {
		registry.addViewController("/home").setViewName("home");
		registry.addViewController("/").setViewName("home");
		registry.addViewController("/oidc/rp/landing").setViewName("landing");
		registry
			.addViewController("/oidc/rp/.well-known/openid-federation")
			.setViewName("well-known");
		registry.addViewController("/hello").setViewName("hello");
		registry
			.addViewController("/oidc/rp/echo_attributes")
			.setViewName("echo_attributes");
	}

}
