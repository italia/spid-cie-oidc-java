package it.spid.cie.oidc.spring.boot.relying.party.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.json.JSONObject;
import org.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.spid.cie.oidc.config.RelyingPartyOptions;
import it.spid.cie.oidc.exception.OIDCException;
import it.spid.cie.oidc.model.FederationEntity;
import it.spid.cie.oidc.spring.boot.relying.party.RelyingPartyWrapper;
import it.spid.cie.oidc.spring.boot.relying.party.config.OidcConfig;
import it.spid.cie.oidc.spring.boot.relying.party.persistence.H2PersistenceImpl;
import it.spid.cie.oidc.model.TrustChain;
import it.spid.cie.oidc.helper.JWTHelper;

@RestController
@RequestMapping("/oidc/rp")
public class EntityStatementController {
    private static final Logger logger = LoggerFactory.getLogger(RelyingPartyWrapper.class);
    @Autowired
    private OidcConfig oidcConfig;
    @Autowired
    private H2PersistenceImpl persistenceImpl;

    @GetMapping("/resolve")
    public ResponseEntity<String> resolveEntityStatement(
            @RequestParam String sub,
            @RequestParam String anchor,
            @RequestParam(defaultValue = "jose") String format
    ) throws OIDCException {

        if (sub == null || anchor == null) {
            return new ResponseEntity<>("sub and anchor parameters are REQUIRED.", HttpStatus.NOT_FOUND);
        }
        String iss = oidcConfig.getRelyingParty().getClientId();

        FederationEntity entityConfiguration = persistenceImpl.fetchFederationEntity(iss, true);

        TrustChain entity = persistenceImpl.fetchTrustChain(sub, anchor);

        if (entity == null) {
            return new ResponseEntity<>("entity not found.", HttpStatus.NOT_FOUND);
        }
        JSONObject metadata = new JSONObject(entity.getMetadata());
        JSONArray trust_chain = new JSONArray(entity.getChain());

        JSONObject response = new JSONObject();
        response.put("iss", iss);
        response.put("sub", sub);
        response.put("iat", entity.getIssuedAt());
        response.put("exp", entity.getExpiresOn());
        response.put("trust_marks", entity.getTrustMarks());
        response.put("metadata", metadata);
        response.put("trust_chain",trust_chain);

        logger.info("resolve endpoint for {}, {}", sub, anchor);

        if ("json".equals(format)) {
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(response.toString());
        } else {
            JWTHelper jws = new JWTHelper(new RelyingPartyOptions());
            return new ResponseEntity<>(jws.createJWS(response, JWTHelper.getJWKSetFromJSON(entityConfiguration.getJwksFed())), HttpStatus.OK);
        }
    }
}