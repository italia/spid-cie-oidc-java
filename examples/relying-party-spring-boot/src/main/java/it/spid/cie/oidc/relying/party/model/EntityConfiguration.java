package it.spid.cie.oidc.relying.party.model;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.spid.cie.oidc.relying.party.helper.EntityHelper;
import it.spid.cie.oidc.relying.party.helper.JWTHelper;
import it.spid.cie.oidc.relying.party.util.ListUtil;
import it.spid.cie.oidc.relying.party.util.StringUtil;
import it.spid.cie.oidc.relying.party.util.Validator;
import it.spid.cie.oidc.spring.boot.relying.party.storage.EntityInfo;

public class EntityConfiguration {

	public static EntityConfiguration of(EntityInfo entityInfo)
		throws Exception {

		return new EntityConfiguration(entityInfo.getJwt());
	}

	/**
	 *
	 * @param jwt the JWS Token
	 */
	public EntityConfiguration(String jwt) throws Exception {
		this(jwt, null);
	}

	public EntityConfiguration(String jwt, EntityConfiguration trustAnchor)
		throws Exception {

		this.jwt = jwt;
		this.trustAnchor = trustAnchor;

		JSONObject token = JWTHelper.fastParse(jwt);

		this.header = token.getJSONObject("header");
		this.payload = token.getJSONObject("payload");

		if (logger.isDebugEnabled()) {
			logger.debug("fastParse=" + token.toString());
		}

		/*
		try {
			PlainObject plainObject = PlainObject.parse(jwt);

			System.out.println("header=" + plainObject.getHeader().toString());
			System.out.println("payload=" + plainObject.getPayload().toString());

			return;
		}
		catch (java.text.ParseException e) {
			System.err.println(e);
			// Invalid plain JOSE object encoding
		}

		try {
			PlainJWT plainJWT = PlainJWT.parse(jwt);

			System.out.println("header=" + plainJWT.getHeader().toString());
			System.out.println("payload=" + plainJWT.getPayload().toString());
		}
		catch (java.text.ParseException e) {
			System.err.println(e);
			// Invalid plain JOSE object encoding
		}
		 */

		/*
		// We expect to have a valid JWS Token
		JWSObject jwsObject = JWSObject.parse(jwt);

		this.header = jwsObject.getHeader();
		this.payload = jwsObject.getPayload();
		this.sub = GetterUtil.getString(payload.toJSONObject().get("sub"));
		this.iss = GetterUtil.getString(payload.toJSONObject().get("iss"));
		*/

		this.sub = payload.getString("sub");
		this.iss = payload.getString("iss");
		this.exp = payload.getLong("exp");

		extractJwks();
	}

//	public JSONObject getHeader() {
//		return header;
//	}

	public String getJwt() {
		return jwt;
	}

//	public JSONObject getPayload() {
//		return payload;
//	}

	public String getSub() {
		return sub;
	}

	public long getExp() {
		return exp;
	}

	public void addFailedDescendantStatement(String key, JSONObject value) {
		// TODO: needed?
	}

	public void addVerifiedDescendantStatement(String key, JSONObject value) {
		this.verifiedDescendantStatements.put(key, value);
	}

	public JSONObject getVerifiedDescendantPayloadMetadataPolicy(String metadataType) {
		// TODO: What if we have more than one entry?
		Iterator<JSONObject> itr = this.verifiedDescendantStatements.values().iterator();

		if (!itr.hasNext()) {
			return null;
		}

		JSONObject value = itr.next();

		return value.optJSONObject(
				"metadata_policy", new JSONObject()
			).optJSONObject(metadataType);
	}

	public JSONObject getPayloadMetadata() {
		return payload.optJSONObject("metadata", new JSONObject());
	}

	public String getFederationFetchEndpoint() {
		JSONObject metadata = payload.optJSONObject("metadata");

		if (metadata != null) {
			JSONObject federationEntity = metadata.optJSONObject(
				"federation_entity");

			if (federationEntity != null) {
				return federationEntity.optString("federation_fetch_endpoint");
			}
		}

		return null;
	}

	public String getPayload() {
		return payload.toString();
	}

	public long getPayloadLong(String key) {
		return payload.optLong(key);
	}

	public String getPayloadString(String key) {
		return payload.optString(key);
	}

	public JSONObject getPayloadJSONObject(String key) {
		return payload.optJSONObject(key);
	}

	public boolean isValid() {
		return this.valid;
	}

	public boolean hasVerifiedBySuperiors() {
		return !verifiedBySuperiors.isEmpty();
	}

	public boolean hasVerifiedDescendantStatement() {
		return !verifiedDescendantStatements.isEmpty();
	}

	public List<EntityConfiguration> getVerifiedBySuperiors() {
		List<EntityConfiguration> result = new ArrayList<>(
			this.verifiedBySuperiors.values());

		return Collections.unmodifiableList(result);
	}

	public List<String> getVerifiedDescendantStatement() {
		List<String> result = new ArrayList<>();

		for (JSONObject value : verifiedDescendantStatements.values()) {
			result.add(value.toString());
		}

		return Collections.unmodifiableList(result);
	}

	@Override
	public String toString() {
		return String.format("(%s valid:%b)", this.sub, this.valid);
	}

	public Map<String, EntityConfiguration> getSuperiors(
			int maxAuthorityHints, List<EntityConfiguration> superiorHints)
		throws Exception {

		List<String> authorityHints = getPayloadStringArray("authority_hints");

		if (maxAuthorityHints > 0 && authorityHints.size() > maxAuthorityHints) {
			int end = authorityHints.size() - maxAuthorityHints;

			logger.warn(
				"Found {} but authority maximum hints is set to {}. The following " +
				"authorities will be ignored: {}", authorityHints.size(),
				maxAuthorityHints, StringUtil.merge(
					ListUtil.subList(authorityHints, 0, end)));

			authorityHints = ListUtil.lasts(authorityHints, maxAuthorityHints);
		}

		for (EntityConfiguration sup : superiorHints) {
			if (authorityHints.contains(sup.getSub())) {
				logger.info(
					"Getting Cached Entity Configurations for {}", sup.getSub());
				authorityHints.remove(sup.getSub());
				verifiedSuperiors.put(sup.getSub(), sup);
			}
		}

		logger.debug(
			"Getting Entity Configurations for {}", StringUtil.merge(authorityHints));

		Map<String, EntityConfiguration> target;

		for (String authorityHint : authorityHints) {
			EntityConfiguration ec;

			try {
				String jwt = EntityHelper.getEntityConfiguration(
					authorityHint);

				ec = new EntityConfiguration(jwt);
			}
			catch (Exception e) {
				logger.warn("Get Entity Configuration for {}: {}", jwt, e);

				continue;
			}

			if (ec.validateItself()) {
				target = this.verifiedSuperiors;
			}
			else {
				target = this.failedSuperiors;
			}

			target.put(ec.getSub(), ec);
		}

		// TODO: Python code recycle authorityHints. Why?

		return this.verifiedSuperiors;
	}

	/**
	 * Validate the EntityConfiguration by itself
	 */
	public boolean validateItself() {
		try {
			return validateItself(true);
		}
		catch (Exception e) {
		}

		return false;
	}

	/**
	 * Validate the EntityConfiguration by itself
	 *
	 * @param silentMode when false Exceptions will be propagated to caller
	 * @return true if entity jwt is self validated
	 * @throws Exception
	 */
	public boolean validateItself(boolean silentMode) throws Exception {
		try {
			this.valid = JWTHelper.verifyJWS(this.jwt, this.jwkSet);

			return this.valid;
		}
		catch (Exception e) {
			logger.error(e.getMessage(), e);

			if (!silentMode) {
				throw e;
			}
		}

		return false;
	}

	public boolean validateBySuperior(String jwt, EntityConfiguration ec)
		throws Exception {

		boolean valid = false;

		JSONObject payload = null;

		try {
			payload = JWTHelper.fastParsePayload(jwt);

			ec.validateItself(false);
			ec.validateDescendant(jwt);

			// Validate entity JWS using superior JWKSet

			JWKSet jwkSet = JWTHelper.getJWKSetFromJWT(jwt);

			valid = JWTHelper.verifyJWS(this.jwt, jwkSet);
		}
		catch (Exception e) {
			StringBuilder sb = new StringBuilder();

			sb.append(getSub());
			sb.append(" failed validation with ");
			sb.append(ec.getSub());
			sb.append("'s superior statement ");
			if (payload != null) {
				sb.append(payload.toString());
			}
			else {
				sb.append(jwt);
			}
			sb.append(". Exception ");
			sb.append(e);

			logger.warn(sb.toString());
		}

		if (valid) {
			ec.addVerifiedDescendantStatement(getSub(), payload);
			this.verifiedBySuperiors.put(payload.getString("iss"), ec);
			this.valid = true;

			// TODO ?? return verifiedBySuperiors(getSub());
		}
		else {

		}
		return valid;
	}

	/**
	 * Validates this entity configuration with the entity statements issued by
	 * its superiors.
	 * <br/>
	 * This method fills the following internal properties:
	 * <ul>
	 *   <li>verifiedSuperiors</li>
	 *   <li>failedSuperiors</li>
	 *   <li>verifiedBySuperiors</li>
	 *   <li>failedBySuperiors</li>
	 *  </ul>
	 *
	 * @param superiors
	 * @return the verifiedSuperiors property
	 * @throws Exception
	 */
	public Map<String, EntityConfiguration> validateBySuperiors(
			Collection<EntityConfiguration> superiors)
		throws Exception {

		for (EntityConfiguration ec : superiors) {
			if (this.verifiedBySuperiors.containsKey(ec.getSub())) {
				continue;
			}

			String federationApiEndpoint = ec.getFederationFetchEndpoint();

			if (Validator.isNullOrEmpty(federationApiEndpoint)) {
				logger.warn(
					"Missing federation_fetch_endpoint in federation_entity " +
					"metadata for {} by {}", getSub(), ec.getSub());

				this.failedBySuperiors.put(ec.getSub(), null);
				continue;
			}

			String url = federationApiEndpoint + "?sub=" + getSub();

			logger.info("Getting entity statements from {}", url);

			String jwt = EntityHelper.getEntityStatement(url);

			validateBySuperior(jwt, ec);
		}

		return Collections.unmodifiableMap(this.verifiedBySuperiors);
	}

	public boolean validateDescendant(String jwt) throws Exception {

		// Fast decode JWT token

		JSONObject token = JWTHelper.fastParse(jwt);

		JSONObject header = token.getJSONObject("header");
		JSONObject payload = token.getJSONObject("payload");

		logger.debug("validateDescendant " + token.toString());

		// Check kid coherence

		String kid = header.optString("kid");

		if (!this.jwksKids.contains(kid)) {
			//throw new UnknownKid(kid  + " not found in " + jwkSet.toString());
			throw new Exception(kid  + " not found in " + jwkSet.toString());
		}

		if (JWTHelper.verifyJWS(jwt, this.jwkSet)) {
			// TODO: need to fill verifiedDescendantStatements* Map?

			return true;
		}
		else {
			// TODO: have to throw exception?
			return false;
		}
	}

	private void extractJwks() throws Exception {
		JSONObject jwks = payload.optJSONObject("jwks");

		if (jwks != null) {
			this.jwkSet = JWKSet.parse(jwks.toMap());
		}

		if (jwkSet == null || jwkSet.getKeys().size() == 0) {
			String msg = String.format(
				"Missing jwks in the statement for {}", sub);
			logger.error(msg);
			//TODO throw new MissingJwksClaimException(msg);
			throw new Exception(msg);
		}

		for (JWK key : jwkSet.getKeys()) {
			jwksKids.add(key.getKeyID());
		}
	}

	private List<String> getPayloadStringArray(String key) {
		List<String> result = new ArrayList<>();

		JSONArray array = payload.optJSONArray(key);

		if (array != null) {
			for (int x = 0; x < array.length(); x++) {
				result.add(array.getString(x));
			}
		}

		return result;
	}

	private static final Logger logger = LoggerFactory.getLogger(
		EntityConfiguration.class);

	private final String jwt;
	private EntityConfiguration trustAnchor;
	private JSONObject header;
	private JSONObject payload;
	private String sub;
	private String iss;
	private long exp;
	private JWKSet jwkSet;
	private List<String> jwksKids = new ArrayList<>();
	private Map<String, EntityConfiguration> verifiedSuperiors = new HashMap<>();
	private Map<String, EntityConfiguration> failedSuperiors = new HashMap<>();
	private Map<String, EntityConfiguration> verifiedBySuperiors = new HashMap<>();
	private Map<String, EntityConfiguration> failedBySuperiors = new HashMap<>();
	private Map<String, JSONObject> verifiedDescendantStatements = new HashMap<>();


	private boolean valid = false;


}