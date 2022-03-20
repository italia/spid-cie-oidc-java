package it.spid.cie.oidc.relying.party.model;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.StringJoiner;
import java.util.TreeMap;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.spid.cie.oidc.relying.party.helper.EntityHelper;
import it.spid.cie.oidc.relying.party.model.EntityConfiguration;
import it.spid.cie.oidc.relying.party.util.ListUtil;

// TODO: Refactor to have a build method returning a TrustChain bean
public class TrustChainBuilder {

	public TrustChainBuilder(String subject, String metadataType) {
		this.subject = subject;
		this.metadataType = metadataType;
	}

	/*
	public TrustChainBuilder(
		String subject, EntityConfiguration trustAnchor, int maxAuthorityHints,
		EntityConfiguration subjectConfiguration,
		int requiredTrustMarks, String metadataType) {

		this.subject = subject;

	}
	*/

	public LocalDateTime getExpiration() {
		return LocalDateTime.ofEpochSecond(exp, 0, ZoneOffset.UTC);
	}

	public String getFinalMetadata() {
		if (finalMetadata == null) {
			return null;
		}

		return this.finalMetadata.toString();
	}

	public String getChainAsString() {
		StringJoiner sj = new StringJoiner(",", "[", "]");

		for (EntityConfiguration ec : trustPath) {
			sj.add(ec.getPayload());
			if (ec.hasVerifiedDescendantStatement()) {
				StringJoiner sj2 = new StringJoiner(",", "[", "]");

				for (String value : ec.getVerifiedDescendantStatement()) {
					sj2.add(value);
				}

				sj.add(sj2.toString());
			}
		}

		return sj.toString();
	}

	public String getPartiesInvolvedAsString() {
		StringJoiner sj = new StringJoiner(",", "[", "]");

		for (EntityConfiguration ec : trustPath) {
			sj.add(ec.getSub());
		}

		return sj.toString();
	}

	public String getVerifiedTrustMarksAsString() {
		JSONArray result = new JSONArray();

		// TODO: manage trust mask

		return result.toString();
	}

	public String getSubject() {
		return this.subject;
	}

	public boolean isValid() {
		return this.valid;
	}

	public TrustChainBuilder setMaxAuthorityHints(int maxAuthorityHints) {
		this.maxAuthorityHints = maxAuthorityHints;

		return this;
	}

	public TrustChainBuilder setRequiredTrustMask(String[] requiredTrustMasks) {
		this.requiredTrustMasks = requiredTrustMasks;

		return this;
	}

	public TrustChainBuilder setSubjectConfiguration(
		EntityConfiguration subjectConfiguration) {

		this.subjectConfiguration = subjectConfiguration;

		return this;
	}

	public TrustChainBuilder setTrustAnchor(EntityConfiguration trustAnchor) {
		trustAnchorConfiguration = trustAnchor;

		return this;
	}

	public TrustChainBuilder setTrustAnchor(String trustAnchor)
		throws Exception {

		logger.info("Starting Metadata Discovery for {}", subject);

		String jwt = EntityHelper.getEntityConfiguration(trustAnchor);

		trustAnchorConfiguration = new EntityConfiguration(jwt);

		return this;
	}

	public TrustChainBuilder start() throws Exception {
		try {
			processTrustAnchorConfiguration();
			processSubjectConfiguration();
			discovery();
		}
		catch (Exception e) {
			logger.error(e.getMessage(), e);
			this.valid = false;
			throw e;
		}

		return this;
	}

	/**
	 * Filters the trust path from subject to trust anchor, apply the metadata
	 * policies along the path and returns the final metadata
	 *
	 * @throws Exception
	 */
	protected void applyMetadataPolicy() throws Exception {

		if (trustPath.isEmpty()) {
			trustPath.add(subjectConfiguration);
		}
		else {
			EntityConfiguration ec = ListUtil.getLast(trustPath);

			if (ec != null && ec.getSub().equals(trustAnchorConfiguration.getSub())) {
				return;
			}
		}

		logger.info(
			"Applying metadata policy for {} over {} starting from {}",
			this.subject, trustAnchorConfiguration.getSub(), ListUtil.getLast(trustPath));

		List<EntityConfiguration> lastNodeEcs = trustsTree.get(trustPath.size() - 1);

		boolean pathFound = false;
		final String trustAnchorSubject = trustAnchorConfiguration.getSub();

		for (EntityConfiguration ec : lastNodeEcs) {
			for (EntityConfiguration supEc : ec.getVerifiedBySuperiors()) {
				while ((trustPath.size() - 2) < maxPathLength) {
					if (supEc.getSub().equals(trustAnchorSubject)) {
						trustPath.add(supEc);
						pathFound = true;
						break;
					}

					if (supEc.hasVerifiedBySuperiors()) {
						trustPath.add(supEc);
						applyMetadataPolicy();
					}
					else {
						logger.info(
							"'Huston, we have a problem' in {} for {} to {}",
							supEc.getSub(), this.subject,
							trustAnchorConfiguration.getSub());

						trustPath.add(this.subjectConfiguration);
						break;
					}
				}
			}
		}

		// once I filtered a concrete and unique trust path I can apply the metadata
		// policy

		if (pathFound) {
			logger.info("Found a trust path: {}", this.trustPath);

			this.finalMetadata = this.subjectConfiguration
				.getPayloadMetadata()
				.optJSONObject(metadataType);

			if (this.finalMetadata == null) {
				logger.error(
					"Missing {} in {}",
					this.metadataType, this.subjectConfiguration.getPayloadMetadata());

				return;
			}

			for (int x = trustPath.size(); x > 0; x--) {
				JSONObject pol = trustPath.get(x - 1)
					.getVerifiedDescendantPayloadMetadataPolicy(metadataType);

				if (pol != null) {
					this.finalMetadata = applyPolicy(this.finalMetadata, pol);
				}
			}
		}

		setExpiration();

		// return this.finalMetadata;
	}

	protected JSONObject applyPolicy(JSONObject metadata, JSONObject policy)
		throws Exception {

		Set<String> policyKeys = policy.keySet();

		for (String key : policy.keySet()) {
			// First Level is always a JSON Object
			JSONObject p = policy.getJSONObject(key);

			if (!metadata.has(key)) {
				if (p.has("value")) {
					metadata.put(key, p.get("value"));
				}
				else if (p.has("add")) {
					metadata.put(key, p.get("add"));
				}
				else if (p.has("default")) {
					metadata.put(key, p.get("default"));
				}
				else if (p.has("essential")) {
					// TODO: undestand essential
				}

				continue;
			}

			if (p.has("value")) {
				metadata.put(key, p.get("value"));
			}
			else if (p.has("one_of")) {
				JSONArray oneOf = p.getJSONArray("one_of");
				JSONArray ar = metadata.optJSONArray(key);

				if (ar != null) {
					boolean good = false;

					for (int x = 0; x < ar.length(); x++) {
						if (jsonArrayContains(oneOf, ar.get(x))) {
							metadata.put(key, ar.get(x));
							good = true;
							break;
						}
					}

					if (!good) {
						throw new Exception(
							String.format(
								"%s: None of %s among %s", key, ar.toString(),
								oneOf.toString()));
					}
				}
				else {
					Object o = metadata.get(key);

					if (!jsonArrayContains(oneOf, o)) {
						throw new Exception(
							String.format(
								"%s: %s not among %s", key, ar.toString(),
								oneOf.toString()));
					}
				}
			}
			else if (p.has("add")) {
				metadata.put(key, jsonArrayUnion(metadata.get(key), p.get("add")));
			}
			else if (p.has("subset_of")) {
				JSONArray ar = jsonArrayIntersect(p.get("subset_of"), metadata.get(key));

				if (!ar.isEmpty()) {
					metadata.put(key, ar);
				}
				else {
					throw new Exception(
						String.format(
							"%s: %s not subset of %s", key, metadata.get(key),
							p.get("subset_of")));
				}
			}
			else if (p.has("superset_of")) {
				JSONArray ar = jsonArrayDifference(
					p.get("superset_of"), metadata.get(key));

				if (!ar.isEmpty()) {
					metadata.put(key, ar);
				}
				else {
					throw new Exception(
						String.format(
							"%s: %s not superset of %s", key, metadata.get(key),
							p.get("superset_of")));
				}
			}
		}

		return metadata;
	}

	protected boolean discovery() throws Exception {
		logger.info("Starting a Walk into Metadata Discovery for " + subject);

		trustsTree.put(0, Arrays.asList(subjectConfiguration));

		List<String> processedSubjects = new ArrayList<>();

		List<EntityConfiguration> superiorHints = Arrays.asList(
			this.trustAnchorConfiguration);

		while ((trustsTree.size() -2) < maxPathLength) {
			List<EntityConfiguration> entities = trustsTree.get(trustsTree.size() -1);

			List<EntityConfiguration> supEcs = new ArrayList<>();

			for (EntityConfiguration ec : entities) {
				if (processedSubjects.contains(ec.getSub())) {
					logger.warn(
						"Metadata discovery loop detection for {}. " +
						"Already present in {}. " +
						"Discovery blocked for this path.", ec.getSub(),
						processedSubjects);

					continue;
				}

				try {
					Map<String, EntityConfiguration> superiors =
						ec.getSuperiors(
							this.maxAuthorityHints, superiorHints);

					Map<String, EntityConfiguration> verifiedSuperiors =
						ec.validateBySuperiors(superiors.values());

					supEcs.addAll(verifiedSuperiors.values());

					processedSubjects.add(ec.getSub());
				}
				catch (Exception e) {
					logger.error(
						"Metadata discovery exception for {}: {}", ec.getSub(),
						e);
				}
			}

			if (!supEcs.isEmpty()) {
				trustsTree.put(trustsTree.size(), supEcs);
			}
			else {
				break;
			}
		}

		EntityConfiguration first = getTrustsTreeNodeValue(0, 0);
		EntityConfiguration last = getTrustsTreeNodeValue(-1, 0);

		if (first != null && first.isValid() && last != null && last.isValid()) {
			this.valid = true;
			applyMetadataPolicy();
		}

		return this.valid;
	}

	protected void processSubjectConfiguration() throws Exception {
		if (subjectConfiguration != null) {
			return;
		}

		try {
			String jwt = EntityHelper.getEntityConfiguration(subject);

			subjectConfiguration = new EntityConfiguration(
				jwt, trustAnchorConfiguration);

			subjectConfiguration.validateItself();
		}
		catch (Exception e) {
			String msg = String.format(
				"Entity Configuration for %s failed: %s", subject,
				e.getMessage());

			logger.error(msg);

			throw new Exception(msg);
		}

		if (requiredTrustMasks.length > 0) {
			// TODO
			//subjectConfiguration.setAllowedTrustMasks(requiredTrustMasks);
			throw new Exception("To Implement");
		}
	}

	protected void processTrustAnchorConfiguration() throws Exception {
		if (trustAnchorConfiguration == null) {
			throw new Exception("Please set TurstAnchor");
		}

		try {
			trustAnchorConfiguration.validateItself(false);
		}
		catch (Exception e) {
			String message =
				"Trust Anchor Entity Configuration validation failed with " + e;

			logger.error(message);

			throw new Exception(message);
		}

		JSONObject constraints =
			trustAnchorConfiguration.getPayloadJSONObject("constraints");

		if (constraints.has("max_path_length")) {
			this.maxPathLength = constraints.getInt("max_path_length");
		}
	}

	protected void setExpiration() {
		this.exp = 0;

		for (EntityConfiguration ec : this.trustPath) {
			if (this.exp == 0) {
				this.exp = ec.getExp();
			}
			else if (ec.getExp() > this.exp) {
				this.exp = ec.getExp();
			}
		}
	}

	private EntityConfiguration getTrustsTreeNodeValue(int nodeIdx, int valueIdx) {
		List<EntityConfiguration> value;

		if (nodeIdx >= 0) {
			value = trustsTree.get(nodeIdx);
		}
		else {
			value = trustsTree.get(trustsTree.size() - 1);
		}

		if (value != null && !value.isEmpty()) {
			if (valueIdx < 0) {
				return value.get(value.size() - 1);
			}
			else if (valueIdx < value.size()) {
				return value.get(valueIdx);
			}
		}

		return null;
	}

	private boolean jsonArrayContains(JSONArray array, Object value) {
		for (int x = 0; x < array.length(); x++) {
			if (Objects.equals(value, array.get(x))) {
				return true;
			}
		}

		return false;
	}

	private JSONArray jsonArrayUnion(Object o1, Object o2) {
		Set<Object> result = new HashSet<>();

		if (o1 instanceof JSONArray) {
			result.addAll(((JSONArray)o1).toList());
		}
		else {
			result.add(o1);
		}
		if (o2 instanceof JSONArray) {
			result.addAll(((JSONArray)o2).toList());
		}
		else {
			result.add(o2);
		}

		return new JSONArray(result);
	}

	private JSONArray jsonArrayIntersect(Object o1, Object o2) {
		Set<Object> s1 = new HashSet<>();

		if (o1 instanceof JSONArray) {
			s1.addAll(((JSONArray)o1).toList());
		}
		else {
			s1.add(o1);
		}

		Set<Object> s2 = new HashSet<>();

		if (o2 instanceof JSONArray) {
			s2.addAll(((JSONArray)o2).toList());
		}
		else {
			s2.add(o2);
		}

		s1.retainAll(s2);

		return new JSONArray(s1);
	}

	private JSONArray jsonArrayDifference(Object o1, Object o2) {
		Set<Object> s1 = new HashSet<>();

		if (o1 instanceof JSONArray) {
			s1.addAll(((JSONArray)o1).toList());
		}
		else {
			s1.add(o1);
		}

		Set<Object> s2 = new HashSet<>();

		if (o2 instanceof JSONArray) {
			s2.addAll(((JSONArray)o2).toList());
		}
		else {
			s2.add(o2);
		}

		s1.removeAll(s2);

		return new JSONArray(s1);
	}


	private static final Logger logger = LoggerFactory.getLogger(
		TrustChainBuilder.class);

	private final String subject;
	private final String metadataType;
	private EntityConfiguration subjectConfiguration;
	private EntityConfiguration trustAnchorConfiguration;
	private int maxPathLength = 0;
	private int maxAuthorityHints = 10;
	private String[] requiredTrustMasks = new String[0];
	private Map<Integer, List<EntityConfiguration>> trustsTree = new TreeMap<>();
	private List<EntityConfiguration> trustPath = new ArrayList<>();
	private long exp = 0;
	private boolean valid = false;
	private JSONObject finalMetadata;
	private Set<String> verifiedTrustMasks = new HashSet<>();


}
