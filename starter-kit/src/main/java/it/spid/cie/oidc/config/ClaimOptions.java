package it.spid.cie.oidc.config;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.json.JSONObject;

import it.spid.cie.oidc.exception.ConfigException;
import it.spid.cie.oidc.exception.OIDCException;
import it.spid.cie.oidc.schemas.ClaimItem;
import it.spid.cie.oidc.schemas.ClaimSection;

public class ClaimOptions {

	private Map<ClaimSection, Set<OptionItem>> itemsMap = new HashMap<>();

	public void addSectionItem(
			ClaimSection section, ClaimItem claimItem, Boolean essential)
		throws OIDCException {

		Set<OptionItem> items = itemsMap.get(section);

		if (items == null) {
			items = new HashSet<>();
			itemsMap.put(section, items);
		}

		items.add(OptionItem.of(claimItem, essential));
	}

	public Set<OptionItem> getSectionItems(ClaimSection section) {
		Set<OptionItem> items = itemsMap.get(section);

		if (items != null) {
			return Collections.unmodifiableSet(items);
		}

		return Collections.emptySet();
	}

	public boolean hasEssentialItem(String value) {
		for (OptionItem item : getSectionItems(ClaimSection.ID_TOKEN)) {
			if (item.isEssential() && item.matchClaimItem(value)) {
				return true;
			}
		}

		for (OptionItem item : getSectionItems(ClaimSection.USER_INFO)) {
			if (item.isEssential() && item.matchClaimItem(value)) {
				return true;
			}
		}

		return false;
	}

	public boolean isEmpty() {
		return itemsMap.isEmpty();
	}

	public JSONObject toJSON() {
		JSONObject idToken = new JSONObject();

		for (OptionItem item : getSectionItems(ClaimSection.ID_TOKEN)) {
			JSONObject value = new JSONObject();

			if (item.getEssential().isPresent()) {
				value.put("essential", item.getEssential().get());
			}

			idToken.put(item.getClaimItem().getAlias(), value);
		}

		JSONObject userInfo = new JSONObject();

		for (OptionItem item : getSectionItems(ClaimSection.USER_INFO)) {
			JSONObject value = new JSONObject();

			if (item.getEssential().isPresent()) {
				value.put("essential", item.getEssential().get());
			}

			userInfo.put(item.getClaimItem().getAlias(), value);
		}

		return new JSONObject()
			.put("id_token", idToken)
			.put("userinfo", userInfo);
	}

	public static class OptionItem {

		private final Boolean essential;
		private final ClaimItem claimItem;

		public static OptionItem of(ClaimItem claimItem, Boolean essential)
			throws OIDCException {

			return new OptionItem(claimItem, essential);
		}

		public OptionItem(ClaimItem claimItem, Boolean essential) throws OIDCException {
			if (claimItem == null) {
				throw new ConfigException("claimItem is null");
			}

			this.claimItem = claimItem;
			this.essential = essential;
		}

		public Optional<Boolean> getEssential() {
			return Optional.ofNullable(essential);
		}

		public ClaimItem getClaimItem() {
			return claimItem;
		}

		public boolean isEssential() {
			if (essential != null) {
				return essential;
			}

			return false;
		}

		public boolean matchClaimItem(String value) {
			if (Objects.equals(value, claimItem.getName()) ||
				Objects.equals(value, claimItem.getAlias())) {

				return true;
			}

			return false;
		}

	}

}
