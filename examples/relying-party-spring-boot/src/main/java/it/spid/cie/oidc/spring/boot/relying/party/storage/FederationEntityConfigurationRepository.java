package it.spid.cie.oidc.spring.boot.relying.party.storage;

import java.util.Optional;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

public interface FederationEntityConfigurationRepository
	extends CrudRepository<FederationEntityConfiguration, Long> {

	public Optional<FederationEntityConfiguration> findById(Long id);

	@Query(
		value = "select * from federation_entity_configuration f where f.sub = ?1 and f.is_active = ?2 LIMIT 1",
		nativeQuery = true
	)
	public FederationEntityConfiguration fetchBySubActive(String sub, boolean active);

	@Query(
		value = "select * from federation_entity_configuration f where f.entity_type = ?1 LIMIT 1",
		nativeQuery = true
	)
	public FederationEntityConfiguration fetchByEntityType(String entityType);

}
