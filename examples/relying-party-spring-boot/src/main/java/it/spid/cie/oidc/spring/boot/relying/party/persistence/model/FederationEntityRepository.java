package it.spid.cie.oidc.spring.boot.relying.party.persistence.model;

import java.util.Optional;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

public interface FederationEntityRepository
	extends CrudRepository<FederationEntityModel, Long> {

	public Optional<FederationEntityModel> findById(Long id);

	@Query(
		value = "select * from federation_entity_configuration f where f.sub = ?1 and f.is_active = ?2 LIMIT 1",
		nativeQuery = true
	)
	public FederationEntityModel fetchBySubActive(String sub, boolean active);

	@Query(
		value = "select * from federation_entity_configuration f where f.sub = ?1 LIMIT 1",
		nativeQuery = true
	)
	public FederationEntityModel fetchBySubject(String subject);

}
