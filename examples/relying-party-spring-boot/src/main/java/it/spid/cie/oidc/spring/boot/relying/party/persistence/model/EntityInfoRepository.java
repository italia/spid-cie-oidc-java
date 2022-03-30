package it.spid.cie.oidc.spring.boot.relying.party.persistence.model;

import java.util.Optional;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

public interface EntityInfoRepository
	extends CrudRepository<EntityInfoModel, Long> {

	public Optional<EntityInfoModel> findById(Long id);

	@Query(
		value = "select * from fetched_entity_statement f where f.sub = ?1 and f.iss = ?2 LIMIT 1",
		nativeQuery = true)
	public EntityInfoModel fetchEntity(String sub, String iss);

}
