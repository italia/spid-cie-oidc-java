package it.spid.cie.oidc.spring.boot.relying.party.storage;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

public interface TrustChainRepository extends CrudRepository<TrustChain, Long> {

	public Optional<TrustChain> findById(Long id);

	@Query(
		value = "SELECT * FROM trust_chain tc WHERE tc.sub = ?1 LIMIT 1",
		nativeQuery = true
	)
	public TrustChain fetchBySub(String sub);

	@Query(
		value =
			"SELECT tc.* FROM trust_chain tc " +
			" INNER JOIN fetched_entity_statement fes ON (" +
			" fes.id = tc.trust_anchor_id AND fes.sub = ?2)" +
			" WHERE tc.sub = ?1 " +
			" LIMIT 1",
		nativeQuery = true
	)
	public TrustChain fetchBySub_TASub(String sub, String trustAnchorSub);

	@Query(
		value =
			"SELECT tc.* FROM trust_chain tc " +
			" INNER JOIN fetched_entity_statement fes ON (" +
			" fes.id = tc.trust_anchor_id AND fes.sub = ?2)" +
			" WHERE tc.sub = ?1 AND tc.type_ = ?3" +
			" LIMIT 1",
		nativeQuery = true
	)
	public TrustChain fetchBySub_TASub_T(
		String sub, String trustAnchorSub, String type);

}
