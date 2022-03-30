package it.spid.cie.oidc.spring.boot.relying.party.persistence.model;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

public interface AuthnTokenRepository
	extends CrudRepository<AuthnTokenModel, Long> {

	public Optional<AuthnTokenModel> findById(Long id);

	@Query(
		value =
			"select * from oidc_authentication_token o " +
			" where o.user_key = ?1 and revoked is null " +
			" order by modified",
		nativeQuery = true
	)
	public List<AuthnTokenModel> findUserTokens(String userKey);

}
