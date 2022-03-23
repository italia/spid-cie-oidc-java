package it.spid.cie.oidc.spring.boot.relying.party.storage;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

public interface OidcAuthenticationTokenRepository
	extends CrudRepository<OidcAuthenticationToken, Long> {

	public Optional<OidcAuthenticationToken> findById(Long id);

	@Query(
		value =
			"select * from oidc_authentication_token o " +
			" where o.user_key = ?1 and revoked is null " +
			" order by modified",
		nativeQuery = true
	)
	public List<OidcAuthenticationToken> findUserTokens(String userKey);

}
