package it.spid.cie.oidc.spring.boot.relying.party.storage;

import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

public interface OidcAuthenticationRepository
	extends CrudRepository<OidcAuthentication, Long> {

	public Optional<OidcAuthentication> findById(Long id);

	public List<OidcAuthentication> findByState(String state);

}
