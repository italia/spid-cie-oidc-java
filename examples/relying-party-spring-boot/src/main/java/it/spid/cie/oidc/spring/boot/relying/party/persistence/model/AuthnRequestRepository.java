package it.spid.cie.oidc.spring.boot.relying.party.persistence.model;

import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

public interface AuthnRequestRepository
	extends CrudRepository<AuthnRequestModel, Long> {

	public Optional<AuthnRequestModel> findById(Long id);

	public List<AuthnRequestModel> findByState(String state);

}
