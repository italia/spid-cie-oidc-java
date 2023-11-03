CREATE TABLE IF NOT EXISTS trust_chain (
	id INT AUTO_INCREMENT PRIMARY KEY,
	created TIMESTAMP(0) NOT NULL,
	modified TIMESTAMP(0) NOT NULL,
	sub VARCHAR(255) NOT NULL,
	type_ VARCHAR(33) NOT NULL,
	exp TIMESTAMP(0) NOT NULL,
	iat TIMESTAMP(0) NOT NULL,
	chain VARCHAR NOT NULL,
	parties_involved VARCHAR NOT NULL,
	is_active BOOLEAN NOT NULL,
	log VARCHAR NOT NULL,
	metadata VARCHAR NULL,
	processing_start TIMESTAMP(0) NOT NULL,
	trust_anchor_id INTEGER NOT NULL,
	trust_masks VARCHAR NOT NULL,
	status VARCHAR(33) NOT NULL
);

CREATE TABLE IF NOT EXISTS fetched_entity_statement (
	id INT AUTO_INCREMENT PRIMARY KEY,
	created TIMESTAMP(0) NOT NULL,
	modified TIMESTAMP(0) NOT NULL,
	iss VARCHAR(255) NOT NULL,
	sub VARCHAR(255) NOT NULL,
	exp TIMESTAMP(0) NOT NULL,
	iat TIMESTAMP(0) NOT NULL,
	statement VARCHAR NOT NULL,
	jwt VARCHAR NOT NULL,
	UNIQUE (iss, sub)
);

CREATE TABLE IF NOT EXISTS federation_entity_configuration (
	id INT AUTO_INCREMENT PRIMARY KEY,
	created TIMESTAMP(0) NOT NULL,
	modified TIMESTAMP(0) NOT NULL,
	sub VARCHAR(255) NOT NULL,
	default_exp INTEGER NOT NULL,
	default_signature_alg VARCHAR(16) NOT NULL,
	authority_hints VARCHAR NOT NULL,
	jwks VARCHAR NOT NULL,
	trust_marks VARCHAR NOT NULL,
	trust_mark_issuers VARCHAR NOT NULL,
	metadata VARCHAR NOT NULL,
	constraints VARCHAR NOT NULL,
	is_active BOOLEAN NOT NULL,
	entity_type VARCHAR(33) NOT NULL,
	UNIQUE(sub)
);

CREATE TABLE IF NOT EXISTS  oidc_authentication (
	id INT AUTO_INCREMENT PRIMARY KEY,
	created TIMESTAMP(0) NOT NULL,
	modified TIMESTAMP(0) NOT NULL,
	client_id VARCHAR NOT NULL,
	state VARCHAR NOT NULL,
	endpoint VARCHAR NULL,
	data VARCHAR NULL,
	successful BOOLEAN NOT NULL,
	provider_configuration VARCHAR NULL,
	provider VARCHAR NULL,
	provider_id VARCHAR NULL,
	provider_jwks VARCHAR NULL,
	UNIQUE(state)
);

CREATE TABLE IF NOT EXISTS  oidc_authentication_token (
	id INT AUTO_INCREMENT PRIMARY KEY,
	created TIMESTAMP(0) NOT NULL,
	modified TIMESTAMP(0) NOT NULL,
	code VARCHAR NULL,
	scope VARCHAR NULL,
	access_token VARCHAR NULL,
	id_token VARCHAR NULL,
	token_type VARCHAR NULL,
	expires_in INTEGER NULL,
	authz_request_id INTEGER NOT NULL,
	user_key VARCHAR NULL,
	revoked TIMESTAMP(0) NULL,
	refresh_token VARCHAR NULL,
	UNIQUE(authz_request_id)
);


