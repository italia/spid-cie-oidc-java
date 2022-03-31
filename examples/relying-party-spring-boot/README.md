# SPID CIE OIDC Relying Party Example Project with SpringBoot and Java

This project showcases the relying party.

## Requirements:

- [python](https://www.python.org/downloads/) 3.x or higher
- [openjdk](https://openjdk.java.net/) 11

## How to run

Run the provider [federation](https://github.com/italia/spid-cie-oidc-django)

- follow these [instructions](https://github.com/italia/spid-cie-oidc-django/blob/main/docs/SETUP.md)
- the project should run on [http://127.0.0.1:8000](http://127.0.0.1:8000), keep it running


Clone this repository and install all the lement inside the MavenLocal registry
```
git clone https://github.com/italia/spid-cie-oidc-java

cd spid-cie-oidc-java

./mvnw clean install
```


Start the spring boot example

```
cd examples/relying-party-spring-boot
../../mvnw clean spring-boot:run
```

this will start the relying party server on [http://127.0.0.1:8080](http://127.0.0.1:8080), keep it running



Do the onboarding process
- generate the relying party jwks
  - go [here](http://127.0.0.1:8080/oidc/rp/.well-known/openid-federation?format=json) to autogenerate it
  - jwks are exposed inside application log
  - paste it into `application.yml` or save as `${user.home}/oidc-rp-jwk.json`
- stop and restart the spring boot example
  - go [here](http://127.0.0.1:8080/oidc/rp/.well-known/openid-federation?format=json)
  - in the application log you will see the configured jwk and the public jwks required for the next step
- register the relying party [here](http://127.0.0.1:8000/admin/spid_cie_oidc_authority/federationdescendant/add)
  - set the name you want
  - use "http://127.0.0.1:8080/oidc/rp/" as sub
  - paste in the relying party federation public jwks exposed in the SpringBoot logs
  - set isActive to true
- create new profile [here](http://127.0.0.1:8000/admin/spid_cie_oidc_authority/federationentityassignedprofile/add/)
  - set this relying party as Descendant
  - set "SPID Public SP" as Profile
  - set the Federation Entity as Issuer
- after creation you review the profiles
  - copy trust_marks from here to `application.yml` or save as `${user.home}/oidc-rp-trust-marks.json`
  - here the trust_marks are exposed as JSONObject you have to store it as JSONArray (put `[` `]` aroud it)
- stop and restart the spring boot example
  - go [here](http://127.0.0.1:8080/oidc/rp/.well-known/openid-federation?format=json)
  - verify trust_marks are exposed


Visit [http://127.0.0.1:8080/oidc/rp/landing](http://127.0.0.1:8080/oidc/rp/landing) to try out the application


## Docker

A docker image containing this example can be built a run:
  - `docker-compose up`
  - visit `http://127.0.0.1:8080/`

Some hints:
- we are still using [federation](https://github.com/italia/spid-cie-oidc-django) v0.5.0 (we be updated soon)
- docker images currently sets a proxy of the exposed ports on the localhost interface, so you could use previous chapter instructions
- docker compose mounts the folder "./docker-data" inside spring-boot container to externalize `jwk` and `trust-marks` configuration


