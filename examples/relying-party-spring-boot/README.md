# SPID CIE OIDC Relying Party Example Project with SpringBoot and Java

This project showcases the relying party.

## Requirements:

- [python](https://www.python.org/downloads/) 3.x or higher
- [openjdk](https://openjdk.java.net/) 11

## How to run

Run the provider [federation](https://github.com/italia/spid-cie-oidc-django)

- follow these [instructions](https://github.com/italia/spid-cie-oidc-django/blob/main/docs/SETUP.md)
- the project should run on [http://127.0.0.1:8000](http://127.0.0.1:8000), keep it running


Clone this repository and install all the elements inside the MavenLocal registry
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



Do the on-boarding process
- generate the relying party jwks
  - go [here](http://127.0.0.1:8080/) to auto-generate it
  - federation jwks and core jwks are exposed on the page and inside application log
  - create the file `${user.home}/oidc-rp-jwk.json` with the federation jwks
  - create the file `${user.home}/oidc-rp-core-jwk.json` with the core jwks
  - - use "reload" link to proceed with next step
- show on-boarding datas
  - go [here](http://127.0.0.1:8080/) to see it
- register the relying party [here](http://127.0.0.1:8000/admin/spid_cie_oidc_authority/federationdescendant/add)
  - set "name", "sub" and "jwks" with values shown in previous step
  - set isActive to true
- create new profile [here](http://127.0.0.1:8000/admin/spid_cie_oidc_authority/federationentityassignedprofile/add/)
  - set this relying party as Descendant
  - set "SPID Public SP" as Profile
  - set the Federation Entity as Issuer
- after creation you review the profiles
  - copy trust_marks and save as `${user.home}/oidc-rp-trust-marks.json`
  - trust_marks are exposed as JSONObject you have to store it as JSONArray (put `[` `]` around it)
- complete relying party on-boarding
  - go [here](http://127.0.0.1:8080/)
  - user "reload" link to acquire trust marks
  - go [here](http://127.0.0.1:8080/oidc/rp/.well-known/openid-federation?format=json) and verify trust_marks are exposed


Visit [http://127.0.0.1:8080/oidc/rp/landing](http://127.0.0.1:8080/oidc/rp/landing) to try out the application


## Docker

With docker we cannot use "127.0.0.1". Before proceed add this line to your `hosts` file

```
127.0.0.1   trust-anchor.org relying-party.org cie-provider.org
```

A docker image containing this example can be built a run:
- `docker-compose up`
- visit `http://relying-party.org:8080/`

Some hints:
- we are using [federation](https://github.com/italia/spid-cie-oidc-django) v1.4.0
- docker images currently sets a proxy of the exposed ports on the localhost interface, so you could use
previous chapter instructions replacing `127.0.0.1` with the right hostname
- docker image mounts the folder `./docker/data-java` as `/data` inside spring-boot container to externalize federation and core `jwks` and `trust-marks` configuration


[Docker Compose in action on YouTube](https://www.youtube.com/watch?v=U2Ec0No2EKg)

**To be onboarded into CIE Federation**:
- use always appropriate and valid TLS Certificates
- use IP from Italian networks for your server [CIE Federation preproduction servers are using geoblocking]
- as contact use the same institutional email address as stated into the administrative part [do not use PEC]
- when copy the federation public key please follow this pattern:
  - ```
    {
    "keys": [
        {
          "alg": "RS256",
          "kid": "....",
          "kty": "RSA",
          "n": ".....",
          "e": "AQAB",
          "use": "sig"
        }
      ]
    }
    ```
- when onboarded, please retrieve the Trust Mark form TA fetch endpoint like this example for preproduction: `https://preprod.oidc.registry.servizicie.interno.gov.it/fetch?sub={your_client_id}` 
- remember to (put `[` `]` around the Trust Mark when writing the appropriate file
- `iat` and `exp` claims must be issued according to the UTC timezone, this is an example command for the webapp: `mvn clean spring-boot:run -Dspring-boot.run.jvmArguments="-Duser.timezone=UTC"`