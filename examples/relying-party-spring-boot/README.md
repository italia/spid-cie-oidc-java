# SpringBoot Relying Party example

This is a minimal, *ugly* and *unripe*, SpringBoot application implementing the following Relying Party aspects:
- well-known endpoint
- authentication flow
- logout flow


It's goal is to indentify SDK requirements and similarities or differences with the Django approach.
A real SpringBoot example is in the Roadmap.


To try it you need to have a running installation of [SPID CIE/OIDC Federation SDK, written in Python](https://github.com/italia/spid-cie-oidc-django).
The code is tested against v0.4.16.


You also need OpenJDK 11.


## H2 Database

The app use H2 to store needed informations. The database is named `oidc-rp` and is created as `$HOME/oidc-rp.mv.db`.
You have to manually remove it if you want to reset the environment.

Use "http://127.0.0.1:8080/h2-console" to access the database console:

- "JDBC URL" is "jdbc:h2:~/oidc-rp"
- "username" is "sa"
- "password" is "password"


## SETUP


### Step 1

Clone the repository and run the application

```bash
git clone -b 1-spring-boot-sample https://github.com/italia/spid-cie-oidc-java
cd spid-cie-oidc-java/examples/relying-party-spring-boot
./mvnw spring-boot:run
```

> Use CTRL-C to stop the application

Open a browser to "http://127.0.0.1:8080/home" to ensure the app is running.



### Step 2 - OnBoarding

Open a browser to "http://127.0.0.1:8080/oidc/rp/.well-known/openid-federation?format=json".

While an error apper in the browser, in the log you'll find a generated RSA JWK. You have to add it into `application.yaml` (like this)

```yaml
oidcfed:
   ....

   relying-party:
      ....
      jwk: |-
         {
           "p": "77cVKxU1PQeDES50YZoC5nWKJp-4NP78qqV--Rb3IonYZ8C2ssREq8OHchV-G6FTzDl17myonqd3StCxfaEAJhAucSXrGmw2BuPZJTQUSH1F2Lq8t1uoY_p7383Cv3UJ49FvjH0lIV49tQ9W3zHbE4K5RNYsz_fd-RvgHvId6p8",
           "kty": "RSA",
           "q": "ihFBGejrlrUqcmvpGC-VBM3Q3Bz3YJWFZs7ioeYFnCQQUhMk5d8ZqzgKphRdhwVJuwcfAgDg0is1w5EagLDJusk0CwavCPGTeDtG_eveqcYnGj8knB51jnpBpZr0F2FRDQyltg38llnAwkYUXdN9ikBq9jfcQTjV3CADNV54RlU",
           "d": "Vp-AGKPaon6F-rD7_wvjT3NVu1luZ8pm2syhQHbQ8OAoTnDkolnSOwyTc0Eeq6FebqVGkrs6w3c6snSrOzwpyNHCyzwgYrJtBY2CZybpzBuq6k7H9-Ipd2w8eei4EZhb1h1afYfDFnNsJC5r0Hv6hMJtCHmsH8Ccf74AVJ1ec0MnhmU9kZUBhUG9FbkNqXCEYyKc6wdzGPJm43vBQmDgksUHQpw685pHpJFNLgb76loG1GiU3u50rStztPtQkxmoELpDP6Jz6C_kjWT1POwqtSB1wFBSJLij7gmQb9bfDBGWS0oCdxDjGKKlSK0UapzBNTUHEqM7t2FLcM6wS12C6Q",
           "e": "AQAB",
           "use": "sig",
           "kid": "HuAVuC5SflpoyPU7agHX-4IpSTcODWnPMQKWojwIAx8",
           "qi": "xYb1ELEYOY_iZaXvGF53BHOD_WtEt5vSevsY-xGPTVsu4jsetksbucNfTjUhhI0BKbugKYlA7c7zHMQGFKEJirzbNYndhdJr-LCM8_AiOJbOo0KfO2vQ_LiqIOehxJVZ4Cz3_jFTMZMU41RNios5UUkmykFmWebB-qFDHbU-sh4",
           "dp": "2KCyH4n935YfSvKZN-6vOkb0Pu1N0Y6xFSGT-lRXp728dB6CvFCD4llD2MQ1f5CuIru2qG1HgIDEXDb2fxp1APDUl2n16Z3qwRU9EdLblZqn-TDgBC9voFInidvvZ4fEFT4aOXKKkHoS98HR9seePCaBeQS34IUV8t3PDwgsIu8",
           "alg": "RS256",
           "dq": "IDwZC_iSkHQpvd8t48SwMRfwbIOiyfz-0Vr6FLyEkMjmupLXqYemEZCbA917XJvCdBUcizYzRz5pZgiJvIQKBT8WlIBx-0-Tk52bXItmSBMIbBtT69M8tRAcJZMA7Dh_WOGcCt5HG79GvtTnymQnSlDx6BxwoxWm8KbUuPAeeqU",
           "n": "gUjZh2CmomUVNfBPSa8y2du1oAufoEDSSFLbG8TAmORDFUrPh_CupdUeHF858tAVdFLi0i5bZQ0H680gNcWr1SKoLV_NP8FoYrReE4nAFgu8YkGxmjWb0LeY0mwiXRtwOVPGQOCe8CDBmXc3lRmy070PHFf3VVNyJaof-aTBZUakK3B5m2-aMN1nShxLBDcBnnjgwgRA9dkmSNFP4yTQYIgGNzKVLhUa5el4-lyy8RZMHBarXPhRlu_fb45DWUsJWiu2WddJPFta7MlkEG6WFl3fQf9UbXP433j4Hzkt5V8BqbbTF6FcLHa2-D8SLjEj9NZs7CdEuxUyw8qR7p5gyw"
         }

      trust-marks: ""
```

Stop and restart the application

```bash
./mvnw clean spring-boot:run
```

Refresh "http://127.0.0.1:8080/oidc/rp/.well-known/openid-federation?format=json" page. Now you'll see more datas. In the log you'll find the public part of your JWK.

```json
[{
  "kty": "RSA",
  "e": "AQAB",
  "alg": "RS256",
  "use": "sig",
  "n": "gUjZh2CmomUVNfBPSa8y2du1oAufoEDSSFLbG8TAmORDFUrPh_CupdUeHF858tAVdFLi0i5bZQ0H680gNcWr1SKoLV_NP8FoYrReE4nAFgu8YkGxmjWb0LeY0mwiXRtwOVPGQOCe8CDBmXc3lRmy070PHFf3VVNyJaof-aTBZUakK3B5m2-aMN1nShxLBDcBnnjgwgRA9dkmSNFP4yTQYIgGNzKVLhUa5el4-lyy8RZMHBarXPhRlu_fb45DWUsJWiu2WddJPFta7MlkEG6WFl3fQf9UbXP433j4Hzkt5V8BqbbTF6FcLHa2-D8SLjEj9NZs7CdEuxUyw8qR7p5gyw",
  "kid": "HuAVuC5SflpoyPU7agHX-4IpSTcODWnPMQKWojwIAx8"
}]
```

You need it for the onboarding procedure.


Go to "http://127.0.0.1:8000/onboarding/landing" and click on "Register your Entity". In the form:
- "organization name" is free (ex: "Java RP")
- "url of the entity" is "http://127.0.0.1/oidc/rp/"
- "federation entity" is "openid_relying_party"
- "public jwks" is the json exposed in the spring app log

Confirm the form.


Go to "http://127.0.0.1:8000/admin". Choose "SPID/CIE OIDC FEDERATION ONBOARDING -> OnBoarding registrations"
- check your registration (ex: Java RP)
- choose "enable descendand" from Action drop-down and click "Go" (Vai).

Choose "SPID/CIE OIDC FEDERATION AUTHORITY -> Federation Entities Descendants" and edit your entity (ex: Java RP) and, at the end, add an email contact.

Choose ""SPID/CIE OIDC FEDERATION AUTHORITY -> Federation Descendants Assigned Profiles" and creare a new record
- "Descendant" is your entity registration (ex: Java RP)
- "Profile" is "SPID Public SP"
- "Issuer" is the current federation "http://127.0.0.1:8000"

Then:
- save
- edit the record
- copy the "Trust mark:" field.

Edit SpringBoot `application.yaml` to add the copied value as JSON Array (you have to manually add square brackets)

```yaml
      ....

      trust-marks: |-
         [
           {
             "id": "https://www.spid.gov.it/openid-federation/agreement/sp-public/",
             "trust_mark": "eyJhbGciOiJSUzI1NiIsImtpZCI6IkZpZll4MDNibm9zRDhtNmdZUUlmTkhOUDljTV9TYW05VGM1bkxsb0lJcmMiLCJ0eXAiOiJ0cnVzdC1tYXJrK2p3dCJ9.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDAvIiwic3ViIjoiaHR0cDovLzEyNy4wLjAuMTo4MDgwL29pZGMvcnAvIiwiaWF0IjoxNjQ4MDM3NDg2LCJpZCI6Imh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L2NlcnRpZmljYXRpb24vcnAiLCJtYXJrIjoiaHR0cHM6Ly93d3cuYWdpZC5nb3YuaXQvdGhlbWVzL2N1c3RvbS9hZ2lkL2xvZ28uc3ZnIiwicmVmIjoiaHR0cHM6Ly9kb2NzLml0YWxpYS5pdC9pdGFsaWEvc3BpZC9zcGlkLXJlZ29sZS10ZWNuaWNoZS1vaWRjL2l0L3N0YWJpbGUvaW5kZXguaHRtbCJ9.AbbSu62GLP2rxGuqYa2-FCr_Z2anPROT7dow1S5Xwfd_NCVfjVNt1_lMlp2hIhk4ACPaZZidWiUzEfnGecehQDSauaBY6RgLZdLaD9hpZ2E00_5HXCKO6yZHhfpbcHo_fKJpU6qhzhldVdMbAb59EAj1fs7WPVAzKoDS3JIpuoeYEMvBWV6YcBWekrfy7uQRsXKWtJ1rfl0kaHSnH38ivXp83q3qXxPgRZ_iMS8c0X2xC070i4fMZidG63bx-GuIkFsisZvZgqTO0GxdLdk_mI0dER7d8h7lE8q5jhYH14xzESTyFvGM6HLw5kKaAqPlnuj8QsbOzNIlx9SBteTGzQ"
           }
         ]
```


Stop and restart the application

```bash
./mvnw clean spring-boot:run
```

Go to "http://127.0.0.1:8080/oidc/rp/.well-known/openid-federation?format=json" page. Now you'll see the complete federation entity configuration for your Relying Party.
This action will also store the configuration inside `federation_entity_configuration` table.



## Authentication Flow

The starting point in "http://127.0.0.1:8080/oidc/rp/landing".


##

