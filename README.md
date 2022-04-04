# SPID/CIE OIDC Federation, for Java

[![Get invited](https://slack.developers.italia.it/badge.svg)](https://slack.developers.italia.it/)
[![Join the #spid openid](https://img.shields.io/badge/Slack%20channel-%23spid%20openid-blue.svg)](https://developersitalia.slack.com/archives/C7E85ED1N/)
[![CodeQL](https://github.com/italia/spid-cie-oidc-java/actions/workflows/codeql.yml/badge.svg)](https://github.com/italia/spid-cie-oidc-java/actions/workflows/codeql.yml)

**SPID/CIE OIDC Federation** is a **starter kit** and **example projects** designed to ease the creation of an OpenID Connect Federation.

> ⚠️ This project is a work-in-progress. Currently only the **Relying Party** has been completed.
>
> 👀 Watch this repository over GitHub to stay informed.

| Starter Kit sections                                   | Status                        |
| ------------------------------------------------------ | ----------------------------- |
| **OpenID Connect Federation**                          | ![In roadmap][status-roadmap] |
| **OpenID Connect Identity Provider**                   | ![In roadmap][status-roadmap] |
| **OpenID Connect Relying Party**                       | ![Ready][status-ready]        |

![preview](preview.gif)


## Packages

### SPID/CIE OIDC Federation Starter Kit

A java library that exposes utilities, _helpers_ and _handlers_ you can include into your application in order
to support the SPID/CIE OpenID Connect Authentication profile and OpenID Federation 1.0.

The library is developed using Java 11 with a "Low Level Java" approach to limit dependencies and allowing it to
be included into projects mades with high-level framework like Spring, SpringBoot, OSGi, Quarkus and many others java based frameworks.


## Example projects

### [SpringBoot Relying Party example](examples/relying-party-spring-boot)

A simple SpringBoot web application using the starter-kit to implement a Relying Party.

This application is for demo purpose only, please don't use it in production or critical environment.


## Useful links

* [Openid Connect Federation](https://openid.net/specs/openid-connect-federation-1_0.html)
* [SPID/CIE OIDC Federation SDK](https://github.com/italia/spid-cie-oidc-django)


## Contribute

Your contribution is welcome, no question is useless and no answer is obvious, we need you.

#### Contribute as end user

Please open an issue if you've discoverd a bug or if you want to ask some features.

### About this implementation

TODO: few notes about the profiles supported and how they was implemented.


## License and Authors

This software is released under the Apache 2 License by:

- Mauro Mariuzzo <mauro.mariuzzo@smc.it>.

[status-roadmap]: https://img.shields.io/badge/status-in%20roadmap-inactive
[status-ready]: https://img.shields.io/badge/status-ready-success
