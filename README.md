# Gatehouse

## Overview

Gatehouse is a lightweight HTTP reverse-proxy providing authentication for end users. Designed to be placed in front of your web applications, Gatehouse provides the core account functionality required for most websites. Features include:

- User Registration & Sign-in
- Email confirmations & Password Resets
- URI-based access control for unauthenticated users

Gatehouse stores user information in a MySQL compatible database and sends outgoing mail via an SNMP server. Below is an example of Gatehouse used in web infrastructure:

```
┌─────────────┐       ┌─────────────────┐       ┌──────────────────┐       ┌──────────────────┐
│   End User  │ HTTPS │ SSL Termination │ HTTP  │  Authentication  │ HTTP  │ Web Application  │
│ Web Browser ├───────►  HAProxy/NGINX  ├───────►    Gatehouse     ├───────► Spring/Flask/etc │
└─────────────┘       └─────────────────┘       └───────▲──────┬───┘       └──────────────────┘
                                                        │      │
                                                        │ SQL  └────────────────────┐ SMTP
                                                        │                           │
                                                ┌───────▼──────────┐       ┌────────▼─────────┐
                                                │    Database      │       │  Outgoing Mail   │
                                                │  MySQL/MariaDB   │       │     Postfix      │
                                                └──────────────────┘       └──────────────────┘
```

## Getting Started

There are some examples of Gatehouse deployments included in the `/examples` directory. These use a generic NGINX container as a web application, but this can be substituted for any other web application. MailDEV hosts a testing SMTP server inbox which can be viewed via port 1080 in a web browser.

### Docker Compose

```
cd /examples
docker-compose up --build
```

## Manual Setup

To deploy Gatehouse manually the following supporting infrastructure is required:

- MySQL compatible database
- SMTP server
- Web proxy for TLS termination

Gatehouse can be configured to use these through environment variables:

```
docker run -p 8080:8080 \
    -e MYSQL_HOST database.mynetwork.local \
    -e MYSQL_PORT 3306 \
    -e MYSQL_USER gatehouse \
    -e MYSQL_PASS UseGoodPasswords \
    -e SMTP_HOST outmail.mynetwork.local \
    -e SMTP_PORT 25 \
    papeben/gatehouse:latest
```

## Options and Parameters

Gatehouse is configured through environment variables. The names and default values of these are listed below:

| Environment Variable	| Purpose |
| ----------------------|--------------------------|
| BACKEND_SERVER	| The IP address of the backend server. Default value is 127.0.0.1. |
| BACKEND_PORT	| The port number of the backend server. Default value is 9000. |
| LISTEN_PORT	| The port number on which the server will listen. Default value is 8080. |
| GATEHOUSE_PATH |	The URI path used by Gatehouse features (e.g. /{path}/login). Default value is gatehouse. |
| APP_NAME	| The name of the application. Default value is Gatehouse. |
| MYSQL_HOST	| The IP address of the MySQL server. Default value is 127.0.0.1. |
| MYSQL_PORT	| The port number of the MySQL server. Default value is 3306. |
| MYSQL_USER	| The username for the MySQL database. Default value is gatehouse. |
| MYSQL_PASS	| The password for the MySQL user. Default value is password. |
| MYSQL_DATABASE |	The name of the MySQL database. Default value is gatehouse. |
| TABLE_PREFIX	| The prefix to be used for all tables in the MySQL database. Default value is gatehouse. |
| SESSION_COOKIE |	The name of the cookie used for session management. Default value is gatehouse-session. |
| REQUIRE_AUTH	| Whether authentication is required or not. Default value is TRUE. |
| REQUIRE_EMAIL_CONFIRM	| Whether email confirmation is required or not. Default value is TRUE. |
| SMTP_HOST	| The IP address of the SMTP server. Default value is 127.0.0.1. |
| SMTP_PORT	| The port number of the SMTP server. Default value is 25. |
| SMTP_USER	| The username for the SMTP server. Default value is an empty string. |
| SMTP_PASS	| The password for the SMTP server. Default value is an empty string. |
| SMTP_TLS	| Whether to use TLS encryption for SMTP or not. Default value is FALSE. |
| SMTP_TLS_SKIP_VERIFY	| Whether to skip verification of the server certificate for SMTP or not. Default value is FALSE. |
| MAIL_ADDRESS	| The sender email address to be used for all outgoing emails. Default value is gatehouse@mydomain.local. |
| WEB_DOMAIN	| The domain name of the web application. Default value is http://localhost:8080. |

## Roadmap

Gatehouse is still in prerelease development at the moment, but I have mapped out the features I plan to include in future releases.

### Initial Release v1.0.0

The initial release of Gatehouse will support:

- Username & Password Sign-in
- Account Registrations with Email
- Email account confirmation and password resets
- Email & App-based Multi-Factor Authentication
- URI path access control for unauthenticated users
- Customisable Form and Email templates
- Configuration via Environment Variables
- User-facing account dashboard

### Priority Additional Features

These are additional features I plan on adding to future releases:

- OpenID Connect Authentication with multiple configurable providers
- Identity JWTs
- CSRF Protection
- Account security alerts
- Account action rate limiting

### Stretch Features

Features which may be implemented in the future depending on demand:

- Alternative user stores (Postgres, LDAP)
- User administration portal