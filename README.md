# Gatehouse
![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/papeben/gatehouse/test-go.yml)
![Language](https://img.shields.io/github/languages/top/papeben/gatehouse)
[![Go Report](https://goreportcard.com/badge/github.com/papeben/gatehouse)](https://goreportcard.com/report/github.com/papeben/gatehouse)
[![Go Coverage](https://github.com/papeben/gatehouse/wiki/coverage.svg)](https://raw.githack.com/wiki/papeben/gatehouse/coverage.html)

A drop-in authentication and account management solution for websites.

## Overview

Gatehouse is a lightweight HTTP reverse-proxy providing authentication for end users. Designed to be placed in front of your web applications, Gatehouse provides the core account functionality required for most websites.

Gatehouse proxies HTTP requests depending on whether a user is authenticated or not. Depending on configuration, unauthenticated users will be shown a login page where they can authenticate or register before being granted access to the backend web application. This authentication process can be configured to enable:

- User Registration & Sign-in
- Email Confirmations
- Email Password Resets
- Email and App-based Multi-Factor authentication
- URI-based access control for unauthenticated users

## Architecture

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

- A HTTP web application to protect
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
    -e BACKEND_SERVER web.mynetwork.local \
    -e BACKEND_PORT 80 \
    papeben/gatehouse:latest
```

## Options and Parameters

Gatehouse is configured through environment variables. The names and default values of these are listed below:

| Environment Variable	| Default | Purpose |
| ----------------------|---------|---------|
| BACKEND_SERVER	| 127.0.0.1 | The IP address or DNS name of the backend server. |
| BACKEND_PORT	| 9000 | The port number of the backend server. |
| LISTEN_PORT	| 8080 | The port number on which the server will listen. |
| GATEHOUSE_PATH |	gatehouse | The URI path used by Gatehouse features (e.g. /{path}/login). |
| APP_NAME	| Gatehouse | The name of the application used in emails and webpages. |
| MYSQL_HOST	| 127.0.0.1 | The IP address or DNS name of the MySQL server. |
| MYSQL_PORT	| 3306 | The port number of the MySQL server. |
| MYSQL_USER	| gatehouse | The username for the MySQL database. |
| MYSQL_PASS	| password | The password for the MySQL user. |
| MYSQL_DATABASE | gatehouse | The name of the MySQL database. |
| TABLE_PREFIX	| gatehouse | The prefix to be used for all tables in the MySQL database. |
| SESSION_COOKIE |	gatehouse-session | The name of the cookie used for session management. |
| REQUIRE_AUTH	| TRUE | Whether authentication is required or not. |
| REQUIRE_EMAIL_CONFIRM	| TRUE | Whether email confirmation is required or not. |
| SMTP_HOST	| 127.0.0.1 | The IP address or DNS name of the SMTP server. |
| SMTP_PORT	| 25 | The port number of the SMTP server. |
| SMTP_USER	| *unset* | The username for the SMTP server. |
| SMTP_PASS	| *unset* | The password for the SMTP server. |
| SMTP_TLS	| FALSE | Whether to use TLS encryption for SMTP or not. |
| SMTP_TLS_SKIP_VERIFY	| FALSE | Whether to skip verification of the server certificate for SMTP or not. |
| MAIL_ADDRESS	| gatehouse@mydomain.local | The sender email address to be used for all outgoing emails. |
| WEB_DOMAIN	| http://localhost:8080 | The full domain URL of the web application. |
| LOG_LEVEL | 4 | Log verbosity level (0 Fatal, 1 Crit, 2 Error, 3 Warn, 4 Info, 5 Debug) |
| ALLOW_REGISTRATION | TRUE | Allow registration for unauthenticated users |
| ALLOW_USERNAME_LOGIN | TRUE | Allow users to sign in with usernames and passwords |
| ALLOW_PASSWORD_RESET | TRUE | Allow users to reset their passwords | 
| ALLOW_MOBILE_MFA | TRUE | Allow users to use mobile MFA token devices | 
| ALLOW_USERNAME_CHANGES | TRUE | Allow users to change their username |
| ALLOW_EMAIL_CHANGES | TRUE | Allow users to change their email |
| ALLOW_DELETE_ACCOUNT | TRUE | Allow users to delete their account |

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