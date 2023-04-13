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
                                                        │ SQL  └────────────────────┐ SNMP
                                                        │                           │
                                                ┌───────▼──────────┐       ┌────────▼─────────┐
                                                │    Database      │       │  Outgoing Mail   │
                                                │  MySQL/MariaDB   │       │     Postfix      │
                                                └──────────────────┘       └──────────────────┘
```

## Getting Started

## Options and Parameters

## Features

## Roadmap