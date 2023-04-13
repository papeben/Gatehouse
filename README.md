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

### Kubernetes

```
cd /examples
kubectl create namespace gatehouse
kubectl create -f gatehouse_demo.yml
```

## Options and Parameters

## Features

## Roadmap