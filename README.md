# Integrate Keycloak as a Third Party Key Manager for WSO2 API Manager

This Keycloak key manager implementation allows you to integrate the WSO2 API Store with an external Keycloak Identity and Access Management server (IAM)
by using the Keycloak OAuth to manage the OAuth clients and tokens required
by WSO2 API Manager. We have a sample client implementation that consumes the admin REST APIs exposed by keycloak.

## Getting Started

To get started, go to [Integrate WSO2 API Store with an external IAM using the Keycloak Open Source IAM](docs/config.md).

## Build

Use the following command to build this implementation
`mvn clean install`

## How You Can Contribute

To contribute to the Okta key manager development, fork the github repository and send your pull requests to
[https://github.com/wso2-extensions/apim-keymanager-keycloak](https://github.com/wso2-extensions/apim-keymanager-keycloak)