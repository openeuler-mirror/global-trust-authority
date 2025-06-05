# GLOBAL TRUST AUTHORITY
## Product Introduction
A secure remote attestation service that enables hardware-verified trust between distributed systems. It validates the integrity of remote nodes (e.g., cloud instances) through cryptographic proofs, ensuring they run authentic software in a trusted state.

GTA is driven by a CLI program and a set of RESTful APIs.

GTA consists of four components: service, cli, agent, and key_manager.
* Service: Primarily used to continuously verify machines deployed with the agent, ensuring their integrity and trustworthiness.
* CLI: Used to manage input/output files or policy information required by the service.
* Agent: Deployed on machines that require attestation to collect IMA and TPM PCR data, establishing a trusted relationship with the service.
* Key_Manager: Utilizes third-party key management tools to store and provide cryptographic keys required by the service during verification.
## Table of Contents
* [Download](#download)
* [Build and Install](#build-and-install)
* [Documentation](#documentation)
## Download
You can obtain a local copy of the Git repository by cloning from the Gitee mirror:
```text
git clone https://gitee.com/openeuler/global-trust-authority.git
```
# build and Install
To install GTA refer to the [instruction found in the documentation](./docs/GTA_Usage_Guidelines.md). 
# Documentation
The current docs directory contains markdown files providing an overview of the project:
* [REST API Details](./docs/api_documentation.md)
* [Agent Module Introduction](./docs/attestation_agent.md)
  * [Agent Deployment Environment Guide](./docs/Challenge_Request_Challenge_Response_Environment_Preparation.md)
* [Command Module Introduction](./docs/attestation_common.md)
* [Service Module Introduction](./docs/attestation_service.md)
* [CLI Usage Guide](./docs/Complete_List_of_Management_Tool_Commands.md)
* [GTA Installation Guide](./docs/GTA_Usage_Guidelines.md)
* [Key Manager Installation Guide](./docs/key_manager_install.md)