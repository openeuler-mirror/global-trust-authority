# HRA API Documentation

## Table of Contents
- [1. General Information](#1-general-information)
- [2. Agent API](#2-agent-api)
  - [2.1 Get Token](#21-get-token)
  - [2.2 Get Evidence](#22-get-evidence)
- [3. Service API](#3-service-api)
  - [3.1 Baseline Management](#31-baseline-management)
  - [3.2 Certificate Management](#32-certificate-management)
  - [3.3 Challenge Related](#33-challenge-related)
  - [3.4 Policy Management](#34-policy-management)
  - [3.5 Token Validation](#35-token-validation)

## 1. General Information

### 1.1 Request Headers
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| Content-Type | string | Yes | Content-Type header |
| Accept | string | Yes | Accept header |
| API-Key | string | No | For API authentication, mutually exclusive with User-Id |
| User-Id | string | No | User identifier, 36-character string (16-byte UUID) |
| User-Name | string | No | Username |
| Request-Id | string | No | Request ID |

## 2. Agent API

### 2.1 Get Token
**Description**: Get token

**Request Method**: `POST /get_token`

#### Request Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| attester_info | | list of object | No | Challenge information |
| | attester_type | string | No | Challenge type, defaults to traversing activated client plugins if not specified |
| | policy_ids | list of string | No | Applied policies, uses default policy if not specified |
| challenge | | bool | No | Whether to challenge, defaults to no challenge |
| attester_data | | object | No | User data, reserved field |

#### Response Parameters
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| message | string | No | Error message |
| token | object | Yes | Token object |

### 2.2 Get Evidence
**Description**: Provides encapsulated Evidence data

**Request Method**: `POST /get_evidence`

#### Request Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| attester_type | | list of string | No | Challenge type, defaults to traversing activated client plugins |
| nonce_type | | string | Yes | ignore/user/default (default value) corresponds to not verifying nonce, using user nonce, using verifier-generated nonce |
| user_nonce | | string | No | Filled when nonce_type is user |
| nonce | | object | No | Nonce value structure / required if nonce_type not filled |
| | iat | string | No | Issue time |
| | value | string | No | Nonce value |
| | signature | string | No | Signature value |
| attester_data | | object | No | User data, reserved field |

#### Response Parameters
| Field | Sub-field | Second-level Sub-field | Type | Required | Description |
|-------|-----------|------------------------|------|----------|-------------|
| agent_version | | | string | Yes | Client version number |
| nonce_type | | | string | No | ignore/user/default (default value) corresponds to not verifying nonce, using user nonce, using verifier-generated nonce |
| user_nonce | | | string | No | Filled when nonce_type is user |
| measurements | | | list of objects | Yes | Measurement data |
| | node_id | | string | No | Node ID, corresponds to ueid |
| | nonce | | object | No | Nonce object, see /challenge definition |
| | attester_data | | object | No | User-defined data to be passed through, must be placed in token as-is |
| | evidences | | list of objects | Yes | Challenge report |
| | | attester_type | string | Yes | Challenge type |
| | | evidence | list of objects | Yes | Specific evidence |

## 3. Service API

### 3.1 Baseline Management

#### 3.1.1 Add Baseline
**Description**: Add baseline

**Request Method**: `POST /refvalue`

##### Request Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| name | | string | Yes | Baseline name |
| description | | string | No | Baseline description |
| attester_type | | string | Yes | Applicable challenge plugin type |
| content | | string | Yes | Baseline content |
| signature | | object | Yes | Signature |
| | signAlg | string | Yes | Signature algorithm |
| | signature | string | Yes | Signature content |
| is_default | | boolean | No | Whether it's default baseline, defaults to false |

##### Response Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| message | | string | No | Error message |
| refvalue | | object | Yes | Baseline information |
| | id | string | No | Baseline ID |
| | name | string | Yes | Baseline name |
| | version | string | Yes | Baseline version number |

#### 3.1.2 Update Baseline
**Description**: Update baseline

**Request Method**: `PUT /refvalue`

##### Request Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| id | | string | No | Baseline ID |
| name | | string | No | Baseline name, directly overwrites when name is the same |
| description | | string | No | Baseline description |
| type | | string | Yes | Applicable challenge plugin type |
| content | | string | Yes | Baseline content |
| signature | | object | Yes | Signature |
| | signAlg | string | Yes | Signature algorithm |
| | signature | string | Yes | Signature content |
| is_default | | boolean | No | Whether it's default baseline, defaults to false |

##### Response Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| message | | string | No | Error message |
| refvalue | | object | Yes | Baseline information |
| | id | string | Yes | Baseline ID |
| | name | string | Yes | Baseline name |
| | version | string | Yes | Baseline update version number |

#### 3.1.3 Query Baseline
**Description**: Query baseline

**Request Method**: `GET /refvalue`

##### Request Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| type | | string | Yes | Query baseline for specified purpose |
| ids | | Array[string] | Yes | Baseline name, if empty, input 10 |

##### Response Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| message | | string | No | Error message |
| refvalue | | list of objects | Yes | Baseline information |
| | id | string | Yes | Baseline ID |
| | name | string | Yes | Baseline name |
| | description | string | No | Baseline description |
| | content | string | No | Baseline content |
| | attester_type | string | No | Applicable challenge plugin type |
| | is_default | boolean | No | Whether it's default baseline, defaults to false |
| | version | int | No | Baseline version |
| | create_time | Long | Yes | Creation time |
| | update_time | Long | Yes | Update time |

#### 3.1.4 Delete Baseline
**Description**: Delete baseline

**Request Method**: `DELETE /refvalue`

##### Request Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| ids | | List of String | Yes | Baseline IDs |
| attester_type | | string | No | Baseline type |

##### Response Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| message | | string | Yes | Error message |

### 3.2 Certificate Management

#### 3.2.1 Add Certificate
**Description**: Add certificate

**Request Method**: `POST /cert`

##### Request Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| name | | string | Yes | Certificate name |
| description | | string | No | Description |
| type | | string | Yes | Certificate type, supported enums: refvalue/policy/tpm_boot/tpm_ima/crl |
| content | | string | Yes | Certificate content |
| is_default | | boolean | No | Whether it's default certificate, defaults to false |
| cert_revoked_list | | array of string | No | Certificate revocation list |

##### Response Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| message | | string | No | Error message |
| certs | | object | No | Certificate |
| | cert_id | string | No | Certificate ID |
| | cert_name | string | No | Certificate name |
| | version | string | No | Certificate version number |
| cert_revoked_list | | array of string | | |
| | cert_id | string | No | Certificate ID |
| | cert_revoked_date | long | No | Certificate revocation time |
| | cert_revoked_reason | string | No | Certificate revocation reason |

#### 3.2.2 Update Certificate
**Description**: Update certificate

**Request Method**: `PUT /cert`

##### Request Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| id | | string | Yes | Certificate ID |
| name | | string | Yes | Certificate name |
| description | | string | No | Description |
| type | | string | Yes | Certificate type, range: {attester_type}, "policy", "refvalue" |
| content | | string | Yes | Certificate content |
| is_default | | boolean | No | Whether it's default certificate, defaults to false |

##### Response Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| message | | string | No | Error message |
| cert | | object | Yes | |
| | id | string | Yes | Certificate ID |
| | name | string | Yes | Certificate name |
| | version | string | Yes | Certificate update version number |

#### 3.2.3 Query Certificate
**Description**: Query certificate

**Request Method**: `GET /cert`

##### Request Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| type | | string | No | Query certificate for specified purpose |
| ids | | Array[string] | Yes | Certificate ID, maximum 10 |

##### Response Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| message | | string | No | Error message |
| total_size | | int | Yes | Total number of certificates |
| certs | | Array[object] | Yes | Certificate information |
| | cert_id | string | Yes | Certificate ID |
| | cert_name | string | Yes | Certificate name |
| | description | string | No | Certificate description |
| | content | string | No | Certificate content |
| | type | string | No | Certificate purpose |
| | is_default | boolean | No | Whether it's default certificate |
| | version | string | Yes | Certificate version |
| | create_time | long | No | Creation timestamp |
| | update_time | long | No | Update timestamp |
| | valid_code | int | No | 0-Normal; 1-Signature verification failed; 2-Revoked |
| | cert_revoked_date | long | No | Certificate revocation time, optional when type is crl |
| | cert_revoked_reason | string | No | Certificate revocation reason, optional when type is crl |

#### 3.2.4 Delete Certificate
**Description**: Delete certificate

**Request Method**: `DELETE /cert`

##### Request Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| delete_type | | string | Yes | Delete type "id""type""all" |
| ids | | Array[string] | No | Certificate ID list |
| type | | string | No | Certificate type, refvalue/policy/tpm_boot/tpm_ima/crl |

##### Response Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| message | | string | No | Error message |

### 3.3 Challenge Related

#### 3.3.1 Request Nonce
**Description**: Request nonce

**Request Method**: `POST /challenge`

##### Request Parameters
| Field | Type | Required | Description | Note |
|-------|------|----------|-------------|------|
| agent_version | string | Yes | Client version number | Format is x.x.x, e.g., 1.0.0 |
| attester_type | list of string | Yes | Plugin type, server returns error if not supported | Only supports "tpm_boot","tpm_ima" |

##### Response Parameters
| Field | Sub-field | Type | Required | Description | Note |
|-------|-----------|------|----------|-------------|------|
| service_version | | string | Yes | Server version | Format is x.x.x, e.g., 1.0.0 |
| message | | string | No | Error message | Maximum length 1024 bytes |
| nonce | | object | No | Nonce information | |
| | iat | long | Yes | Issue time | Maximum uint64 |
| | value | string | Yes | Nonce value | 64~1024BYTE, base64 encoded |
| | signature | string | Yes | Signature value | Not less than 64BYTE, default BASE64 encoding |

#### 3.3.2 Remote Attestation
**Description**: Report evidence for remote attestation

**Request Method**: `POST /attest`

##### Request Parameters
| Field | Sub-field | Second-level Sub-field | Type | Required | Description |
|-------|-----------|------------------------|------|----------|-------------|
| agent_version | | | string | Yes | Client version number |
| nonce_type | | | string | No | ignore/user/default (default value) corresponds to not verifying nonce, using user nonce, using verifier-generated nonce |
| user_nonce | | | string | No | Filled when nonce_type is user, 64~1024BYTE, base64 encoded |
| measurements | | | list of objects | Yes | Measurement data |
| | node_id | | string | No | Node ID, corresponds to uied, recommended 32~128 characters, based on actual device |
| | nonce | | object | No | Nonce object |
| | | iat | long | No | Issue time |
| | | value | string | Yes | Nonce value |
| | | signature | string | No | Signature value |
| | attester_data | | object | No | User-defined data to be passed through, must be placed in token as-is |
| | evidences | | list of objects | Yes | Challenge report |
| | | attester_type | string | Yes | Challenge type, see attester_type specification |
| | | evidence | object | Yes | Specific evidence |
| | | policy_ids | list of string | No | Policy ID list to verify, maximum 10 |

##### Response Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| service_version | | string | Yes | Server version number, format is x.x.x, e.g., 1.0.0 |
| message | | string | No | Error message, maximum 1024 characters |
| tokens | | list of objects | Yes, can be empty | |
| | node_id | string | No | Node ID, not corresponding to uied, recommended 32~128 characters, based on actual device |
| | token | string | Yes | JWT format object, see token structure |

##### Token Object Structure
| Field Location | Field | Sub-field | Second-level Sub-field | Type | Required | Description | Filled By |
|----------------|-------|-----------|------------------------|------|----------|-------------|-----------|
| header | alg | | | string | Yes | Token signature algorithm | Token generation module |
| header | jku | | | string | No | JSON Web Key Set URI. URL containing JSON-encoded public token signing keys identified by kid. Retrieved based on configuration | Token generation module |
| header | kid | | | string | No | Signature key ID, retrieved based on configuration | Token generation module |
| header | typ | | | string | Yes | Token type, fixed as JWT | Token generation module |
| body | iat | | | number | Yes | Issue time | Token generation module |
| body | exp | | | number | Yes | Expiration time | Token generation module |
| body | iss | | | string | No | Issuer | Token generation module |
| body | jti | | | string | Yes | JWT identifier | Token generation module |
| body | ver | | | string | Yes | Token version | Token generation module |
| body | nbf | | | string | No | Not before time | Token generation module |
| body | eat_profile | | | string | Yes | URL, EAT content description website, defaults to code repository | Token generation module |
| body | intuse | | | string | No | Expected usage | Challenge response module |
| body | dbgstat | | | object | No | Debug status | Challenge response module |
| body | ueid | | | string | No | Device unique identifier (taken from certificate) | Challenge response module |
| body | verifier_id | | | string | No | Verifier ID (consider container ID?) | Challenge response module |
| body | status | | | string | Yes | Overall verification status, pass/fail | Challenge response module |
| body | eat_nonce | | | string | No | Nonce value, not filled for user_nonce and ignore_nonce | Challenge response module |
| body | attester_data | | | object | No | User-defined information | Challenge response module |
| body | ${attester_type} | | | object | Yes | Verification result corresponding to attester_type | Challenge response module |
| | | attestation_status | | string | Yes | Verification status corresponding to attester_type, pass/fail | Challenge response module |
| | | raw_evidence flattened fields | | object | No | Evidence uploaded by attester, e.g., pcr value; generated according to default policy | Challenge response module |
| | | policy_info | | list of object | Yes | Policy information | Challenge response module |
| | | | appraisal_policy_id | string | Yes | Applied policy ID | Challenge response module |
| | | | policy_version | string | Yes | Policy version | Challenge response module |
| | | | attestation_valid | boolean | Yes | Whether policy matching passed | Challenge response module |
| | | | custom_data | object | No | Policy-defined output | Challenge response module |

### 3.4 Policy Management

#### 3.4.1 Add Policy
**Description**: Add policy

**Request Method**: `POST /policy`

##### Request Parameters
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| id | string | No | Policy ID, length 1~36 characters, if filled, use it as policy ID, if not filled, generate UUID |
| name | string | Yes | Policy name, length 1~256 characters |
| description | string | No | Policy description, length not exceeding 512 characters |
| attester_type | string | Yes | Applicable challenge plugin type, see previous specification |
| content_type | string | Yes | jwt/text (corresponding to unsigned case) |
| content | string | Yes | Policy content, maximum 500KB before encoding |
| is_default | boolean | No | Whether it's default policy, defaults to false |

When content_type is jwt, jwt content:
| Field Location | Field | Sub-field | Second-level Sub-field | Type | Required | Description |
|----------------|-------|-----------|------------------------|------|----------|-------------|
| header | alg | | | string | Yes | Token signature algorithm |
| header | kid | | | string | No | Public key ID |
| body | policy | | | string | Yes | Policy content |

##### Response Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| message | | string | No | Error message |
| policy | | object | No | Policy information |
| | id | string | Yes | Policy ID, UUID, 16byte, 36 characters with hyphen |
| | name | string | Yes | Policy name |
| | version | u32 | Yes | Policy version, created as 1, increments by 1 on update |

#### 3.4.2 Update Policy
**Description**: Update policy

**Request Method**: `PUT /policy`

##### Request Parameters
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| id | string | Yes | Policy ID |
| name | string | No | Policy name |
| description | string | No | Policy description |
| attester_type | list of string | No | Applicable challenge plugin type |
| content_type | string | No | jwt/text (corresponding to unsigned case) |
| content | string | No | Policy content |
| is_default | boolean | No | Whether it's default policy, defaults to false |

##### Response Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| message | | string | No | Error message |
| policies | | string | No | Policy information |
| | id | string | Yes | Policy ID |
| | name | string | Yes | Policy name |
| | version | u32 | Yes | Policy version |

#### 3.4.3 Delete Policy
**Description**: Delete policy

**Request Method**: `DELETE /policy`

##### Request Parameters
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| delete_type | string | Yes | Delete type "id""attester_type""all" |
| ids | List of String | No | Policy IDs, maximum 10 |
| attester_type | string | No | Policy type |

##### Response Parameters
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| message | string | No | Error message |

#### 3.4.4 Query Policy
**Description**: Query policy

**Request Method**: `GET /policy`

##### Request Parameters
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| ids | List of String | No | Policy IDs maximum 10, error if exceeding maximum message limit |
| type | string | No | Policy type |

##### Response Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| message | | string | No | Error message |
| policies | | list of objects | Yes | Policy information |
| | id | string | Yes | Policy ID |
| | name | string | Yes | Policy name |
| | description | string | No | Policy description |
| | content | string | No | Policy content |
| | attester_type | list of string | No | Applicable challenge plugin type |
| | is_default | boolean | No | Whether it's default policy, defaults to false |
| | valide_code | u8 | No | Signature verification result, 0-pass, 1-fail |
| | version | u64 | No | Policy version |
| | update_time | u64 | Yes | Creation time |

> Note: When querying with ids, returns all fields of entries filtered by id; without ids, only returns required fields like id, name, version, etc., does not return specific content (entries filtered by type, if type not filled returns all for that user)

### 3.5 Token Validation

#### 3.5.1 Validate Token
**Description**: Validate Token

**Request Method**: `POST /validate-token`

##### Request Parameters
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| token | string | Yes | Token to be validated and parsed |

##### Response Parameters
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| verification_pass | boolean | Yes | Whether signature verification passed |
| token_body | object | No | Required when verification passes, returns parsed token body |
| token_header | object | No | Required when verification passes, returns parsed token header |

> Note:
> 1. When querying with ids, returns all fields of entries filtered by id
> 2. Without ids, only returns required fields like id, name, version, etc., does not return specific content (entries filtered by type, returns all for that user if type not filled)