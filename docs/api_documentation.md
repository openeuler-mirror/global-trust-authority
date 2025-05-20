# API Documentation

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
| Accept | string | No | Accept header |
| API-Key | string | No | For API authentication, mutually exclusive with User-Id |
| User-Id | string | Yes | User identifier, 36-character string (16-byte UUID) |
| User-Name | string | No | Username |
| Request-Id | string | No | Request ID |

## 2. Agent API

### 2.1 Get Token
**Description**: Get token

**Request Method**: `POST /global-trust-authority/agent/v1/tokens`

#### Request Parameters
| Field | Sub-field | Type | Required | parameter constraint | Description |
|-------|-----------|------|----------|-------------|-------------|
| attester_info | | list of object | No |  | Challenge information |
| | attester_type | string | No |  | Challenge type, defaults to traversing activated client plugins if not specified |
| | policy_ids | list of string | No |  | Applied policies, uses default policy if not specified |
| challenge | | bool | No |  | Whether to challenge, defaults to no challenge |
| attester_data | | object | No |  | User data, reserved field |

#### Response Parameters
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| message | string | No | Error message |
| token | object | Yes | Token object |

### 2.2 Get Evidence
**Description**: Provides encapsulated Evidence data

**Request Method**: `POST /global-trust-authority/agent/v1/evidences`

#### Request Parameters
| Field | Sub-field | Type | Required | parameter constraint | Description |
|-------|-----------|------|----------|-------------|-------------|
| attester_type | | list of string | No |  | Challenge type, defaults to traversing activated client plugins |
| nonce_type | | string | Yes |  | ignore/user/default (default value) corresponds to not verifying nonce, using user nonce, using verifier-generated nonce |
| user_nonce | | string | No |  | Filled when nonce_type is user |
| nonce | | object | No |  | Nonce value structure / required if nonce_type not filled |
| | iat | string | No |  | Issue time |
| | value | string | No |  | Nonce value |
| | signature | string | No |  | Signature value |
| attester_data | | object | No |  | User data, reserved field |

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

**Request Method**: `POST /global-trust-authority/v1/service/refvalue`

##### Request Parameters
| Field | Sub-field | Type | Required | parameter constraint | Description |
|-------|-----------|------|----------|-------------|-------------|
| name | | string | Yes | Length 1-255 characters | Baseline name |
| description | | string | No | Length 0-512 characters | Baseline description |
| attester_type | | string | Yes | tpm_ima character | Applicable challenge plugin type |
| content | | string | Yes | Maximum length 10M | Baseline content |
| is_default | | boolean | No | true or false | Whether it's default baseline, defaults to false |

##### Response Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| message | | string | No | Error message |
| refvalue | | object | Yes | Baseline information |
| | id | string | No | Baseline ID |
| | name | string | Yes | Baseline name |
| | version | string | Yes | Baseline version number |

##### Example of request

###### request body

```
{
    "name": "syyx",
    "description": "test",
    "attester_type": "tpm_ima",
    "is_default":true,
    "content": "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJyZWZlcmVuY2VWYWx1ZXMiOlt7ImZpbGVOYW1lIjoic3l5eC0xLlBBVCIsInNoYTI1NiI6IjEyMzQ1NiJ9XX0.W15mJKFmdMA7FS_yDgC9-EGSxqwyDSEf5TyEkMRasYtJ_zjlMqsz57zpsPdPc384mX9_J6ITpSJKpk454fb7wWbdoi4S5g-3kaCW9WgaDDHiTDr7wbx9CN0e80UotI4vXGA7p0rEV8rExAtxehBP2QjOk9Dp39LKcO6iR5OWlStYevKNUHVVpfpidUiX14tm8lG4uGYOpnyVqoKBjpSS7-fkin5qacYo4XoFNFNwMFxtM57Cv2l-_6ky4n4wNpufJoH8FeE3uao-DX-v37o-DClkNPnP4Sj51Vsdnyx79FIEevnkPXYCizPxdiiN7LS068-EkVkenGv2TFigG8ySi_4FwiVxbHDf8lKjV6nunblgH8jK3uqxZkUwYMDmeej5dsk3624TRUxK-29d1KGnpB6ax-lGKqcqzYkJOa7CykmZyOJgo8aTj19qlC2MY_xN7iY-ZP1uvXvzvNF01UoOWIBmVsj0UH_moI-2huFu-k7PPmy661cwskKpycH3o813s7jEW-dTFtiht7iq1kDwIB5iMJWq-kxjAfwf8ICOUhimM2hoYPgCUxAlPguNnN26o2NWGKAdXhZdipARqyrZU5PwJU-iJwMernOKE1qtBpi-UKb5F9YbJ2EkRZTrUKW1hs9iMaPCauZWYJM1PXh3uPG98a7CbFGIwYql6B7pN6M"
}
```

###### response body

 ```
 {
     "id": "2b0ead4b-6a15-4239-bf68-b1413df538bb",
     "name": "syyx",
     "version": 1
 }
 ```



#### 3.1.2 Update Baseline

**Description**: Update baseline

**Request Method**: `PUT /global-trust-authority/v1/service/refvalue`

##### Request Parameters
| Field | Sub-field | Type | Required | parameter constraint | Description |
|-------|-----------|------|----------|-------------|-------------|
| id | | string | Yes | Length 1-32 characters | Baseline ID |
| name | | string | No | Length 1-255 characters | Baseline name, directly overwrites when name is the same |
| description | | string | No | Length 0-512 characters | Baseline description |
| content | | string | No | Maximum length 10M | Baseline content |
| is_default | | boolean | No | true or false | Whether it's default baseline, defaults to false |

##### Response Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| message | | string | No | Error message |
| refvalue | | object | Yes | Baseline information |
| | id | string | Yes | Baseline ID |
| | name | string | Yes | Baseline name |
| | version | string | Yes | Baseline update version number |

##### Example of request

###### request body

```
{
    "id": "2b0ead4b-6a15-4239-bf68-b1413df538bb",
    "name": "syyx",
    "description": "test",
    "is_default":true,
    "content": "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJyZWZlcmVuY2VWYWx1ZXMiOlt7ImZpbGVOYW1lIjoic3l5eC0xLlBBVCIsInNoYTI1NiI6IjEyMzQ1NiJ9XX0.W15mJKFmdMA7FS_yDgC9-EGSxqwyDSEf5TyEkMRasYtJ_zjlMqsz57zpsPdPc384mX9_J6ITpSJKpk454fb7wWbdoi4S5g-3kaCW9WgaDDHiTDr7wbx9CN0e80UotI4vXGA7p0rEV8rExAtxehBP2QjOk9Dp39LKcO6iR5OWlStYevKNUHVVpfpidUiX14tm8lG4uGYOpnyVqoKBjpSS7-fkin5qacYo4XoFNFNwMFxtM57Cv2l-_6ky4n4wNpufJoH8FeE3uao-DX-v37o-DClkNPnP4Sj51Vsdnyx79FIEevnkPXYCizPxdiiN7LS068-EkVkenGv2TFigG8ySi_4FwiVxbHDf8lKjV6nunblgH8jK3uqxZkUwYMDmeej5dsk3624TRUxK-29d1KGnpB6ax-lGKqcqzYkJOa7CykmZyOJgo8aTj19qlC2MY_xN7iY-ZP1uvXvzvNF01UoOWIBmVsj0UH_moI-2huFu-k7PPmy661cwskKpycH3o813s7jEW-dTFtiht7iq1kDwIB5iMJWq-kxjAfwf8ICOUhimM2hoYPgCUxAlPguNnN26o2NWGKAdXhZdipARqyrZU5PwJU-iJwMernOKE1qtBpi-UKb5F9YbJ2EkRZTrUKW1hs9iMaPCauZWYJM1PXh3uPG98a7CbFGIwYql6B7pN6M"
}
```

###### response body

 ```
{
    "id": "2b0ead4b-6a15-4239-bf68-b1413df538bb",
    "name": "syyx",
    "version": 2
}
 ```

#### 3.1.3 Query Baseline

**Description**: Query baseline

**Request Method**: `GET /global-trust-authority/v1/service/refvalue`

##### Request Parameters
| Field | Sub-field | Type | Required | parameter constraint | Description |
|-------|-----------|------|----------|-------------|-------------|
| type | | string | Yes | tpm_ima | Query baseline for specified purpose |
| ids | | Array[string] | Yes | Length 1-32 characters | Baseline name, if empty, input 10 |

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

##### Example of request

###### request url

```
http://10.10.0.102:8080/global-trust-authority/v1/service/refvalue?ids=2b0ead4b-6a15-4239-bf68-b1413df538bb
```

###### response body

 ```
{
    "refvalue": [
        {
            "id": "2b0ead4b-6a15-4239-bf68-b1413df538bb",
            "name": "syyx",
            "description": "This is Test",
            "content": "package verification\n\n# Extract is_log_valid from first tpm_ima log\nis_log_valid = valid {\n    some i\n    logs := input.evidence.logs\n    logs[i].log_type == \"ImaLog\"\n    valid := logs[i].is_log_valid\n}\n\n# Check if pcrs 10 is present in any hash algorithm (sha1, sha256, sha384, sha512)\npcr_present {\n    all := {x | x := [10][_] }\n    measured := {pcr.pcr_index | pcr := input.evidence.pcrs.pcr_values[_]}\n    all_pcrs_subset := all - measured\n    count(all_pcrs_subset) == 0\n}\n\n# Attestation valid if all conditions met\ndefault attestation_valid = false\nattestation_valid {\n    is_log_valid == true\n    pcr_present\n}\n\n# Output result\nresult = {\n    \"policy_matched\": attestation_valid,\n    \"custom_data\": {\n        \"hash_alg\": input.evidence.pcrs.hash_alg\n    }\n}",
            "attester_type": [
                "tpm_ima"
            ],
            "is_default": true,
            "version": 1,
            "update_time": 1747640682,
            "valid_code": 0
        }
    ]
}
 ```

#### 3.1.4 Delete Baseline

**Description**: Delete baseline

**Request Method**: `DELETE /global-trust-authority/service/v1/refvalue`

##### Request Parameters
| Field | Sub-field | Type | Required | parameter constraint | Description |
|-------|-----------|------|----------|-------------|-------|
| ids | | List of String | No | Length 1-32 characters | Baseline IDs |
| attester_type | | string | No | tpm_ima | Baseline type |
| delete_type | | string | Yes | id, type, all | Delete Type |

##### Response Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| message | | string | Yes | Error message |

### 3.2 Certificate Management

#### 3.2.1 Add Certificate
**Description**: Add certificate

**Request Method**: `POST /global-trust-authority/v1/service/cert`

##### Request Parameters
| Field | Sub-field | Type | Required | parameter constraint | Description |
|-------|-----------|------|----------|-------------|-------------|
| name | | string | Yes | Length 1-255 characters | Certificate name |
| description | | string | No | Length 0-512 characters | Description |
| type | | string | Yes | refvalue/policy/tpm_boot/tpm_ima/crl | Certificate type, supported enums: refvalue/policy/tpm_boot/tpm_ima/crl |
| content | | string | Yes |  | Certificate content |
| is_default | | boolean | No | true false | Whether it's default certificate, defaults to false |
| cert_revoked_list | | array of string | No |  | Certificate revocation list |

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

##### Example of request

###### request body

```
{
	"name": "root.crt.refvalue",
	"description": null,
	"type": ["tpm_ima", "tpm_boot"],
	"content": "-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUa2Y3bA0XAm4XLafe/q8+KC3aokIwDQYJKoZIhvcNAQELBQAwRDELMAkGA1UEBhMCQ04xEDAOBgNVBAoMB3Rlc3QgQ0ExDTALBgNVBAsMBHRlc3QxFDASBgNVBAMMC1RQTSBSb290IENBMCAXDTI1MDQyODA5MjEwOVoYDzIwNTUwNDIxMDkyMTA5WjBEMQswCQYDVQQGEwJDTjEQMA4GA1UECgwHdGVzdCBDQTENMAsGA1UECwwEdGVzdDEUMBIGA1UEAwwLVFBNIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAOdXbxpdveE7eBkjX7NEoiE1rosffByMdMGC4kT+LDYU8tO93TFYJpCBVT1JpubU5zEFCilER39z5DA+y5w/dRaZrpTkXWCD8RcGEB+wVzuJIsl2kafH+lgui374zVWB9pePbLfOHkv09OpPsNjF/rO1OlHEEuGSe1LD+GLuSblIzGoX97ODWl1TacZlot8LnzqidhXUwLgmXgYLr/VApXFHyUhZ7ipSQcQng3/Morek0bTQPPGUPd308G7Fotw2wp9Io2NLPxuZLGqeraH+hV22ayPaVWSOXfOD/mezt935NqVHgEHOJOIIMnDeT8JD+n/cHLSZM9Br6F8JwevUHAgMBAAGjUzBRMB0GA1UdDgQWBBTo4w19Mkg5ynJdPlllemXnRXZ+ijAfBgNVHSMEGDAWgBTo4w19Mkg5ynJdPlllemXnRXZ+ijAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQA09kjseBelT6x71ST6XAr7GIQjkxlTedQydTuY3sgWDLvCGW3rRHjuRDPRb+0c22DEVg8BvCsFbS7jexnscMFQz4llxCDpns2yPs9afIfxFolAizdaxwBaOkwNAIRUWbI9ZwTIHezaitreJDTWWZdVWTBHQMNQ6aAH9yOl/iWXXFyVcMIl5S4iVrOqH5sk+zl3BFkq4WPB6FbGKRVBJ4e9UlWKWflMrk7D6HmG93E7ZO4Vlen+HbnOvnOsIkaa/6rOqmgXhi1g1QTOZazSp7xHx1lOq0JYH9g1tSmTDBWg57ZZWOAUwusw2OSrG4k8GXhxNQDRJyDSNNd7AjTIvOYV\n-----END CERTIFICATE-----",
	"is_default": null,
	"cert_revoked_list": null
}
```

###### response body

 ```
{
    "cert": {
        "cert_id": "4740ac7fb9c659e5a1cafad301e1ed00",
        "cert_name": "root.crt.refvalue",
        "version": 1
    }
}
 ```

#### 3.2.2 Update Certificate

**Description**: Update certificate

**Request Method**: `PUT /global-trust-authority/v1/service/cert`

##### Request Parameters
| Field | Type | Required | parameter constraint | Description |
|-------|------|----------|-------------|-------------|
| id | string | Yes | Length 1-32 characters | Certificate ID |
| name | string | No | Length 1-255 characters | Certificate name |
| description | string | No | Length 0-512 characters | Description |
| type | string | Yes | refvalue/policy/tpm_boot/tpm_ima/crl | Certificate type, range: {attester_type}, "policy", "refvalue" |
| is_default | boolean | No | true or false | Whether it's default certificate, defaults to false |

##### Response Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| message | | string | No | Error message |
| cert | | object | Yes | |
| | id | string | Yes | Certificate ID |
| | name | string | Yes | Certificate name |
| | version | string | Yes | Certificate update version number |

##### Example of request

###### request body

```
{
	"name": "root.crt.refvalue",
	"description": null,
	"type": ["tpm_ima", "tpm_boot"],
	"is_default": true,
	"cert_revoked_list": null
}
```

###### response body

 ```
{
    "cert": {
        "cert_id": "4740ac7fb9c659e5a1cafad301e1ed00",
        "cert_name": "root.crt.refvalue",
        "version": 2
    }
}
 ```

#### 3.2.3 Query Certificate

**Description**: Query certificate

**Request Method**: `GET /global-trust-authority/v1/service/cert`

##### Request Parameters
| Field | Sub-field | Type | Required | parameter constraint | Description |
|-------|-----------|------|----------|-------------|-------------|
| type | | string | No | refvalue/policy/tpm_boot/tpm_ima/crl | Query certificate for specified purpose |
| ids | | Array[string] | No |  | Certificate ID, maximum 10 |

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

##### Example of request

###### request url

```
http://10.10.0.102:8080/global-trust-authority/v1/service/cert?ids=4740ac7fb9c659e5a1cafad301e1ed00
```

###### response body

 ```
{
  "certs": [
    {
      "cert_id": "4740ac7fb9c659e5a1cafad301e1ed00",
      "cert_name": "root.crt.refvalue",
      "content": "-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUa2Y3bA0XAm4XLafe/q8+KC3aokIwDQYJKoZIhvcNAQELBQAwRDELMAkGA1UEBhMCQ04xEDAOBgNVBAoMB3Rlc3QgQ0ExDTALBgNVBAsMBHRlc3QxFDASBgNVBAMMC1RQTSBSb290IENBMCAXDTI1MDQyODA5MjEwOVoYDzIwNTUwNDIxMDkyMTA5WjBEMQswCQYDVQQGEwJDTjEQMA4GA1UECgwHdGVzdCBDQTENMAsGA1UECwwEdGVzdDEUMBIGA1UEAwwLVFBNIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAOdXbxpdveE7eBkjX7NEoiE1rosffByMdMGC4kT+LDYU8tO93TFYJpCBVT1JpubU5zEFCilER39z5DA+y5w/dRaZrpTkXWCD8RcGEB+wVzuJIsl2kafH+lgui374zVWB9pePbLfOHkv09OpPsNjF/rO1OlHEEuGSe1LD+GLuSblIzGoX97ODWl1TacZlot8LnzqidhXUwLgmXgYLr/VApXFHyUhZ7ipSQcQng3/Morek0bTQPPGUPd308G7Fotw2wp9Io2NLPxuZLGqeraH+hV22ayPaVWSOXfOD/mezt935NqVHgEHOJOIIMnDeT8JD+n/cHLSZM9Br6F8JwevUHAgMBAAGjUzBRMB0GA1UdDgQWBBTo4w19Mkg5ynJdPlllemXnRXZ+ijAfBgNVHSMEGDAWgBTo4w19Mkg5ynJdPlllemXnRXZ+ijAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQA09kjseBelT6x71ST6XAr7GIQjkxlTedQydTuY3sgWDLvCGW3rRHjuRDPRb+0c22DEVg8BvCsFbS7jexnscMFQz4llxCDpns2yPs9afIfxFolAizdaxwBaOkwNAIRUWbI9ZwTIHezaitreJDTWWZdVWTBHQMNQ6aAH9yOl/iWXXFyVcMIl5S4iVrOqH5sk+zl3BFkq4WPB6FbGKRVBJ4e9UlWKWflMrk7D6HmG93E7ZO4Vlen+HbnOvnOsIkaa/6rOqmgXhi1g1QTOZazSp7xHx1lOq0JYH9g1tSmTDBWg57ZZWOAUwusw2OSrG4k8GXhxNQDRJyDSNNd7AjTIvOYV\n-----END CERTIFICATE-----",
      "cert_type": [
        "tpm_ima",
        "tpm_boot"
      ],
      "version": 1,
      "create_time": 1747643045307,
      "update_time": 1747643045307,
      "valid_code": 0
    }
  ]
}
 ```

#### 3.2.4 Delete Certificate

**Description**: Delete certificate

**Request Method**: `DELETE /global-trust-authority/v1/service/cert`

##### Request Parameters
| Field | Sub-field | Type | Required | parameter constraint | Description |
|-------|-----------|------|----------|-------------|-------------|
| delete_type | | string | Yes | "id""type""all" | Delete type "id""type""all" |
| ids | | Array[string] | No | Maximum 10 ids | Certificate ID list |
| type | | string | No | refvalue/policy/tpm_boot/tpm_ima/crl | Certificate type, refvalue/policy/tpm_boot/tpm_ima/crl |

##### Response Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| message | | string | No | Error message |

### 3.3 Challenge Related

#### 3.3.1 Request Nonce
**Description**: Request nonce

**Request Method**: `POST /global-trust-authority/v1/service/challenge`

##### Request Parameters
| Field | Type | Required | parameter constraint | Description | Note |
|-------|------|----------|-------------|------|------|
| agent_version | string | Yes | Length 1-50 characters | Client version number | Format is x.x.x, e.g., 1.0.0 |
| attester_type | list of string | Yes | "tpm_boot","tpm_ima" | Plugin type, server returns error if not supported | Only supports "tpm_boot","tpm_ima" |

##### Response Parameters
| Field | Sub-field | Type | Required | Description | Note |
|-------|-----------|------|----------|-------------|------|
| service_version | | string | Yes | Server version | Format is x.x.x, e.g., 1.0.0 |
| message | | string | No | Error message | Maximum length 1024 bytes |
| nonce | | object | No | Nonce information | |
| | iat | long | Yes | Issue time | Maximum uint64 |
| | value | string | Yes | Nonce value | 64~1024BYTE, base64 encoded |
| | signature | string | Yes | Signature value | Not less than 64BYTE, default BASE64 encoding |

##### Example of request

###### request body

```
{
    "agent_version": "1.0",
    "attester_type": ["tpm_boot"]
}
```

###### response body

 ```
{
    "service_version": "1.0",
    "nonce": {
        "iat": 1747646103,
        "value": "alTQWp3PPVLCLVqTWBViqNgG14KeWtFF7muXoK8Pb8AGj1U5GVFyoK67z2PgNMlcQIUvnzXTzG9pqsj89+B0Gg==",
        "signature": "UTeRydOBjPnzPljSsjIYxgYIfBOZAdY4SPe9Vz47KKRRJomWHOQICqqGic/1kul8neVRFnn9sPTAyPeOqvQw5Z8h30CrM2McVf8bJxwi5j24WJqFhUVuBBZm8zMi+iuhGiNkFF1VVbsDkf97kFsajKQsMaysQJHL+wtxbbOYSgkLy4SzpYLx39+mSsZUTRuJC6y1VdNdQs1AypgnusEGUmTO5SYU4kWiVy/l/3fnCd8vuAofClb2Xge6yKFYvoeGYeRxYwEO0DLNIpI8MTAfi/67/oarqZlr1dOFsbNzjkzzv71GjzNuXU1mBdew4dd7rxUKHIqjex0+RqXJQtg69kH0AdpgI2EAKqkB4icjxm2jX07yDSlIG2zLjlhaaa0ch/A0mxrOFhtFMhHtlyarChuk0p8E2wKdNNwDTWdyNg9F07BrqcsBHMU2R1Keq+NXN54TGT+M87Pq3fdZ8qgD4rSmZjGUSDgCeIJckPZOtvWnF8yNbtcnajm1rTeXYbSK"
    }
}
 ```

#### 3.3.2 Remote Attestation

**Description**: Report evidence for remote attestation

**Request Method**: `POST /global-trust-authority/v1/service/attest`

##### Request Parameters
| Field | Sub-field | Second-level Sub-field | Type | Required | parameter constraint | Description |
|-------|-----------|------------------------|------|----------|-------------|-------------|
| agent_version | | | string | Yes | Length 1-50 characters | Client version number |
| nonce_type | | | string | No |  | ignore/user/default (default value) corresponds to not verifying nonce, using user nonce, using verifier-generated nonce |
| user_nonce | | | string | No |  | Filled when nonce_type is user, 64~1024BYTE, base64 encoded |
| measurements | | | list of objects | Yes |  | Measurement data |
| | node_id | | string | No | Length 1-255 characters | Node ID, corresponds to uied, recommended 32~128 characters, based on actual device |
| | nonce | | object | No |  | Nonce object |
| | | iat | long | No |  | Issue time |
| | | value | string | Yes |  | Nonce value |
| | | signature | string | No |  | Signature value |
| | attester_data | | object | No |  | User-defined data to be passed through, must be placed in token as-is |
| | evidences | | list of objects | Yes |  | Challenge report |
| | | attester_type | string | Yes |  | Challenge type, see attester_type specification |
| | | evidence | object | Yes |  | Specific evidence |
| | | policy_ids | list of string | No | Length 1-36 characters | Policy ID list to verify, maximum 10 |

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

Too many parameters to show a sample request

### 3.4 Policy Management

#### 3.4.1 Add Policy
**Description**: Add policy

**Request Method**: `POST /global-trust-authority/v1/service/policy`

##### Request Parameters
| Field | Type | Required | parameter constraint | Description |
|-------|------|----------|-------------|-------------|
| id | string | No | length 1~36 characters | Policy ID, length  if filled, use it as policy ID, if not filled, generate UUID |
| name | string | Yes | length 1~255 characters | Policy name |
| description | string | No | length not exceeding 512 characters | Policy description |
| attester_type | string | Yes | length 1~255 characters | Applicable challenge plugin type, see previous specification |
| content_type | string | Yes | jwt or text | jwt/text (corresponding to unsigned case) |
| content | string | Yes | Default maximum 500kb | Policy content, maximum 500KB before encoding |
| is_default | boolean | No | true or false | Whether it's default policy, defaults to false |

When content_type is jwt, jwt content:
| Field Location | Field | Type | Required | Description |
|----------------|-------|------|----------|-------------|
| header | alg | string | Yes | Token signature algorithm |
| header | kid | string | No | Public key ID |
| body | policy | string | Yes | Policy content |

##### Response Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| message | | string | No | Error message |
| policy | | object | No | Policy information |
| | id | string | Yes | Policy ID, UUID, 16byte, 36 characters with hyphen |
| | name | string | Yes | Policy name |
| | version | u32 | Yes | Policy version, created as 1, increments by 1 on update |

##### Example of request

###### request body

```
{
    "name": "test_policy{{$number.int}}",
    "description": "This is Test",
    "attester_type": [
        "tpm_ima"
    ],
    "content": "cGFja2FnZSB2ZXJpZmljYXRpb24KCiMgRXh0cmFjdCBpc19sb2dfdmFsaWQgZnJvbSBmaXJzdCB0cG1faW1hIGxvZwppc19sb2dfdmFsaWQgPSB2YWxpZCB7CiAgICBzb21lIGkKICAgIGxvZ3MgOj0gaW5wdXQuZXZpZGVuY2UubG9ncwogICAgbG9nc1tpXS5sb2dfdHlwZSA9PSAiSW1hTG9nIgogICAgdmFsaWQgOj0gbG9nc1tpXS5pc19sb2dfdmFsaWQKfQoKIyBDaGVjayBpZiBwY3JzIDEwIGlzIHByZXNlbnQgaW4gYW55IGhhc2ggYWxnb3JpdGhtIChzaGExLCBzaGEyNTYsIHNoYTM4NCwgc2hhNTEyKQpwY3JfcHJlc2VudCB7CiAgICBhbGwgOj0ge3ggfCB4IDo9IFsxMF1bX10gfQogICAgbWVhc3VyZWQgOj0ge3Bjci5wY3JfaW5kZXggfCBwY3IgOj0gaW5wdXQuZXZpZGVuY2UucGNycy5wY3JfdmFsdWVzW19dfQogICAgYWxsX3BjcnNfc3Vic2V0IDo9IGFsbCAtIG1lYXN1cmVkCiAgICBjb3VudChhbGxfcGNyc19zdWJzZXQpID09IDAKfQoKIyBBdHRlc3RhdGlvbiB2YWxpZCBpZiBhbGwgY29uZGl0aW9ucyBtZXQKZGVmYXVsdCBhdHRlc3RhdGlvbl92YWxpZCA9IGZhbHNlCmF0dGVzdGF0aW9uX3ZhbGlkIHsKICAgIGlzX2xvZ192YWxpZCA9PSB0cnVlCiAgICBwY3JfcHJlc2VudAp9CgojIE91dHB1dCByZXN1bHQKcmVzdWx0ID0gewogICAgInBvbGljeV9tYXRjaGVkIjogYXR0ZXN0YXRpb25fdmFsaWQsCiAgICAiY3VzdG9tX2RhdGEiOiB7CiAgICAgICAgImhhc2hfYWxnIjogaW5wdXQuZXZpZGVuY2UucGNycy5oYXNoX2FsZwogICAgfQp9",
    "content_type": "text",
    "is_default": true
}
```

###### response body

 ```
{
    "id": "685e03ef-c111-4633-99b1-647262639682",
    "name": "test_policy628176847040204",
    "version": 1
}
 ```

#### 3.4.2 Update Policy

**Description**: Update policy

**Request Method**: `PUT /global-trust-authority/v1/service/policy`

##### Request Parameters
| Field | Type | Required | parameter constraint | Description |
|-------|------|----------|-------------|-------------|
| id | string | Yes | length 1~36 characters | Policy ID |
| name | string | No | length 1~255 characters | Policy name |
| description | string | No | length 0~512 characters | Policy description |
| attester_type | list of string | No | length 1~255 characters | Applicable challenge plugin type |
| content_type | string | No | jwt or text | jwt/text (corresponding to unsigned case) |
| content | string | No | Default maximum 500kb | Policy content |
| is_default | boolean | No | true or false | Whether it's default policy, defaults to false |

##### Response Parameters
| Field | Sub-field | Type | Required | Description |
|-------|-----------|------|----------|-------------|
| message | | string | No | Error message |
| policies | | string | No | Policy information |
| | id | string | Yes | Policy ID |
| | name | string | Yes | Policy name |
| | version | u32 | Yes | Policy version |

##### Example of request

###### request body

```
{
    "id": "685e03ef-c111-4633-99b1-647262639682",
    "name": "Tes2t",
    "description": "123",
    "content": "cGFja2FnZSBkaWdlc3RfdmVyaWZpY2F0aW9uCgppbXBvcnQgZnV0dXJlLmtleXdvcmRzLmlmCmltcG9ydCBmdXR1cmUua2V5d29yZHMuaW4KCiMgRGVmYXVsdCByZXN1bHQgaXMgcGFzcwpkZWZhdWx0IHJlc3VsdCA9IHsic3RhdHVzIjogInBhc3MifQoKIyBNYWluIHJ1bGUgdG8gZXZhbHVhdGUgdGhlIGlucHV0IGFnYWluc3QgYmFzZWxpbmUKcmVzdWx0ID0gb3V0cHV0IGlmIHsKICAgICMgR2V0IGlucHV0IGRhdGEKICAgIGlucHV0X2RhdGEgOj0gaW5wdXQKICAgIAogICAgIyBFeHRyYWN0IGFsbCBTSEEyNTYgZGlnZXN0cyBmcm9tIGV2ZW50cwogICAgZGlnZXN0cyA6PSBbZGlnZXN0IHwKICAgICAgICBldmVudCA6PSBpbnB1dF9kYXRhLmV2ZW50c1tfXQogICAgICAgIGRpZ2VzdF9vYmogOj0gZXZlbnQuRGlnZXN0c1tfXQogICAgICAgIGRpZ2VzdF9vYmouQWxnb3JpdGhtSWQgPT0gInNoYTI1NiIKICAgICAgICBkaWdlc3QgOj0gZGlnZXN0X29iai5EaWdlc3QKICAgIF0KICAgIAogICAgIyBGaW5kIG1pc3NpbmcgZGlnZXN0cyB1c2luZyB0aGUgUnVzdCBmdW5jdGlvbgogICAgIyBUaGlzIGZ1bmN0aW9uIG5vdyByZWFkcyB0aGUgYmFzZWxpbmUgZnJvbSBhIGZpbGUgZGlyZWN0bHkKICAgIG1pc3NpbmdfZGlnZXN0cyA6PSBmaW5kX21pc3NpbmdfZGlnZXN0cyhkaWdlc3RzKQogICAgCiAgICAjIENyZWF0ZSBtYXBwaW5nIG9mIG1pc3NpbmcgZGlnZXN0cyB0byBldmVudCBudW1iZXJzCiAgICBtaXNzaW5nX2V2ZW50cyA6PSB7ZGlnZXN0OiB7ImV2ZW50X251bWJlciI6IGV2ZW50LkV2ZW50TnVtfSB8CiAgICAgICAgZXZlbnQgOj0gaW5wdXRfZGF0YS5ldmVudHNbX10KICAgICAgICBkaWdlc3Rfb2JqIDo9IGV2ZW50LkRpZ2VzdHNbX10KICAgICAgICBkaWdlc3Rfb2JqLkFsZ29yaXRobUlkID09ICJzaGEyNTYiCiAgICAgICAgZGlnZXN0IDo9IGRpZ2VzdF9vYmouRGlnZXN0CiAgICAgICAgZGlnZXN0IGluIG9iamVjdC5rZXlzKG1pc3NpbmdfZGlnZXN0cykKICAgIH0KICAgIAogICAgIyBEZXRlcm1pbmUgaWYgYW55IGRpZ2VzdHMgYXJlIG1pc3NpbmcKICAgIGNvdW50KG9iamVjdC5rZXlzKG1pc3NpbmdfZGlnZXN0cykpID4gMAogICAgCiAgICAjIENyZWF0ZSBvdXRwdXQgd2l0aCBmYWlsdXJlIHN0YXR1cyBhbmQgbWlzc2luZyBkaWdlc3RzCiAgICBvdXRwdXQgOj0gewogICAgICAgICJzdGF0dXMiOiAiZmFpbCIsCiAgICAgICAgIm1pc3NpbmdfZGlnZXN0cyI6IG1pc3NpbmdfZXZlbnRzCiAgICB9Cn0=",
    "content_type": "text"
}
```

###### response body

 ```
{
    "id": "685e03ef-c111-4633-99b1-647262639682",
    "name": "Tes2t",
    "version": 2
}
 ```

#### 3.4.3 Delete Policy

**Description**: Delete policy

**Request Method**: `DELETE /global-trust-authority/service/v1/policy`

##### Request Parameters
| Field | Type | Required | parameter constraint | Description |
|-------|------|----------|-------------|-------------|
| delete_type | string | Yes | "id""attester_type""all" | Delete type "id""attester_type""all" |
| ids | List of String | No | maximum 10 | Policy IDs, maximum 10 |
| attester_type | string | No | length 1~255 characters | Policy type |

##### Response Parameters
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| message | string | No | Error message |

#### 3.4.4 Query Policy
**Description**: Query policy

**Request Method**: `GET /global-trust-authority/v1/service/policy`

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

##### Example of request

###### request url

```
http://10.10.0.102:8080/global-trust-authority/v1/service/policy?ids=2b0ead4b-6a15-4239-bf68-b1413df538bb
```

###### response body

 ```
{
    "policies": [
        {
            "id": "2b0ead4b-6a15-4239-bf68-b1413df538bb",
            "name": "test_policy3891702073167223",
            "description": "This is Test",
            "content": "package verification\n\n# Extract is_log_valid from first tpm_ima log\nis_log_valid = valid {\n    some i\n    logs := input.evidence.logs\n    logs[i].log_type == \"ImaLog\"\n    valid := logs[i].is_log_valid\n}\n\n# Check if pcrs 10 is present in any hash algorithm (sha1, sha256, sha384, sha512)\npcr_present {\n    all := {x | x := [10][_] }\n    measured := {pcr.pcr_index | pcr := input.evidence.pcrs.pcr_values[_]}\n    all_pcrs_subset := all - measured\n    count(all_pcrs_subset) == 0\n}\n\n# Attestation valid if all conditions met\ndefault attestation_valid = false\nattestation_valid {\n    is_log_valid == true\n    pcr_present\n}\n\n# Output result\nresult = {\n    \"policy_matched\": attestation_valid,\n    \"custom_data\": {\n        \"hash_alg\": input.evidence.pcrs.hash_alg\n    }\n}",
            "attester_type": [
                "tpm_ima"
            ],
            "is_default": true,
            "version": 1,
            "update_time": 1747640682,
            "valid_code": 0
        }
    ]
}
 ```

### 3.5 Token Validation

#### 3.5.1 Validate Token
**Description**: Validate Token

**Request Method**: `POST /global-trust-authority/v1/service/token/verify`

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

##### Example of request

###### request body

```
{
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6ImprdSIsImtpZCI6ImtpZCJ9.eyJpbnR1c2UiOiJHZW5lcmljIiwidWVpZCI6IlRQTSBBSyIsInRwbV9ib290Ijp7ImF0dGVzdGF0aW9uX3N0YXR1cyI6ImZhaWwiLCJwb2xpY3lfaW5mbyI6W3siYXBwcmFpc2FsX3BvbGljeV9pZCI6IjgwMzhkNjlmLWY0MTItNGZhNC1hODFjLWRhYWJmZjUyNWYwOCIsInBvbGljeV92ZXJzaW9uIjoxLCJwb2xpY3lfbWF0Y2hlZCI6ZmFsc2UsImN1c3RvbV9kYXRhIjp7InBjcnMiOlt7ImJhc2VsaW5lX3ZhbHVlIjoiOWQ3NTA0YmIwZDMyZjYyZDQzMzEwZjM4ZGYzN2NkZDVlNDJiZGI4M2RkMGMwNTkyZmQ5YjFjM2IxNjc3MGMzNSIsImluZGV4IjowLCJtZWFzdXJlZF92YWx1ZSI6ImUyMWI3MDNlZTY5Yzc3NDc2YmNjYjQzZWMwMzM2YTlhMWIyOTE0YjM3ODk0NGY3YjAwYTEwMjE0Y2E4ZmVhOTMifSx7ImJhc2VsaW5lX3ZhbHVlIjoiMzg4NDYyNzFlMmE4NmQ2YmY0M2VmMzg4YmUyZDFjYjgzYTg5ZjFjMGJiMTU0ZmU0OTRhMWRkYTE5OGRhMjliZSIsImluZGV4IjoxLCJtZWFzdXJlZF92YWx1ZSI6ImEzMmJmOGJmMzI5OTA3ZGMyYjQ4MzlmZjNjNjFiNDU2YTk4NTZkMTIxMTBmNDlkNDkwZGYzM2JhZjE4OTM0MGUifSx7ImJhc2VsaW5lX3ZhbHVlIjoiM2Q0NThjZmU1NWNjMDNlYTFmNDQzZjE1NjJiZWVjOGRmNTFjNzVlMTRhOWZjZjlhNzIzNGExM2YxOThlNzk2OSIsImluZGV4IjoyLCJtZWFzdXJlZF92YWx1ZSI6ImE5ZDViZGYzYjBiMDM0YTQzNGVmM2FkZGUyZDVjYjBhNzUzMzgwM2Y5N2Y4ODg5ZjExNzRhYjYwYmQ0ZGNiNzAifSx7ImJhc2VsaW5lX3ZhbHVlIjoiM2Q0NThjZmU1NWNjMDNlYTFmNDQzZjE1NjJiZWVjOGRmNTFjNzVlMTRhOWZjZjlhNzIzNGExM2YxOThlNzk2OSIsImluZGV4IjozLCJtZWFzdXJlZF92YWx1ZSI6ImUyMWI3MDNlZTY5Yzc3NDc2YmNjYjQzZWMwMzM2YTlhMWIyOTE0YjM3ODk0NGY3YjAwYTEwMjE0Y2E4ZmVhOTMifSx7ImJhc2VsaW5lX3ZhbHVlIjoiOGVkMTJjNDE1MDU2MzYyYzdhNGQ0MDNlNmUyYWNhZGYwOTBlNzhiZmI0Nzk4YTg3YjBhMzI3YzgzODA2NDkzMSIsImluZGV4Ijo0LCJtZWFzdXJlZF92YWx1ZSI6ImZjZTdmMTA4MzA4MmIxNmNmZTJiMDg1ZGQ3ODU4YmIxMWEzN2MwOWI3OGUzNmM3OWU1YTJmZDUyOTM1M2M0ZTIifSx7ImJhc2VsaW5lX3ZhbHVlIjoiNjYxMjFkNWJjZGI4YWI2ZDYyOGI0OTgyNzU5MGFjOGUxZjJmMDllMjZhYTJkMWRkMWNmZWM1MzU4ODU0Y2QzYSIsImluZGV4Ijo1LCJtZWFzdXJlZF92YWx1ZSI6IjhlZGRlOTEyNjk5Y2VkZGRkYzdkOWEzZDdlZTQ0YThiMWIxOTEwODE1NjkyZGVmNmM5ZTYzN2UyYjkzOWY5NDEifSx7ImJhc2VsaW5lX3ZhbHVlIjoiM2Q0NThjZmU1NWNjMDNlYTFmNDQzZjE1NjJiZWVjOGRmNTFjNzVlMTRhOWZjZjlhNzIzNGExM2YxOThlNzk2OSIsImluZGV4Ijo2LCJtZWFzdXJlZF92YWx1ZSI6ImUyMWI3MDNlZTY5Yzc3NDc2YmNjYjQzZWMwMzM2YTlhMWIyOTE0YjM3ODk0NGY3YjAwYTEwMjE0Y2E4ZmVhOTMifSx7ImJhc2VsaW5lX3ZhbHVlIjoiNzRmYTJjMDY3ODkyZmFhNzRiZmIwY2FmYWNjNGM3MTAyZGQyYzljZjczZWZkZmE0MWYwN2ZkZmM3YzFlZWExYiIsImluZGV4Ijo3LCJtZWFzdXJlZF92YWx1ZSI6ImUyMWI3MDNlZTY5Yzc3NDc2YmNjYjQzZWMwMzM2YTlhMWIyOTE0YjM3ODk0NGY3YjAwYTEwMjE0Y2E4ZmVhOTMifV19fV0sImlzX2xvZ192YWxpZCI6dHJ1ZSwicGNycyI6eyJoYXNoX2FsZyI6InNoYTI1NiIsInBjcl92YWx1ZXMiOlt7ImlzX21hdGNoZWQiOnRydWUsInBjcl9pbmRleCI6MCwicGNyX3ZhbHVlIjoiZTIxYjcwM2VlNjljNzc0NzZiY2NiNDNlYzAzMzZhOWExYjI5MTRiMzc4OTQ0ZjdiMDBhMTAyMTRjYThmZWE5MyIsInJlcGxheV92YWx1ZSI6ImUyMWI3MDNlZTY5Yzc3NDc2YmNjYjQzZWMwMzM2YTlhMWIyOTE0YjM3ODk0NGY3YjAwYTEwMjE0Y2E4ZmVhOTMifSx7ImlzX21hdGNoZWQiOnRydWUsInBjcl9pbmRleCI6MSwicGNyX3ZhbHVlIjoiYTMyYmY4YmYzMjk5MDdkYzJiNDgzOWZmM2M2MWI0NTZhOTg1NmQxMjExMGY0OWQ0OTBkZjMzYmFmMTg5MzQwZSIsInJlcGxheV92YWx1ZSI6ImEzMmJmOGJmMzI5OTA3ZGMyYjQ4MzlmZjNjNjFiNDU2YTk4NTZkMTIxMTBmNDlkNDkwZGYzM2JhZjE4OTM0MGUifSx7ImlzX21hdGNoZWQiOnRydWUsInBjcl9pbmRleCI6MiwicGNyX3ZhbHVlIjoiYTlkNWJkZjNiMGIwMzRhNDM0ZWYzYWRkZTJkNWNiMGE3NTMzODAzZjk3Zjg4ODlmMTE3NGFiNjBiZDRkY2I3MCIsInJlcGxheV92YWx1ZSI6ImE5ZDViZGYzYjBiMDM0YTQzNGVmM2FkZGUyZDVjYjBhNzUzMzgwM2Y5N2Y4ODg5ZjExNzRhYjYwYmQ0ZGNiNzAifSx7ImlzX21hdGNoZWQiOnRydWUsInBjcl9pbmRleCI6MywicGNyX3ZhbHVlIjoiZTIxYjcwM2VlNjljNzc0NzZiY2NiNDNlYzAzMzZhOWExYjI5MTRiMzc4OTQ0ZjdiMDBhMTAyMTRjYThmZWE5MyIsInJlcGxheV92YWx1ZSI6ImUyMWI3MDNlZTY5Yzc3NDc2YmNjYjQzZWMwMzM2YTlhMWIyOTE0YjM3ODk0NGY3YjAwYTEwMjE0Y2E4ZmVhOTMifSx7ImlzX21hdGNoZWQiOnRydWUsInBjcl9pbmRleCI6NCwicGNyX3ZhbHVlIjoiZmNlN2YxMDgzMDgyYjE2Y2ZlMmIwODVkZDc4NThiYjExYTM3YzA5Yjc4ZTM2Yzc5ZTVhMmZkNTI5MzUzYzRlMiIsInJlcGxheV92YWx1ZSI6ImZjZTdmMTA4MzA4MmIxNmNmZTJiMDg1ZGQ3ODU4YmIxMWEzN2MwOWI3OGUzNmM3OWU1YTJmZDUyOTM1M2M0ZTIifSx7ImlzX21hdGNoZWQiOnRydWUsInBjcl9pbmRleCI6NSwicGNyX3ZhbHVlIjoiOGVkZGU5MTI2OTljZWRkZGRjN2Q5YTNkN2VlNDRhOGIxYjE5MTA4MTU2OTJkZWY2YzllNjM3ZTJiOTM5Zjk0MSIsInJlcGxheV92YWx1ZSI6IjhlZGRlOTEyNjk5Y2VkZGRkYzdkOWEzZDdlZTQ0YThiMWIxOTEwODE1NjkyZGVmNmM5ZTYzN2UyYjkzOWY5NDEifSx7ImlzX21hdGNoZWQiOnRydWUsInBjcl9pbmRleCI6NiwicGNyX3ZhbHVlIjoiZTIxYjcwM2VlNjljNzc0NzZiY2NiNDNlYzAzMzZhOWExYjI5MTRiMzc4OTQ0ZjdiMDBhMTAyMTRjYThmZWE5MyIsInJlcGxheV92YWx1ZSI6ImUyMWI3MDNlZTY5Yzc3NDc2YmNjYjQzZWMwMzM2YTlhMWIyOTE0YjM3ODk0NGY3YjAwYTEwMjE0Y2E4ZmVhOTMifSx7ImlzX21hdGNoZWQiOnRydWUsInBjcl9pbmRleCI6NywicGNyX3ZhbHVlIjoiZTIxYjcwM2VlNjljNzc0NzZiY2NiNDNlYzAzMzZhOWExYjI5MTRiMzc4OTQ0ZjdiMDBhMTAyMTRjYThmZWE5MyIsInJlcGxheV92YWx1ZSI6ImUyMWI3MDNlZTY5Yzc3NDc2YmNjYjQzZWMwMzM2YTlhMWIyOTE0YjM3ODk0NGY3YjAwYTEwMjE0Y2E4ZmVhOTMifV19LCJzZWN1cmVfYm9vdCI6Ik5BIn0sImlhdCI6MTc0Njg2NDExNTgxMSwiZXhwIjoxNzQ2ODY0NzE1ODExLCJpc3MiOiJpc3MiLCJqdGkiOiI4MDE3ODBjYi0wOTM3LTQ1ZjQtYmRmZi1iNzUxMDhhMjQ1MDciLCJ2ZXIiOiIxLjAiLCJuYmYiOjE3NDY4NjQxMTU4MTEsImVhdF9wcm9maWxlIjoiZWF0X3Byb2ZpbGUifQ.WAPSQ1WAITX68N4A33BZauS76CRJOLNuiHMEVrD4RD4VvChNrkitrPbugk6PPLMzEPl2xzgIL_rtapJBpsBXXXHdyUFpUnoDZ9c0VKj5GqrM4qd7cXjMLAbnNBuXNY-oPfmq_Rk-m0uI4CeIQL1lGHrgRARvxWYdJ7aNhJ9GQR9xD39qpsiH8dM_oPHTwScMmNdgO9Z89_pnsQDDeyolzMhXQiuMXpMEUiH5kAuO7ViHqravn7R93BxdKcS4QppPlRmbedkg7RoWuWU9jJahZX64CG_MtJAGZ22C0t6gI36jbuAlC4kX3RxT2B9KvSZqg2okCXjpJ9iaI9xuQFLe6pUwpkzS6mC-X3wjzOkmSq24mUDln8xE-Sr6tnSm726TSa9DzfICstGtcYDGjt0J1XHgjJbASbaIZx0gx9CwKDxHHEfN97Mv3Qx4L4vEtQInAHBn6soRzvy30N0kJ2JaTerWksXl580yd9rItyywbiSltTRA5w6Eqol2dZSMzmvQ"
}
```

###### response body

 ```
{
    "verification_pass": false,
    "token_body": null,
    "token_header": {
        "typ": "JWT",
        "alg": "HS256"
    }
}
 ```

