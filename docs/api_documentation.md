# API Documentation

## Table of Contents
- [1. General Information](#1-general-information)
- [2. Agent API](#2-agent-api)
  - [2.1 Get Token](#21-get-token)
  - [2.2 Get Evidence](#22-get-evidence)
- [3. Service API](#3-service-api)
  - [3.1 Reference Value Management](#31-reference-value-management)
  - [3.2 Certificate Management](#32-certificate-management)
  - [3.3 Challenge Related](#33-challenge-related)
  - [3.4 Policy Management](#34-policy-management)
  - [3.5 Token Validation](#35-token-validation)
- [4. Key Manager API](#4-Key-Manager-API)
  - [4.1 Query Key](#41-Query-key)

## 1. General Information

### 1.1 Request Headers
| Field        | Type   | Required | Description                                             |
|--------------|--------|----------|---------------------------------------------------------|
| Content-Type | string | Yes      | Content-Type header                                     |
| Accept       | string | No       | Accept header                                           |
| API-Key      | string | No       | For API authentication, mutually exclusive with User-Id |
| User-Id      | string | Yes      | User identifier, 36-character string (16-byte UUID)     |
| User-Name    | string | No       | Username                                                |
| Request-Id   | string | No       | Request ID                                              |

## 2. Agent API

### 2.1 Get Token
**Description**: Get token

**Request Method**: `POST /global-trust-authority/agent/v1/tokens`

#### Request Parameters
| Field         | Sub-field     | Type           | Required | parameter constraint          | Description                                                                      |
|---------------|---------------|----------------|----------|-------------------------------|----------------------------------------------------------------------------------|
| attester_info |               | list of object | No       |                               | Challenge information                                                            |
|               | attester_type | string         | No       | tpm_boot or tpm_ima character | Challenge type, defaults to traversing activated client plugins if not specified |
|               | policy_ids    | list of string | No       | The number is less than 10    | Applied policies, uses default policy if not specified                           |
| challenge     |               | bool           | No       |                               | Whether to challenge, defaults to no challenge                                   |
| attester_data |               | object         | No       |                               | User data, reserved field                                                        |

#### Response Parameters
| Field   | Type   | Required                   | Description   |
|---------|--------|----------------------------|---------------|
| message | string | Yes for failed request     | Error message |
| token   | object | Yes for successful request | Token object  |

##### Example of request

###### request body

```
{
    "attester_info": [
      {
        "attester_type": "tpm_boot",
        "policy_ids": []
      }
    ],
    "challenge": true,
    "attester_data": {"test_key": "test_value"}
}
```

###### response body

 ```
 {
    "token":"xxx"
 }
 ```

### 2.2 Get Evidence
**Description**: Provides encapsulated Evidence data

**Request Method**: `POST /global-trust-authority/agent/v1/evidences`

#### Request Parameters
| Field         | Sub-field     | Type            | Required | parameter constraint                       | Description                                                                                                              |
|---------------|---------------|-----------------|----------|--------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| attesters     |               | list of objects | Yes      | Fill in either tpm_boot or tpm_ima or both | challenge information                                                                                                    |
|               | attester_type | string          | yes      | tpm_boot/tpm_ima/virt_cca                  | challenge types                                                                                                          |
|               | log_types     | list of strings | No       | ImaLog/TcgEventLog/CCEL                    | types of log to collect                                                                                                  |
| nonce_type    |               | string          | No       | ignore、user or verifier                    | ignore/user/verifier(default value) corresponds to not verifying nonce, using user nonce, using verifier-generated nonce |
| user_nonce    |               | string          | No       | Lenght 1-1024 bytes                        | Filled when nonce_type is user, Format: Base64                                                                           |
| nonce         |               | object          | No       |                                            | Nonce value structure / required if nonce_type not filled                                                                |
|               | iat           | u64             | No       |                                            | Issue time                                                                                                               |
|               | value         | string          | No       | Lenght 1-1024 bytes                        | Nonce value                                                                                                              |
|               | signature     | string          | No       |                                            | Signature value                                                                                                          |
| attester_data |               | object          | No       |                                            | User data, reserved field                                                                                                |

#### Response Parameters
| Field         | Sub-field     | Second-level Sub-field | Type            | Required | Description                                                                                                              |
|---------------|---------------|------------------------|-----------------|----------|--------------------------------------------------------------------------------------------------------------------------|
| agent_version |               |                        | string          | No       | Client version number                                                                                                    |
| nonce_type    |               |                        | string          | No       | ignore/user/verifier(default value) corresponds to not verifying nonce, using user nonce, using verifier-generated nonce |
| user_nonce    |               |                        | string          | No       | Filled when nonce_type is user                                                                                           |
| measurements  |               |                        | list of objects | No       | Measurement data                                                                                                         |
|               | node_id       |                        | string          | No       | Node ID, corresponds to ueid                                                                                             |
|               | nonce         |                        | object          | No       | Nonce object, see /challenge definition                                                                                  |
|               | attester_data |                        | object          | No       | User-defined data to be passed through, must be placed in token as-is                                                    |
|               | evidences     |                        | list of objects | No       | Challenge report                                                                                                         |
|               |               | attester_type          | string          | No       | Challenge type                                                                                                           |
|               |               | evidence               | list of objects | No       | Specific evidence                                                                                                        |

##### Example of request

###### request body

```
{
    "attester_types": ["tpm_boot"],
    "nonce_type": "verifier",
    "nonce": {
      "iat": 1749721474,
      "value": "ImQiIm+6vwdKhAH6FC58XFxfuQ8TWvGxO6qlYwQK6P11Fi/ole/VMN9+4PJodOGt8E6+sbkfJOmuU96/Wc0JSw==",
      "signature": "eEZHR66P+wPOuTTJanS0OhjqPLquLlJci2KxdptPz8+yLJpOVsOSUDsdeadv0a3aFStY130NdthZ/aBWQNWusblABhq0uepaS/29UFVUXT9tbSQG2PGhsG1+NQxkNr1/u/zktQLqThk9oxiEF8nwFozZTyaSJAvzV5b/3lIvJxa588OUug6PhurMKxIOx0KqpPxv/sHq74IUjW50r4ZtLUlRUxERLPORuobHaCjmJ9UMby6NZ6xlvjKVb5gAWGcupZS4M1PSAYb3+90MpflFrfu6gGLbe29o5CIWDgrwMYfgFGsJ9GaWdTZ20rbdn60USYPvManw0dkNr4Q4tKhs4VYX+IkByVddfexg9t5en/wC8axVk2zH6C7edoepgZfW2AJo8TKYdb8XEGIBteadlvGohX3w957/uZc3lAcJmNEImYTEzwJu4aj4pcOH54YhOWoIYY3fGaIw5JQ87VslG256VUo0h8QIlYUEtEisFpZzwuInOlNwB9o4TMbPuosd"
    },
    "attester_data": {"test_key": "test_value"}
  }'
```

###### response body

 ```
{
    "agent_version":"0.1.0","nonce_type":"verifier","measurements":[{"node_id":"TPM AK","nonce":{"iat":1749721474,"value":"ImQiIm+6vwdKhAH6FC58XFxfuQ8TWvGxO6qlYwQK6P11Fi/ole/VMN9+4PJodOGt8E6+sbkfJOmuU96/Wc0JSw==","signature":"eEZHR66P+wPOuTTJanS0OhjqPLquLlJci2KxdptPz8+yLJpOVsOSUDsdeadv0a3aFStY130NdthZ/aBWQNWusblABhq0uepaS/29UFVUXT9tbSQG2PGhsG1+NQxkNr1/u/zktQLqThk9oxiEF8nwFozZTyaSJAvzV5b/3lIvJxa588OUug6PhurMKxIOx0KqpPxv/sHq74IUjW50r4ZtLUlRUxERLPORuobHaCjmJ9UMby6NZ6xlvjKVb5gAWGcupZS4M1PSAYb3+90MpflFrfu6gGLbe29o5CIWDgrwMYfgFGsJ9GaWdTZ20rbdn60USYPvManw0dkNr4Q4tKhs4VYX+IkByVddfexg9t5en/wC8axVk2zH6C7edoepgZfW2AJo8TKYdb8XEGIBteadlvGohX3w957/uZc3lAcJmNEImYTEzwJu4aj4pcOH54YhOWoIYY3fGaIw5JQ87VslG256VUo0h8QIlYUEtEisFpZzwuInOlNwB9o4TMbPuosd"},"attester_data":{"test_key":"test_value"},"evidences":[{"attester_type":"tpm_boot","evidence":{"ak_cert":"-----BEGIN CERTIFICATE-----\nxxxxx\n-----END CERTIFICATE-----","quote":{"quote_data":"/1RDR4AYACIAC6dK2j3UWnqCmI9se9Itpmwo+GB2VAKRbS/VU2Iczqe1ACA1SjdRM3NRYkY2WXA2UjZUMVFtOGsxZ1g3ajlZenZINAAAAACDq3eBAAAAGwAAAAABIBkQIwAWNjYAAAABAAsD/wAAACDmjVToNmS/+eKvnv6kvbrY+7FU8ALNmB8Ntz2L9wJotw==","signature":"ABQACwEAnm7Y3gZrwC81wPiFtz6I+2agoG7FOmFCSCz6OwuJScJ1fJTSL+UD0V/9R0NVDeH5ooRCc6z7r+khisBUiuOaC4o61W0CLrjZH35VXiLFtj2tQgmB8AKVKmTrj7sUN5Lu77NqUcKr4AWO2NgJyWqZgns1K5KKu/pcAzS679xUk6ZMdNg0hzJYQM6ufG90hjJO7Xa6Uww0T8fufWWEVOWnKlQmRM2DOSGIwWhuMf5/vHYSNab5s0roICIKj3wNlsP25t69kfy6PLBN2h/ZH2R5KsqplueKQr1ekuvwOtShBzfuijcxnbnLLyJkfjSWzkfSYACthMUvpkqI6by8v0ThLQ=="},"pcrs":{"hash_alg":"sha256","pcr_values":[{"pcr_index":0,"pcr_value":"e21b703ee69c77476bccb43ec0336a9a1b2914b378944f7b00a10214ca8fea93"},{"pcr_index":1,"pcr_value":"a32bf8bf329907dc2b4839ff3c61b456a9856d12110f49d490df33baf189340e"},{"pcr_index":2,"pcr_value":"a9d5bdf3b0b034a434ef3adde2d5cb0a7533803f97f8889f1174ab60bd4dcb70"},{"pcr_index":3,"pcr_value":"e21b703ee69c77476bccb43ec0336a9a1b2914b378944f7b00a10214ca8fea93"},{"pcr_index":4,"pcr_value":"fce7f1083082b16cfe2b085dd7858bb11a37c09b78e36c79e5a2fd529353c4e2"},{"pcr_index":5,"pcr_value":"8edde912699ceddddc7d9a3d7ee44a8b1b1910815692def6c9e637e2b939f941"},{"pcr_index":6,"pcr_value":"e21b703ee69c77476bccb43ec0336a9a1b2914b378944f7b00a10214ca8fea93"},{"pcr_index":7,"pcr_value":"e21b703ee69c77476bccb43ec0336a9a1b2914b378944f7b00a10214ca8fea93"}]},"logs":[{"log_type":"TcgEventLog","log_data":"AAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACEAAABTcGVjIElEIEV2ZW50MDMAAAAAAAACAgIBAAAACwAgAAABAAAABgAAAAEAAAALAKUQl5WfT2u4kWVrAbSwFzFjH47hjONtvzakrA+LlDtEHAAAAAEAAAAUAAAAP56Gs4+udkBZNHIbDv9fS+P5kjUCAAAABQAAAAEAAAALAM6xuxF9FKN/B+I8luWAcp4/zBL3SZFbvcjtrfwg4hrPFQAAAFN0YXJ0IE9wdGlvbiBST00gU2NhbgIAAAAGAAAAAQAAAAsAQsNfc9yoYaT2lBuIXP60QTs/V44tYaVIrSbo/STF/vIgAAAABwAAABgAAAAAAAAAh/vA7LHufU2MjIjH2KL7Psj5nqUCAAAABgAAAAEAAAALAEhCcfsTwdRfjq1K1720aNnRAZTpRdNnOcSJR3WojkSDIAAAAAcAAAAYAAAAAAAAAKF3/pUe76cFAoGMcB9F4l1zCtadAgAAAAYAAAABAAAACwDoVl9LfTKvNQynp1Xau/dtFxpE0UeBPIM0P3be9myybSAAAAAHAAAAGAAAAAAAAABnDJzHm0hZlEcF7s5xDcMyGIt5tAQAAAAFAAAAAQAAAAsAehmlpW/SxKnJ29jHRTfzTQvEQqSlKMNvtEo8zYWN8SsPAAAAQ2FsbGluZyBJTlQgMTloAAAAAAQAAAABAAAACwCtlRMbwLeZwLGvR3+xT88mpqn3YHnki/CQrLfoNnv9DgQAAAD/////AQAAAAQAAAABAAAACwCtlRMbwLeZwLGvR3+xT88mpqn3YHnki/CQrLfoNnv9DgQAAAD/////AgAAAAQAAAABAAAACwCtlRMbwLeZwLGvR3+xT88mpqn3YHnki/CQrLfoNnv9DgQAAAD/////AwAAAAQAAAABAAAACwCtlRMbwLeZwLGvR3+xT88mpqn3YHnki/CQrLfoNnv9DgQAAAD/////BAAAAAQAAAABAAAACwCtlRMbwLeZwLGvR3+xT88mpqn3YHnki/CQrLfoNnv9DgQAAAD/////BQAAAAQAAAABAAAACwCtlRMbwLeZwLGvR3+xT88mpqn3YHnki/CQrLfoNnv9DgQAAAD/////BgAAAAQAAAABAAAACwCtlRMbwLeZwLGvR3+xT88mpqn3YHnki/CQrLfoNnv9DgQAAAD/////BwAAAAQAAAABAAAACwCtlRMbwLeZwLGvR3+xT88mpqn3YHnki/CQrLfoNnv9DgQAAAD/////BAAAAAUAAAABAAAACwCTSuIFkroG1wKWsgvJKnBsFgwLvBFfJlCJS3Y3UhxlOhwAAABCb290aW5nIEJDViBkZXZpY2UgODBoIChIREQpBAAAAA0AAAABAAAACwCfj8pNuhjuU9V1PHZiqzy9cTY3G9yjOqzfC6pJyRPlLAMAAABNQlIFAAAADgAAAAEAAAALAANFsCy5TpPzbQ926+9+lu9QuPhi1KuuUrcygr0MMilREwAAAE1CUiBQQVJUSVRJT05fVEFCTEU="}]}}]}]
}
 ```

## 3. Service API

### 3.1 Reference Value Management

#### 3.1.1 Add Reference Value
**Description**: Add reference value

**Request Method**: `POST /global-trust-authority/service/v1/ref_value`

##### Request Parameters
| Field         | Sub-field | Type    | Required | parameter constraint    | Description                                             |
|---------------|-----------|---------|----------|-------------------------|---------------------------------------------------------|
| name          |           | string  | Yes      | Length 1-255 characters | Reference value name                                    |
| description   |           | string  | No       | Length 0-512 characters | Reference value description                             |
| attester_type |           | string  | Yes      | only support tpm_ima    | Applicable challenge plugin type                        |
| content       |           | string  | Yes      | Maximum length 10M      | Reference value content                                 |
| is_default    |           | boolean | No       | true or false           | Whether it's default reference value, defaults to false |

##### Response Parameters
| Field     | Sub-field | Type   | Required                   | Description                    |
|-----------|-----------|--------|----------------------------|--------------------------------|
| message   |           | string | Yes for failed request     | Error message                  |
| ref_value |           | object | Yes for successful request | Reference value information    |
|           | id        | string | Yes                        | Reference value ID             |
|           | name      | string | Yes                        | Reference value name           |
|           | version   | string | Yes                        | Reference value version number |

##### Example of request

###### request body

```
{
    "name": "test",
    "description": "test",
    "attester_type": "tpm_ima",
    "is_default":true,
    "content": "xxxx"
}
```

###### response body

 ```
{
    "ref_value": {
        "id": "7255326052342740548",
        "version": "1",
        "name": "test"
    }
}
 ```



#### 3.1.2 Update Reference Value

**Description**: Update Reference Value

**Request Method**: `PUT /global-trust-authority/service/v1/ref_value`

##### Request Parameters
| Field         | Sub-field | Type    | Required | parameter constraint    | Description                                                     |
|---------------|-----------|---------|----------|-------------------------|-----------------------------------------------------------------|
| id            |           | string  | Yes      | Length 1-32 characters  | Reference value ID                                              |
| name          |           | string  | No       | Length 1-255 characters | Reference value name, directly overwrites when name is the same |
| description   |           | string  | No       | Length 0-512 characters | Reference value description                                     |
| content       |           | string  | No       | Maximum length 10M      | Reference value content                                         |
| is_default    |           | boolean | No       | true or false           | Whether it's default Reference value, defaults to false         |
| attester_type |           | string  | No       | only support tpm_ima    | Applicable challenge plugin type                                |

##### Response Parameters
| Field     | Sub-field | Type   | Required                   | Description                           |
|-----------|-----------|--------|----------------------------|---------------------------------------|
| message   |           | string | Yes for failed request     | Error message                         |
| ref_value |           | object | Yes for successful request | Reference value information           |
|           | id        | string | Yes                        | Reference value ID                    |
|           | name      | string | Yes                        | Reference value name                  |
|           | version   | string | Yes                        | Reference value update version number |

##### Example of request

###### request body

```
{
    "id": "7255326052342740548",
    "name": "test",
    "description": "test_description",
    "is_default":true,
    "content": "xxxx"
}
```

###### response body

 ```
{
    "ref_value": {
        "id": "7255326052342740548",
        "version": "2",
        "name": "test"
    }
}
 ```

#### 3.1.3 Query Reference Value

**Description**: Query Reference Value

**Request Method**: `GET /global-trust-authority/service/v1/ref_value`

##### Request Parameters
| Field         | Sub-field | Type           | Required | parameter constraint   | Description                                 |
|---------------|-----------|----------------|----------|------------------------|---------------------------------------------|
| attester_type |           | string         | No       | tpm_ima                | Query reference value for specified purpose |
| ids           |           | List of String | No       | Length 1-32 characters | Reference value name, if empty, input 10    |

##### Response Parameters
| Field      | Sub-field     | Type            | Required                   | Description                                             |
|------------|---------------|-----------------|----------------------------|---------------------------------------------------------|
| message    |               | string          | Yes for failed request     | Error message                                           |
| ref_values |               | list of objects | Yes for successful request | Reference value information                             |
|            | id            | string          | Yes                        | Reference value ID                                      |
|            | name          | string          | No                         | Reference value name                                    |
|            | uid           | string          | Yes                        | User ID                                                 |
|            | description   | string          | No                         | Reference value description                             |
|            | content       | string          | No                         | Reference value content                                 |
|            | attester_type | string          | Yes                        | Applicable challenge plugin type                        |
|            | is_default    | boolean         | No                         | Whether it's default reference value, defaults to false |
|            | version       | int             | No                         | Reference value version                                 |
|            | create_time   | Long            | Yes                        | Creation time                                           |
|            | update_time   | Long            | Yes                        | Update time                                             |

> Note: When querying with ids, returns all fields of entries filtered by id; without ids, only returns required fields like id, name, version, etc., does not return specific content (entries filtered by type, if type not filled returns all for that user)

##### Example of request

###### request url

```
http(s)://ip:port/global-trust-authority/service/v1/refvalue?ids=2b0ead4b-6a15-4239-bf68-b1413df538bb
```

###### response body

 ```
{
    "ref_value": [
        {
            "id": "2b0ead4b-6a15-4239-bf68-b1413df538bb",
            "name": "test_refvalue",
            "description": "This is Test",
            "content": "xxxx",
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

#### 3.1.4 Delete Reference Value

**Description**: Delete reference value

**Request Method**: `DELETE /global-trust-authority/service/v1/ref_value`

##### Request Parameters
| Field         | Sub-field | Type           | Required | parameter constraint   | Description          |
|---------------|-----------|----------------|----------|------------------------|----------------------|
| ids           |           | List of String | No       | Length 1-32 characters | Reference value IDs  |
| attester_type |           | string         | No       | tpm_ima                | Reference value type |
| delete_type   |           | string         | Yes      | id, type, all          | Delete Type          |

##### Response Parameters
| Field   | Type   | Required               | Description   |
|---------|--------|------------------------|---------------|
| message | string | Yes for failed request | Error message |

##### Example of request

###### request body

```
{
    "delete_type": "ids",
    "ids": ["8710919450846562689"]
}
```

###### response body

 ```
empty
 ```

### 3.2 Certificate Management

#### 3.2.1 Add Certificate
**Description**: Add certificate

**Request Method**: `POST /global-trust-authority/service/v1/cert`

##### Request Parameters
| Field       | Sub-field | Type           | Required | parameter constraint                 | Description                                                             |
|-------------|-----------|----------------|----------|--------------------------------------|-------------------------------------------------------------------------|
| name        |           | string         | Yes      | Length 1-255 characters              | Certificate name                                                        |
| description |           | string         | No       | Length 0-512 characters              | Description                                                             |
| type        |           | List of String | Yes      | refvalue/policy/tpm_boot/tpm_ima/crl | Certificate type, supported enums: refvalue/policy/tpm_boot/tpm_ima/crl |
| content     |           | string         | No       |                                      | Certificate content                                                     |
| is_default  |           | boolean        | No       | true false                           | Whether it's default certificate, defaults to false                     |
| crl_content |           | string         | No       |                                      | Certificate revocation list                                             |

##### Response Parameters
| Field   | Sub-field | Type   | Required                   | Description                      |
|---------|-----------|--------|----------------------------|----------------------------------|
| message |           | string | Yes for failed request     | Error message                    |
| cert    |           | object | Yes for successful request | Certificate                      |
|         | cert_id   | string | Yes                        | Certificate ID                   |
|         | cert_name | string | Yes                        | Certificate name                 |
|         | version   | string | Yes                        | Certificate version number       |
| crl     |           | object | Yes for successful request |                                  |
|         | crl_id    | string | Yes                        | Certificate revocation list id   |
|         | crl_name  | string | Yes                        | Certificate revocation list name |

##### Example of request

###### insert cert request body

```
{
	"name": "root.crt",
	"type": ["tpm_ima", "tpm_boot"],
	"content": "-----BEGIN CERTIFICATE-----\nxxxxx\n-----END CERTIFICATE-----",
}
```

###### insert cert response body

 ```
{
    "cert": {
        "cert_id": "4740ac7fb9c659e5a1cafad301e1ed00",
        "cert_name": "root.crt.refvalue",
        "version": 1
    }
}
 ```

###### insert crl request body

```
{
	"name": "crl.pem",
	"type": ["crl"],
	"crl_content": "-----BEGIN X509 CRL-----\nxxxxx\n-----END X509 CRL-----"
}
```

###### insert crl response body

 ```
{
    "crl": {
        "crl_id": "11398858-cc4b-49f8-8e6e-b98c82aaf496",
        "crl_name": "crl.pem"
    }
}
 ```

#### 3.2.2 Update Certificate

**Description**: Update certificate

**Request Method**: `PUT /global-trust-authority/service/v1/cert`

##### Request Parameters
| Field       | Type           | Required | parameter constraint                 | Description                                                    |
|-------------|----------------|----------|--------------------------------------|----------------------------------------------------------------|
| id          | string         | Yes      | Length 1-32 characters               | Certificate ID                                                 |
| name        | string         | No       | Length 1-255 characters              | Certificate name                                               |
| description | string         | No       | Length 0-512 characters              | Description                                                    |
| type        | List of String | No       | refvalue/policy/tpm_boot/tpm_ima/crl | Certificate type, range: {attester_type}, "policy", "refvalue" |
| is_default  | boolean        | No       | true or false                        | Whether it's default certificate, defaults to false            |

##### Response Parameters
| Field   | Sub-field | Type   | Required                   | Description                       |
|---------|-----------|--------|----------------------------|-----------------------------------|
| message |           | string | Yes for failed request     | Error message                     |
| cert    |           | object | Yes for successful request |                                   |
|         | cert_id   | string | Yes                        | Certificate ID                    |
|         | cert_name | string | Yes                        | Certificate name                  |
|         | version   | string | Yes                        | Certificate update version number |

##### Example of request

###### request body

```
{
	"name": "root.crt.refvalue",
	"type": ["tpm_ima", "tpm_boot"],
	"is_default": true,
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

**Request Method**: `GET /global-trust-authority/service/v1/cert`

##### Request Parameters
Note: To query revoked certificates, type must specify crl.

| Field     | Sub-field | Type           | Required | parameter constraint                 | Description                             |
|-----------|-----------|----------------|----------|--------------------------------------|-----------------------------------------|
| cert_type |           | string         | No       | refvalue/policy/tpm_boot/tpm_ima/crl | Query certificate for specified purpose |
| ids       |           | List of String | No       |                                      | Certificate ID, maximum 100             |

##### Response Parameters
| Field   | Sub-field           | Type           | Required                   | Description                                              |
|---------|---------------------|----------------|----------------------------|----------------------------------------------------------|
| message |                     | string         | Yes for failed request     | Error message                                            |
| certs   |                     | List of Object | Yes for successful request | Certificate information                                  |
|         | cert_id             | string         | Yes                        | Certificate ID                                           |
|         | cert_name           | string         | Yes                        | Certificate name                                         |
|         | description         | string         | No                         | Certificate description                                  |
|         | content             | string         | No                         | Certificate content                                      |
|         | cert_type           | List of String | No                         | Certificate purpose                                      |
|         | is_default          | boolean        | No                         | Whether it's default certificate                         |
|         | version             | int            | Yes                        | Certificate version                                      |
|         | create_time         | long           | No                         | Creation timestamp                                       |
|         | update_time         | long           | No                         | Update timestamp                                         |
|         | valid_code          | int            | No                         | 0-Normal; 1-Signature verification failed; 2-Revoked     |
|         | cert_revoked_date   | long           | No                         | Certificate revocation time, optional when type is crl   |
|         | cert_revoked_reason | string         | No                         | Certificate revocation reason, optional when type is crl |
| crls    |                     | List of Object | Yes for successful request | Certificate revocation list information                  |
|         | crl_id              | string         | Yes                        | Certificate revocation list ID                           |
|         | crl_name            | string         | Yes                        | Certificate revocation list name                         |
|         | crl_content         | string         | Yes                        | Certificate revocation list content                      |

> Note: When querying with ids, returns all fields of entries filtered by id; without ids, only returns required fields like id, name, version, etc., does not return specific content (entries filtered by type, if type not filled returns all for that user)


##### Example of request

###### query cert request url

```
http(s)://ip:port/global-trust-authority/service/v1/cert?ids=4740ac7fb9c659e5a1cafad301e1ed00
```

###### query cert response body

 ```
{
  "certs": [
    {
      "cert_id": "4740ac7fb9c659e5a1cafad301e1ed00",
      "cert_name": "root.crt.refvalue",
      "content": "-----BEGIN CERTIFICATE-----\nxxxxx\n-----END CERTIFICATE-----",
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

###### query crl request url

```
http(s)://ip:port/global-trust-authority/service/v1/cert?cert_type=crl
```

###### query crl response body

 ```
{
    "crls": [
        {
            "crl_id": "3ca52323-aa6a-4e70-af1f-46f015630d77",
            "crl_name": "crl.pem",
            "crl_content": "-----BEGIN X509 CRL-----\nxxxxx\n-----END X509 CRL-----"
        }
    ]
}
 ```

#### 3.2.4 Delete Certificate

**Description**: Delete certificate

**Request Method**: `DELETE /global-trust-authority/service/v1/cert`

##### Request Parameters
Note: To delete revoked certificates, type must specify crl.

| Field       | Sub-field | Type           | Required | parameter constraint                 | Description                                                                    |
|-------------|-----------|----------------|----------|--------------------------------------|--------------------------------------------------------------------------------|
| delete_type |           | string         | Yes      | "id""type""all"                      | Delete type "id""type""all", When the type is crl, there is no need to pass it |
| ids         |           | List of String | No       | Maximum 10 ids                       | Certificate ID list                                                            |
| type        |           | string         | No       | refvalue/policy/tpm_boot/tpm_ima/crl | Certificate type, refvalue/policy/tpm_boot/tpm_ima/crl                         |

##### Response Parameters
| Field   | Type   | Required               | Description   |
|---------|--------|------------------------|---------------|
| message | string | Yes for failed request | Error message |

###### delete cert request body

```
{
	"delete_type": "id",
	"ids": ["9acc144ed3515b1a84a4e00bccaeb4e2"]
}
```

###### delete crl request body

```
{
	"type": "crl",
	"ids": ["7b7462bd-7187-4cb9-a392-14f0e5fa8656"]
}
```

### 3.3 Challenge Related

#### 3.3.1 Request Nonce
**Description**: Request nonce

**Request Method**: `POST /global-trust-authority/service/v1/challenge`

##### Request Parameters
| Field         | Type           | Required | parameter constraint   | Description                                        | Note                               |
|---------------|----------------|----------|------------------------|----------------------------------------------------|------------------------------------|
| agent_version | string         | No       | Length 1-50 characters | Client version number                              | Format is x.x.x, e.g., 1.0.0       |
| attester_type | list of string | Yes      | "tpm_boot","tpm_ima"   | Plugin type, server returns error if not supported | Only supports "tpm_boot","tpm_ima" |

##### Response Parameters
| Field           | Sub-field | Type   | Required                   | Description       | Note                                          |
| --------------- | --------- | ------ | -------------------------- | ----------------- | --------------------------------------------- |
| service_version |           | string | Yes                        | Server version    | Format is x.x.x, e.g., 1.0.0                  |
| message         |           | string | Yes for failed request     | Error message     | Maximum length 1024 bytes                     |
| nonce           |           | object | Yes for successful request | Nonce information |                                               |
|                 | iat       | long   | Yes                        | Issue time        | Maximum uint64                                |
|                 | value     | string | Yes                        | Nonce value       | 64~1024BYTE, base64 encoded                   |
|                 | signature | string | Yes                        | Signature value   | Not less than 64BYTE, default BASE64 encoding |

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

**Request Method**: `POST /global-trust-authority/service/v1/attest`

##### Request Parameters
| Field         | Sub-field     | Second-level Sub-field | Type            | Required | parameter constraint    | Description                                                  |
| ------------- | ------------- | ---------------------- | --------------- | -------- | ----------------------- | ------------------------------------------------------------ |
| agent_version |               |                        | string          | No       | Length 1-50 characters  | Client version number                                        |
| nonce_type    |               |                        | string          | No       |                         | ignore/user/verifier (default value) corresponds to not verifying nonce, using user nonce, using verifier-generated nonce |
| user_nonce    |               |                        | string          | No       |                         | Filled when nonce_type is user, 1~1024BYTE, base64 encoded   |
| measurements  |               |                        | list of objects | Yes      |                         | Measurement data                                             |
|               | node_id       |                        | string          | No       | Length 1-255 characters | Node ID, corresponds to uied, recommended 32~128 characters, based on actual device |
|               | nonce         |                        | object          | No       |                         | Nonce object                                                 |
|               |               | iat                    | long            | No       |                         | Issue time                                                   |
|               |               | value                  | string          | Yes      |                         | Nonce value                                                  |
|               |               | signature              | string          | No       |                         | Signature value                                              |
|               | attester_data |                        | object          | No       |                         | User-defined data to be passed through, must be placed in token as-is |
|               | evidences     |                        | list of objects | Yes      |                         | Challenge report                                             |
|               |               | attester_type          | string          | Yes      |                         | Challenge type, see attester_type specification              |
|               |               | evidence               | object          | Yes      |                         | Specific evidence                                            |
|               |               | policy_ids             | list of string  | No       | Length 1-36 characters  | Policy ID list to verify, maximum 10                         |

##### Response Parameters
| Field           | Sub-field | Type            | Required                   | Description                                                                               |
|-----------------|-----------|-----------------|----------------------------|-------------------------------------------------------------------------------------------|
| service_version |           | string          | Yes                        | Server version number, format is x.x.x, e.g., 1.0.0                                       |
| message         |           | string          | Yes for failed request     | Error message, maximum 1024 characters                                                    |
| tokens          |           | list of objects | Yes for successful request |                                                                                           |
|                 | node_id   | string          | No                         | Node ID, not corresponding to uied, recommended 32~128 characters, based on actual device |
|                 | token     | string          | Yes                        | JWT format object, see token structure                                                    |

##### Token Object Structure
| Field Location | Field            | Sub-field                 | Second-level Sub-field | Type           | Required | Description                                                  | Filled By                 |
| -------------- | ---------------- | ------------------------- | ---------------------- | -------------- | -------- | ------------------------------------------------------------ | ------------------------- |
| header         | alg              |                           |                        | string         | Yes      | Token signature algorithm                                    | Token generation module   |
| header         | jku              |                           |                        | string         | No       | JSON Web Key Set URI. URL containing JSON-encoded public token signing keys identified by kid. Retrieved based on configuration | Token generation module   |
| header         | kid              |                           |                        | string         | No       | Signature key ID, retrieved based on configuration           | Token generation module   |
| header         | typ              |                           |                        | string         | Yes      | Token type, fixed as JWT                                     | Token generation module   |
| body           | iat              |                           |                        | number         | Yes      | Issue time                                                   | Token generation module   |
| body           | exp              |                           |                        | number         | Yes      | Expiration time                                              | Token generation module   |
| body           | iss              |                           |                        | string         | No       | Issuer                                                       | Token generation module   |
| body           | jti              |                           |                        | string         | Yes      | JWT identifier                                               | Token generation module   |
| body           | ver              |                           |                        | string         | Yes      | Token version                                                | Token generation module   |
| body           | nbf              |                           |                        | string         | No       | Not before time                                              | Token generation module   |
| body           | eat_profile      |                           |                        | string         | Yes      | URL, EAT content description website, defaults to code repository | Token generation module   |
| body           | intuse           |                           |                        | string         | No       | Expected usage                                               | Challenge response module |
| body           | dbgstat          |                           |                        | object         | No       | Debug status                                                 | Challenge response module |
| body           | ueid             |                           |                        | string         | No       | Device unique identifier (taken from certificate)            | Challenge response module |
| body           | verifier_id      |                           |                        | string         | No       | Verifier ID (consider container ID?)                         | Challenge response module |
| body           | status           |                           |                        | string         | Yes      | Overall verification status, pass/fail                       | Challenge response module |
| body           | eat_nonce        |                           |                        | string         | No       | Nonce value, not filled for user_nonce and ignore_nonce      | Challenge response module |
| body           | attester_data    |                           |                        | object         | No       | User-defined information                                     | Challenge response module |
| body           | ${attester_type} |                           |                        | object         | Yes      | Verification result corresponding to attester_type           | Challenge response module |
|                |                  | attestation_status        |                        | string         | Yes      | Verification status corresponding to attester_type, pass/fail | Challenge response module |
|                |                  | evidence flattened fields |                        | object         | No       | Evidence uploaded by attester, e.g., pcr value; generated according to default policy | Challenge response module |
|                |                  | policy_info               |                        | list of object | Yes      | Policy information                                           | Challenge response module |
|                |                  |                           | appraisal_policy_id    | string         | Yes      | Applied policy ID                                            | Challenge response module |
|                |                  |                           | policy_version         | string         | Yes      | Policy version                                               | Challenge response module |
|                |                  |                           | attestation_valid      | boolean        | Yes      | Whether policy matching passed                               | Challenge response module |
|                |                  |                           | custom_data            | object         | No       | Policy-defined output                                        | Challenge response module |

##### Example of request

###### request body

```
{
    "agent_version": "0.1.0",
    "nonce_type": "ignore",
    "measurements": [
        {
            "node_id": "TPM AK",
            "evidences": [
                {
                    "attester_type": "tpm_boot",
                    "evidence": {
                        "ak_cert": "-----BEGIN CERTIFICATE-----\nxxxxx\n-----END CERTIFICATE-----",
                        "quote": {
                            "quote_data": "/1RDR4AYACIAC6dK2j3UWnqCmI9se9Itpmwo+GB2VAKRbS/VU2Iczqe1AAAAAAAAqTW9RAAAABsAAAAAASAZECMAFjY2AAAAAQALA/8AAAAg5o1U6DZkv/nir57+pL262PuxVPACzZgfDbc9i/cCaLc=",
                            "signature": "ABQACwEAB2a8RxbLV10KdV4rBaKvYZBxBrknL3E6flmOs1UCEz3U8v81RNWDxq5y7q301HsaF6HrP7TQWVq/5dX56RAgEtSxgiiKSIbR7S0SSaKMjHWKGHf+BeehZIaaxubl9rhlSVqBd+/K9rbHP3ADFJI8q1Ikg/6oAeYHsw1yZGinMocOF1+feMXBxri8YsEnX8a8/1tY8mAH34fhLf1OI8BjBnDmZG1kHQg930lJLcxB5uVNtEZd9Hcq/UMn9Hq+GQ6eVcpS4KgG9KwePnk96i/pjDTeDPk6VsZbYiXZPn9wQrAnwzDJX+7nTQj8QEOat49X7A57sAWHX9zRQV/mkVmvrw=="
                        },
                        "pcrs": {
                            "hash_alg": "sha256",
                            "pcr_values": [
                                {
                                    "pcr_index": 0,
                                    "pcr_value": "e21b703ee69c77476bccb43ec0336a9a1b2914b378944f7b00a10214ca8fea93"
                                },
                                {
                                    "pcr_index": 1,
                                    "pcr_value": "a32bf8bf329907dc2b4839ff3c61b456a9856d12110f49d490df33baf189340e"
                                },
                                {
                                    "pcr_index": 2,
                                    "pcr_value": "a9d5bdf3b0b034a434ef3adde2d5cb0a7533803f97f8889f1174ab60bd4dcb70"
                                },
                                {
                                    "pcr_index": 3,
                                    "pcr_value": "e21b703ee69c77476bccb43ec0336a9a1b2914b378944f7b00a10214ca8fea93"
                                },
                                {
                                    "pcr_index": 4,
                                    "pcr_value": "fce7f1083082b16cfe2b085dd7858bb11a37c09b78e36c79e5a2fd529353c4e2"
                                },
                                {
                                    "pcr_index": 5,
                                    "pcr_value": "8edde912699ceddddc7d9a3d7ee44a8b1b1910815692def6c9e637e2b939f941"
                                },
                                {
                                    "pcr_index": 6,
                                    "pcr_value": "e21b703ee69c77476bccb43ec0336a9a1b2914b378944f7b00a10214ca8fea93"
                                },
                                {
                                    "pcr_index": 7,
                                    "pcr_value": "e21b703ee69c77476bccb43ec0336a9a1b2914b378944f7b00a10214ca8fea93"
                                }
                            ]
                        },
                        "logs": [
                            {
                                "log_type": "TcgEventLog",
                                "log_data": "xxxxx"
                            }
                        ]
                    }
                }
            ]
        }
    ]
}
```

###### response body

 ```
{
    "service_version": "1.0",
    "tokens": [
        {
            "node_id": "TPM AK",
            "token": "xxxxxx"
        }
    ]
}
 ```

### 3.4 Policy Management

#### 3.4.1 Add Policy
**Description**: Add policy

**Request Method**: `POST /global-trust-authority/service/v1/policy`

##### Request Parameters
| Field         | Type           | Required | parameter constraint                           | Description                                                                     |
|---------------|----------------|----------|------------------------------------------------|---------------------------------------------------------------------------------|
| id            | string         | No       | length 1~36 characters                         | Policy ID, length  if filled, use it as policy ID, if not filled, generate UUID |
| name          | string         | Yes      | length 1~255 characters                        | Policy name                                                                     |
| description   | string         | No       | length not exceeding 512 characters            | Policy description                                                              |
| attester_type | list of string | Yes      | Each element character length 1~255 characters | Applicable challenge plugin type, see previous specification                    |
| content_type  | string         | Yes      | jwt or text                                    | jwt/text (corresponding to unsigned case)                                       |
| content       | string         | Yes      | Default maximum 500kb                          | Policy content, maximum 500KB before encoding                                   |
| is_default    | boolean        | No       | true or false                                  | Whether it's default policy, defaults to false                                  |

When content_type is jwt, jwt content:

| Field Location | Field  | Type   | Required | Description               |
|----------------|--------|--------|----------|---------------------------|
| header         | alg    | string | Yes      | Token signature algorithm |
| header         | kid    | string | No       | Public key ID             |
| body           | policy | string | Yes      | Policy content            |

##### Response Parameters
| Field   | Sub-field | Type   | Required                   | Description                                             |
|---------|-----------|--------|----------------------------|---------------------------------------------------------|
| message |           | string | Yes for failed request     | Error message                                           |
| policy  |           | object | Yes for successful request | Policy information                                      |
|         | id        | string | Yes                        | Policy ID, UUID, 16byte, 36 characters with hyphen      |
|         | name      | string | Yes                        | Policy name                                             |
|         | version   | u32    | Yes                        | Policy version, created as 1, increments by 1 on update |

##### Example of request

###### request body

```
{
    "name": "test_policy",
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
    "policy": {
        "id": "349fb201-311d-4cd9-9ef5-a7b9f33a5ecf",
        "name": "test_policy",
        "version": 1
    }
}
 ```

#### 3.4.2 Update Policy

**Description**: Update policy

**Request Method**: `PUT /global-trust-authority/service/v1/policy`

##### Request Parameters
| Field         | Type           | Required | parameter constraint                           | Description                                    |
|---------------|----------------|----------|------------------------------------------------|------------------------------------------------|
| id            | string         | Yes      | length 1~36 characters                         | Policy ID                                      |
| name          | string         | No       | length 1~255 characters                        | Policy name                                    |
| description   | string         | No       | length 0~512 characters                        | Policy description                             |
| attester_type | list of string | No       | Each element character length 1~255 characters | Applicable challenge plugin type               |
| content_type  | string         | No       | jwt or text                                    | jwt/text (corresponding to unsigned case)      |
| content       | string         | No       | Default maximum 500kb                          | Policy content                                 |
| is_default    | boolean        | No       | true or false                                  | Whether it's default policy, defaults to false |

##### Response Parameters
| Field    | Sub-field | Type   | Required                   | Description        |
|----------|-----------|--------|----------------------------|--------------------|
| message  |           | string | Yes for failed request     | Error message      |
| policies |           | string | Yes for successful request | Policy information |
|          | id        | string | Yes                        | Policy ID          |
|          | name      | string | Yes                        | Policy name        |
|          | version   | u32    | Yes                        | Policy version     |

##### Example of request

###### request body

```
{
    "id": "349fb201-311d-4cd9-9ef5-a7b9f33a5ecf",
    "name": "Test",
    "description": "123",
    "content": "cGFja2FnZSBkaWdlc3RfdmVyaWZpY2F0aW9uCgppbXBvcnQgZnV0dXJlLmtleXdvcmRzLmlmCmltcG9ydCBmdXR1cmUua2V5d29yZHMuaW4KCiMgRGVmYXVsdCByZXN1bHQgaXMgcGFzcwpkZWZhdWx0IHJlc3VsdCA9IHsic3RhdHVzIjogInBhc3MifQoKIyBNYWluIHJ1bGUgdG8gZXZhbHVhdGUgdGhlIGlucHV0IGFnYWluc3QgYmFzZWxpbmUKcmVzdWx0ID0gb3V0cHV0IGlmIHsKICAgICMgR2V0IGlucHV0IGRhdGEKICAgIGlucHV0X2RhdGEgOj0gaW5wdXQKICAgIAogICAgIyBFeHRyYWN0IGFsbCBTSEEyNTYgZGlnZXN0cyBmcm9tIGV2ZW50cwogICAgZGlnZXN0cyA6PSBbZGlnZXN0IHwKICAgICAgICBldmVudCA6PSBpbnB1dF9kYXRhLmV2ZW50c1tfXQogICAgICAgIGRpZ2VzdF9vYmogOj0gZXZlbnQuRGlnZXN0c1tfXQogICAgICAgIGRpZ2VzdF9vYmouQWxnb3JpdGhtSWQgPT0gInNoYTI1NiIKICAgICAgICBkaWdlc3QgOj0gZGlnZXN0X29iai5EaWdlc3QKICAgIF0KICAgIAogICAgIyBGaW5kIG1pc3NpbmcgZGlnZXN0cyB1c2luZyB0aGUgUnVzdCBmdW5jdGlvbgogICAgIyBUaGlzIGZ1bmN0aW9uIG5vdyByZWFkcyB0aGUgYmFzZWxpbmUgZnJvbSBhIGZpbGUgZGlyZWN0bHkKICAgIG1pc3NpbmdfZGlnZXN0cyA6PSBmaW5kX21pc3NpbmdfZGlnZXN0cyhkaWdlc3RzKQogICAgCiAgICAjIENyZWF0ZSBtYXBwaW5nIG9mIG1pc3NpbmcgZGlnZXN0cyB0byBldmVudCBudW1iZXJzCiAgICBtaXNzaW5nX2V2ZW50cyA6PSB7ZGlnZXN0OiB7ImV2ZW50X251bWJlciI6IGV2ZW50LkV2ZW50TnVtfSB8CiAgICAgICAgZXZlbnQgOj0gaW5wdXRfZGF0YS5ldmVudHNbX10KICAgICAgICBkaWdlc3Rfb2JqIDo9IGV2ZW50LkRpZ2VzdHNbX10KICAgICAgICBkaWdlc3Rfb2JqLkFsZ29yaXRobUlkID09ICJzaGEyNTYiCiAgICAgICAgZGlnZXN0IDo9IGRpZ2VzdF9vYmouRGlnZXN0CiAgICAgICAgZGlnZXN0IGluIG9iamVjdC5rZXlzKG1pc3NpbmdfZGlnZXN0cykKICAgIH0KICAgIAogICAgIyBEZXRlcm1pbmUgaWYgYW55IGRpZ2VzdHMgYXJlIG1pc3NpbmcKICAgIGNvdW50KG9iamVjdC5rZXlzKG1pc3NpbmdfZGlnZXN0cykpID4gMAogICAgCiAgICAjIENyZWF0ZSBvdXRwdXQgd2l0aCBmYWlsdXJlIHN0YXR1cyBhbmQgbWlzc2luZyBkaWdlc3RzCiAgICBvdXRwdXQgOj0gewogICAgICAgICJzdGF0dXMiOiAiZmFpbCIsCiAgICAgICAgIm1pc3NpbmdfZGlnZXN0cyI6IG1pc3NpbmdfZXZlbnRzCiAgICB9Cn0=",
    "content_type": "text"
}
```

###### response body

 ```
{
    "policy": {
        "id": "349fb201-311d-4cd9-9ef5-a7b9f33a5ecf",
        "name": "test_policy",
        "version": 2
    }
}
 ```

#### 3.4.3 Delete Policy

**Description**: Delete policy

**Request Method**: `DELETE /global-trust-authority/service/v1/policy`

##### Request Parameters
| Field         | Type           | Required | parameter constraint     | Description                          |
|---------------|----------------|----------|--------------------------|--------------------------------------|
| delete_type   | string         | Yes      | "id""attester_type""all" | Delete type "id""attester_type""all" |
| ids           | List of String | No       | maximum 10               | Policy IDs, maximum 10               |
| attester_type | string         | No       | length 1~255 characters  | Policy type                          |

##### Response Parameters
| Field   | Type   | Required               | Description   |
|---------|--------|------------------------|---------------|
| message | string | Yes for failed request | Error message |

##### Example of request

###### request body

```
{
    "delete_type": "attester_type",
    "attester_type": "tpm_ima"
}
```

###### response body

 ```
empty
 ```

#### 3.4.4 Query Policy
**Description**: Query policy

**Request Method**: `GET /global-trust-authority/service/v1/policy`

##### Request Parameters
| Field         | Type           | Required | Description                                                     |
|---------------|----------------|----------|-----------------------------------------------------------------|
| ids           | List of String | No       | Policy IDs maximum 10, error if exceeding maximum message limit |
| attester_type | string         | No       | Policy type                                                     |

##### Response Parameters
| Field    | Sub-field     | Type            | Required                   | Description                                    |
|----------|---------------|-----------------|----------------------------|------------------------------------------------|
| message  |               | string          | Yes for failed request     | Error message                                  |
| policies |               | list of objects | Yes for successful request | Policy information                             |
|          | id            | string          | Yes                        | Policy ID                                      |
|          | name          | string          | Yes                        | Policy name                                    |
|          | description   | string          | No                         | Policy description                             |
|          | content       | string          | No                         | Policy content                                 |
|          | attester_type | list of string  | No                         | Applicable challenge plugin type               |
|          | is_default    | boolean         | No                         | Whether it's default policy, defaults to false |
|          | valide_code   | u8              | No                         | Signature verification result, 0-pass, 1-fail  |
|          | version       | u64             | No                         | Policy version                                 |
|          | update_time   | u64             | Yes                        | Creation time                                  |

> Note: When querying with ids, returns all fields of entries filtered by id; without ids, only returns required fields like id, name, version, etc., does not return specific content (entries filtered by type, if type not filled returns all for that user)

##### Example of request

###### request url

```
http(s)://ip:port/global-trust-authority/service/v1/policy?ids=2b0ead4b-6a15-4239-bf68-b1413df538bb
```

###### response body

 ```
{
    "policies": [
        {
            "id": "2b0ead4b-6a15-4239-bf68-b1413df538bb",
            "name": "test_policy3891702073167223",
            "description": "This is Test",
            "content": "xxxx",
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

**Request Method**: `POST /global-trust-authority/service/v1/token/verify`

##### Request Parameters
| Field | Type   | Required | Description                      |
|-------|--------|----------|----------------------------------|
| token | string | Yes      | Token to be validated and parsed |

##### Response Parameters
| Field             | Type    | Required                   | Description                                                    |
|-------------------|---------|----------------------------|----------------------------------------------------------------|
| message           | string  | Yes for failed request     | Error message                                                  |
| verification_pass | boolean | Yes for successful request | Whether signature verification passed                          |
| token_body        | object  | No                         | Required when verification passes, returns parsed token body   |
| token_header      | object  | No                         | Required when verification passes, returns parsed token header |


##### Example of request

###### request body

```
{
    "token": "xxxxx"
}
```

###### response body

 ```
{
    "verification_pass": false
}
 ```

### 3.6 register apikey
**Description**: When the request header is empty, to obtain User Id and API Key, when these two parameters are passed in the request header, to update User Id and API Key

**Request Method**: `GET /global-trust-authority/service/v1/register`

##### Request Headers
| Field   | Type   | Required | Description                         |
|---------|--------|----------|-------------------------------------|
| User-Id | string | Yes      | Used to distinguish users           |
| API-Key | string | Yes      | Used to verify the current identity |

##### Response Parameters
| Field   | Type    | Required                   | Description                                                    |
|---------|---------|----------------------------|----------------------------------------------------------------|
| User-Id | string  | Yes for failed request     | Error message                                                  |
| API-Key | boolean | Yes for successful request | Whether signature verification passed                          |

##### Example of request

###### response body

 ```
{
    "User-Id": "xxxxx"
    "API-Key": "xxxxx"
}
 ```
## 4. Key Manager API

### 4.1 Query key
**Description**: Query all the keys of the current key management component

**Request Method**: `GET /v1/vault/get_signing_keys`

#### Request Parameters
None

#### Response Parameters
| Field | Sub-field   | Type   | Required | Description           |
|-------|-------------|--------|----------|-----------------------|
| NSK   |             | string | YES      | key NSK               |
|       | private_key | string | Yes      | key info              |
|       | algorithm   | string | Yes      | Private key algorithm |
|       | encoding    | string | Yes      | Private key format    |
|       | version     | string | Yes      | Private key version   |
| PSK   |             | string | YES      | key PSK               |
|       | private_key | string | Yes      | key info              |
|       | algorithm   | string | Yes      | Private key algorithm |
|       | encoding    | string | Yes      | Private key format    |
|       | version     | string | Yes      | Private key version   |
| TSK   |             | string | YES      | key TSK               |
|       | private_key | string | Yes      | key info              |
|       | algorithm   | string | Yes      | Private key algorithm |
|       | encoding    | string | Yes      | Private key format    |
|       | version     | string | Yes      | Private key version   |