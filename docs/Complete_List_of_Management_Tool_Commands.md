## Certificate Management

```cmd
# Query Certificate Management Command Help
 attestation_cli certificate -h
```

### Insert Certificate

**Command: attestation_cli certificate set**

**Parameters and options:**

| Long Arguement | Short Arguement | Required | Description                                                  |
| -------------- | --------------- | -------- | ------------------------------------------------------------ |
| --name         | -n              | no       | name of the certificate                                      |
| --description  | -d              | no       | description of the certificate                               |
| --cert_type    |                 | yes      | type of the certificate, possible values: policy/refvalue,tpm_boot,tpm_ima,crl |
| --content      |                 | no       | content of the certificate, starting with @ indicates the file path |
| --crl-content  | -c              | no       | certificate revoked list content, starting with @ indicates the file path |
| --is-default   | -i              | no       | is default certificate, default to 'No'                      |

**Usage examples:**

```cmd
#Inquiry Help
sudo attestation_cli certificate set -h

#Insert Certificate
sudo attestation_cli -u "test_01" certificate set \
	--cert-type "policy" "refvalue" \
	--content @/home/test/rsa_2048_certificate.pem

sudo attestation_cli -u "test_01" certificate set \
	--name "new.pem" \
	--cert-type "policy" "refvalue" \
	--content "-----BEGIN CERTIFICATE-----
xxxxx
-----END CERTIFICATE-----"
	
	
#Insert certificate (full version)
sudo attestation_cli -u "test_01" certificate set \
	--name "certificate.pem" \
	--description "This is certificate" \
	--cert-type "policy" "refvalue" \
	--content @/home/test/rsa_2048_certificate.pem \
	--is-default

#Insert the list of revocations
sudo attestation_cli -u "test_01" certificate set \
	--name "crl.pem" \
	--cert-type "crl" \
	--crl-content "-----BEGIN X509 CRL-----
xxxxx
-----END X509 CRL-----"
```

### Delete Certificate

**Command: attestation_cli certificate delete**

**Parameters and options:**

| Long Arguement | Short Arguement | Required | Description                                                  |
| -------------- | --------------- | -------- | ------------------------------------------------------------ |
| --delete-type  | -d              | no       | delete method, possible values: <br />    id (delete by IDs)<br />    type (delete by type)<br />    all (delete all) |
| --ids          | -i              | no       | certificate ids to delete                                    |
| --cert-type    | -c              | no       | type of the certificate to delete                            |

**Usage examples:**

```cmd
#Inquiry Help
 attestation_cli certificate delete -h

#Delete all
sudo attestation_cli -u "test_01" certificate delete \
	--delete-type "all"

#Delete by id
sudo attestation_cli -u "test_01" certificate delete \
	--delete-type "id" \
	--ids "id1" "id2"

#Delete by certificate type
sudo attestation_cli -u "test_01" certificate delete \
	--delete-type "type" \
	--cert-type "policy" 
	
#Delete revoked certificate
sudo attestation_cli -u "test_01" certificate delete \
	--cert-type "crl" \
	--ids "7763f0a1-385a-43b8-84b8-4e4e448de73f"
```

### Update Certificate

**Command: attestation_cli certificate update**

**Parameters and options:**

| Long Arguement | Short Arguement | Required | Description                             |
| -------------- | --------------- | -------- | --------------------------------------- |
| --id           |                 | yes      | ID of the certificate to update         |
| --name         | -n              | no       | name of the certificate                 |
| --description  | -d              | no       | description of the certificate          |
| --cert-type    | -c              | yes      | type of the certificate                 |
| --is-default   | -i              | no       | is default certificate, default to 'No' |

**Usage examples:**

```cmd
#Inquiry Help
 attestation_cli certificate update -h

#Modification of certificates
sudo attestation_cli -u "test_01" certificate update \
	--id "b8481f3e58525f359e12bda53a5779a9" \
	--name "new_name" \
	--description "new_description" \
	--cert-type "policy" "refvalue" \
	--is-default true
	
sudo attestation_cli -u "test_01" certificate update \
	--id "cada113be95d5689a38a465f211bd9bd" \
	--name "new_name.pem" \
	--description "new_description" \
	--cert-type "policy" "refvalue" \
	--is-default true \
	--content "-----BEGIN CERTIFICATE-----
xxxxx
-----END CERTIFICATE-----"

```

### Query Certificate

**Command: attestation_cli certificate get**

**Parameters and options:**

| Long Arguement | Short Arguement | Required | Description                     |
| -------------- | --------------- | -------- | ------------------------------- |
| --ids          | -i              | no       | ID of the certificates to query |
| --cert-type    | -t              | yes      | certificate type to query       |

**Usage examples:**

```cmd
#Inquiry Help
 attestation_cli certificate get -h

#Check all certificates
sudo attestation_cli -u "test_01" certificate get

#Search by certificate type
sudo attestation_cli -u "test_01" certificate get \
	--cert-type "refvalue" 

#Search by certificate id
sudo attestation_cli -u "test_01" certificate get \
	--ids "id1" "id2"
	
# Query Revocation Certificate
sudo attestation_cli -u "test_01" certificate get \
	--cert-type "crl" 
```



## Policy Management

```cmd
#Query Policy Management Command Help
 attestation_cli policy -h
```

### Insert Policy

**Command: attestation_cli policy set**

**Parameters and options:**

| Long Arguement  | Short Arguement | Required | Description                                             |
| --------------- | --------------- | -------- | ------------------------------------------------------- |
| --name          | -n              | no       | name of the policy                                      |
| --description   | -d              | no       | description of the policy                               |
| --attester-type | -a              | yes      | attester type of the policy                             |
| --content-type  |                 | yes      | policy content type, possible values: jwt/text          |
| --content       |                 | yes      | policy content, starting with @ indicates the file path |
| --is-default    | -i              | no       | is default policy, default is 'No'                      |

**Usage examples:**

```cmd
#Inquiry Help
 attestation_cli policy set -h

#Added text type strategy (abbreviated version)
sudo attestation_cli -u "test_01" policy set \
	--name "test_policy{{$number.int}}" \
	--content "package verification

# Extract log_status from first tpm_ima log
log_status = status {
    some i
    logs := input.evidence.logs
    logs[i].log_type == \"tpm_ima\"
    status := logs[i].log_status
}

ref_value_match_status = status {
    some i
    logs := input.evidence.logs
    logs[i].log_type == \"tpm_ima\"
    status := logs[i].ref_value_match_status
}

# Check if pcrs 10 is present in any hash algorithm (sha1, sha256, sha384, sha512)
pcr_present {
    all := {x | x := [10][_] }
    measured := {pcr.pcr_index | pcr := input.evidence.pcrs.pcr_values[_]}
    all_pcrs_subset := all - measured
    count(all_pcrs_subset) == 0
}

# Attestation valid if all conditions met
default attestation_valid = false
attestation_valid {
    log_status == "replay_success"
    ref_value_match_status == "matched"
    pcr_present
}

# Output result
result = {
    \"attestation_valid\": attestation_valid,
    \"custom_data\": {
        \"hash_alg\": input.evidence.pcrs.hash_alg
    }
}

" \
	--attester-type "tpm_ima" "tpm_boot" \
	--content-type "text" 

sudo attestation_cli -u "test_01" policy set \
	--content @/tmp/text_policy.txt \
	--attester-type "tpm_ima" "tpm_boot" \
	--content-type "text" 
		
#add jwt-type strategies (abbreviated version)
sudo attestation_cli -u "test_01" policy set \
	--name "add" \
    --content "xxx" \
	--attester-type "tpm_ima" "tpm_boot" \
	--content-type "jwt" 
	
sudo attestation_cli -u "test_01" policy set \
	--content @/home/test/policy_jwt.txt \
	--attester-type "tpm_ima" "tpm_boot" \
	--content-type "jwt" 

#add strategy (full version)
sudo attestation_cli -u "test_01" policy set \
	--name "digest_verification.rego" \
	--description "This is policy" \
	--attester-type "tpm_ima" "tpm_boot" \
	--content @/home/test/policy_jwt.txt \
	--content-type "jwt" \
	--is-default
```

### Delete Policy

**Command: attestation_cli policy delete**

**Parameters and options:**

| Long Arguement  | Short Arguement | Required | Description                                                  |
| --------------- | --------------- | -------- | ------------------------------------------------------------ |
| --delete-type   | -d              | no       | delete method, possible values: <br />    id (delete by IDs)<br />    type (delete by type)<br />    all (delete all) |
| --ids           | -i              | no       | IDs of the policies to delete                                |
| --attester-type | -t              | no       | attester type of the policy to delete                        |

**Usage examples:**

```cmd
#Inquiry Help
 attestation_cli policy delete -h

#Delete all
sudo attestation_cli -u "test_01" policy delete \
	--delete-type "all"

#Delete by id
sudo attestation_cli -u "test_01" policy delete \
	--delete-type "id" \
	--ids "id1" "id2"

#Delete by plugin type
sudo attestation_cli -u "test_01" policy delete \
	--delete-type "attester_type" \
	--attester-type "tpm_ima" 

```

### Update Policy

**Command: attestation_cli policy update**

**Parameters and options:**

| Long Arguement  | Short Arguement | Required | Description                                             |
| --------------- | --------------- | -------- | ------------------------------------------------------- |
| --id            |                 | yes      | ID of the policy to update                              |
| --name          | -n              | no       | name of the policy                                      |
| --description   | -d              | no       | description of the policy                               |
| --attester-type | -a              | no       | attester type of the policy                             |
| --content-type  |                 | no       | policy content type, possible values: jwt/text          |
| --content       |                 | no       | policy content, starting with @ indicates the file path |
| --is-default    | -i              | no       | is default policy, default is 'No'                      |

**Usage examples:**

```cmd
#Inquiry Help
 attestation_cli policy update -h

#Modification of certificates
sudo attestation_cli -u "test_01" policy update \
	--id "be8c820d-55d3-4645-b54b-fe2cb5f84f81" \
	--name "new_name" \
	--description "new_description" \
	--content @/home/test/policy_jwt.txt \
	--attester-type "tpm_ima" "tpm_boot" \
	--content-type "jwt" \
	--is-default true

```

###  Query Policy

**Command: attestation_cli policy get**

**Parameters and options:**

| Long Arguement  | Short Arguement | Required | Description                      |
| --------------- | --------------- | -------- | -------------------------------- |
| --attester-type | -d              | no       | attester type of policy to query |
| --ids           | -i              | no       | IDs of policies to query         |

**Usage examples:**

```cmd
# Query help
 attestation_cli policy get -h

# Query all policies
sudo attestation_cli -u "test_01" policy get

# Query by policy type
sudo attestation_cli -u "test_01" policy get \
	--attester-type "tpm_ima" 

#Query based on policy type
sudo attestation_cli -u "test_01" policy get \
	--ids "id1" "be8c820d-55d3-4645-b54b-fe2cb5f84f81"

```



## Reference Value Management

```cmd
#Query Baseline Management Command Help
 attestation_cli baseline -h
```

### Insert Reference Value

**Command: attestation_cli baseline set**

**Parameters and options:**

| Long Arguement  | Short Arguement | Required | Description                                                  |
| --------------- | --------------- | -------- | ------------------------------------------------------------ |
| --name          | -n              | no       | name of the reference value                                  |
| --description   | -d              | no       | description of the reference value                           |
| --attester-type | -a              | yes      | attester type of the reference value                         |
| --content       |                 | yes      | reference value content, starting with @ indicates the file path |
| --is-default    | -i              | no       | is default reference value, default is 'No'                  |

**Usage examples:**

```cmd
#Inquiry Help
 attestation_cli baseline set -h

#Additional baselines (abridged version)
sudo attestation_cli -u "test_01" baseline set \
	--content @/home/test/baseline.txt

sudo attestation_cli -u "test_01" baseline set \
	--name "baseline.txt" \
	--content "xxxxx"

#Add strategy (full version)
sudo attestation_cli -u "test_01" baseline set \
	--name "baseline" \
	--description "This is baseline" \
	--attester-type "tpm_ima" \
	--content @/home/test/baseline.txt \
    --is-default
```
### Delete Reference Value

**Command: attestation_cli baseline delete**

**Parameters and options:**

| Long Arguement | Short Arguement | Required | Description                                                  |
| -------------- | --------------- | -------- | ------------------------------------------------------------ |
| --delete-type  | -d              | no       | delete method, possible values: <br />    id (delete by IDs)<br />    type (delete by type)<br />    all (delete all) |
| --ids          | -i              | no       | IDs of the reference value to delete                         |
| --cert-type    | -t              | no       | type of the reference value to delete                        |

**Usage examples:**

```cmd
#Inquiry Help
 attestation_cli baseline delete -h

#Delete all
sudo attestation_cli -u "test_01" baseline delete \
	--delete-type "all"

#Delete by id
sudo attestation_cli -u "test_01" baseline delete \
	--delete-type "id" \
	--ids "id1" "id2"

#Delete by plugin type
sudo attestation_cli -u "test_01" baseline delete \
	--delete-type "type" \
	--attester-type "tpm_ima" 
```
### Update Reference Value

**Command: attestation_cli baseline update**

**Parameters and options:**

| Long Arguement  | Short Arguement | Required | Description                                                  |
| --------------- | --------------- | -------- | ------------------------------------------------------------ |
| --id            |                 | yes      | id of the reference value to update                          |
| --name          | -n              | no       | name of the reference value                                  |
| --description   | -d              | no       | description of the reference value                           |
| --attester-type | -a              | no       | attester type of the reference value                         |
| --content       |                 | no       | reference value content, starting with @ indicates the file path |
| --is-default    | -i              | no       | is default reference value, default is 'No'                  |

**Usage examples:**

```cmd
#Inquiry Help
 attestation_cli baseline update -h

#Modifying the baseline
sudo attestation_cli -u "test_01" baseline update \
	--id "757737811267856835" \
	--name "new_name" \
	--description "new_description" \
	--content @/home/test/baseline.txt \
	--attester-type "tpm_ima" \
	--is-default false
	
sudo attestation_cli -u "test_01" baseline update \
	--id "757737811267856835" \
	--name "new_name" \
	--description "new_description" \
	--content "xxxxx" \
	--attester-type "tpm_ima" \
	--is-default false
```
### Query Reference Value

**Command: attestation_cli baseline query**

**Parameters and options:**

| Long Arguement  | Short Arguement | Required | Description                               |
| --------------- | --------------- | -------- | ----------------------------------------- |
| --attester-type | -d              | no       | attester type of reference value to query |
| --ids           | -i              | no       | IDs of reference value to query           |

**Usage examples:**

```cmd
# Query help
 attestation_cli baseline get -h

#Query all baselines
sudo attestation_cli -u "test_01" baseline get

#Query by baseline type
sudo attestation_cli -u "test_01" baseline get \
	--attester-type "tpm_ima" 

#Query based on baseline id
sudo attestation_cli -u "test_01" baseline get \
	--ids "id1" "id2"
```



## Nonce management

```cmd
#Query Nonce Management Command Help
 attestation-cli nonce -h
```

### Get Nonce

**Command: attestation_cli nonce get**

**Parameters and options:**

| Long Arguement | Short Arguement | Required | Description      |
| -------------- | --------------- | -------- | ---------------- |
| --out          | -o              | no       | output file path |

**Usage examples:**

```cmd
	#Get Nonce
sudo attestation_cli -u "test_01" nonce get --out "/tmp/nonce.txt"
```



## Evidence management

```cmd
#Query Evidence Management Command Help
 attestation_cli evidence -h
```

###  Collect Evidence

**Note: Configure the plugins before collect evidence (/etc/attestation_agent/agent_config.yaml). This command will automatically collect evidence of all enabled plugins. **

**Command: attestation_cli evidence get**

**Parameters and options:**

| Long Arguement  | Short Arguement | Required | Description      |
| --------------- | --------------- | -------- | ---------------- |
| --nonce-type    | -t              | yes      | nonce type       |
| --nonce         | -n              | no       | nonce            |
| --out           | -o              | yes      | output file path |
| --attester-data | -a              | no       | user data        |

**Usage examples:**

```cmd
#Inquiry Help
 attestation_cli evidence get -h

#Collect evidence of all enabled plugins
sudo attestation_cli evidence get \
	--nonce-type "ignore" \
	--out "/tmp/evidence.txt"

sudo attestation_cli evidence get \
	--nonce-type "verifier" \
	--nonce "eyJpYXQiOiAxNzQ1ODUwNjI2LCAidmFsdWUiOiAiOGc1dC9nNXhmTUpxNWR1eERhT0IzV2NDUzRVVlVselhiNHc0QTlUQm1tYUZCQ3dva0c2WXBzdjgySVFiMGpSakQ2b3Vpbm9VaXdGWVl4cS8wNHFJNVE9PSIsICJzaWduYXR1cmUiOiAibVRIR016NjJqZjJ2NE1MZjE1MVM5WTNzTVc4MGVid0pEbitGZ3E3VUtKS2NBQlR3NXRWeDJld1g4dFk2ZUl4QlhqYVY1QmlHY1Q2VWpudTdXNk9Xc2Z5ZGwzWXFzcEp5TjR0MFZENHJaYjQ5OHp6dEt5RHVWN1Jra3RsaElMeFlJOHpiQU14ZmJyU1hCc25xbm9LY2lreUJHNDFPNkEzaGY3UFlXNDFWVjdSMi92SFFvL0VUVWpGYTBJZTVvYUhZUGJUZVRySklVQ3YrY1RMNG90TTJjeWZGdFdoSGN5blZsQUxtU3ZrVzFmaWJVYU8wNTdvdndKVUFwUkJDdTFYUHBqOUxNUDJMWkV2bCtCc2VseEg1YWlheVo5Qk03VUhxRFBlU2dUOEhkSVlqRG5xMDFJaEpkaXk3U1c1UWdPM1FTOXJVeWhRaG90QzlqbnF6YUxFVE96WXFsd2FiQXlCNGQ4UGhoVWFSWWNBbzJFOTVFK3lYb3ZpSHVqaWs5M0VHZ1c2cW9QMHNwZHJyM21pL25XaGhQMzI5YmloSStkSWp4eTh2TDJrVElwYnZqWld6ZmM2d1Z1QkxlUUpVNld0clo4aDA2VUtkbG9VaTU3bnRGUzk2R3dzSkhiODV2c1hGMTZrdVRZUHNMMHVVWmhYTnpsWWJtbzFQTUsxU0wrdDMiIH0=" \
	--out "/tmp/evidence.txt"
	
sudo attestation_cli evidence get \
	--nonce-type "verifier" \
	--nonce @/tmp/nonce.txt \
	--out "/tmp/evidence.txt"
	
sudo attestation_cli evidence get \
	--nonce-type "user" \
	--nonce "YXdkb2huam9hd2lkb2F3aWQ=" \
	--out "/tmp/evidence.txt"
```



## Attestation

```cmd
#Query Challenge Management Command Help
 attestation_cli attest -h
```

### Get attestation result

**Command: attestation_cli attest **

**Parameters and options:**

| Long Arguement | Short Arguement | Required | Description                         |
| -------------- | --------------- | -------- | ----------------------------------- |
| --file         | -f              | yes      | file path of the evidence to attest |
| --out          | -o              | no       | output file path                    |

**Usage examples:**

```cmd
#Query Challenge Management Command Help
 attestation_cli attest -h

#challenge
sudo attestation_cli -u "test_01" attest \
	--file "/tmp/evidence.txt" \
	--out "/tmp/token.txt"
```



## Token Validation

```cmd
#Query Token Management Command Help
 attestation_cli token -h
```

### Get Token Validation Result

**Command: attestation_cli token verify **

**Parameters and options:**

| Long Arguement | Short Arguement | Required | Description                      |
| -------------- | --------------- | -------- | -------------------------------- |
| --file         | -f              | no       | file path of the token to verify |
| --token        | -t              | no       | content of the token to verify   |

**Usage examples:**

```cmd
#Inquiry Help
 attestation_cli token verify -h

#Verify the Token, according to the file
sudo attestation_cli token verify \
	--file "/tmp/token.txt"

#Verify the Token, based on the input
sudo attestation_cli token verify \
	--token "xxxxx"
```

## APIKey Management

```cmd
#Query APIKey Management Command Help
attestation_cli token -h

#Get APIKey and write agent_config.yaml
attestation_cli register new 

#Only get APIKey
attestation_cli register new --nowrite

#Update APIKey and write agent_config.yaml, param from agent_config.yaml
attestation_cli register refresh  

#Only refresh APIKey, param from agent_config.yaml
attestation_cli register refresh --nowrite

#Only refresh APIKey and write agent_config.yaml, param from input
attestation_cli register refresh -u User-Id -k API-Key

#Only refresh APIKey, param from input
attestation_cli register refresh -u User-Id -k API-Key --nowrite
```
