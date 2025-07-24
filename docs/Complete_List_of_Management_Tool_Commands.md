### Certificate Management

```cmd
# Query Certificate Management Command Help
 attestation_cli certificate -h
```

#### Evidence added

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

#### Certificate Deletion

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

#### Certificate Modification

```cmd
#Inquiry Help
 attestation_cli certificate update -h

#Modification of certificates
sudo attestation_cli -u "test_01" certificate update \
	--id "b8481f3e58525f359e12bda53a5779a9" \
	--name "new_name" \
	--description "new_description" \
	--content @/home/test/rsa_2048_certificate.pem
	--cert-type "policy" "refvalue" \
	--is-default true
	
sudo attestation_cli -u "test_01" certificate update \
	--id "cada113be95d5689a38a465f211bd9bd" \
	--name "new_name.pem" \
	--description "new_description" \
	--content "-----BEGIN CERTIFICATE-----
xxxxx
-----END CERTIFICATE-----" \
	--cert-type "policy" "refvalue" \
	--is-default true
```

#### Certificate Search

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



### strategy management

```cmd
#Query Policy Management Command Help
 attestation_cli policy -h
```

#### Strategy Additions

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

"\
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

#### policy deletion

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

#### Update strategy

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

#### Strategy Query

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



### Baseline management

```cmd
#Query Baseline Management Command Help
 attestation_cli baseline -h
```

#### Add Baseline

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
#### delete baseline

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
#### Baseline modification

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
#### query baseline

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



### Nonce management

```cmd
#Query Nonce Management Command Help
 attestation_cli nonce -h
```

#### Get Nonce

```cmd
#Inquiry Help
 attestation_cli nonce get -h
	
#Get Nonce
sudo attestation_cli -u "test_01" nonce get --out "/tmp/nonce.txt"
```



### Evidence management

```cmd
#Query Evidence Management Command Help
 attestation_cli evidence -h
```

#### Access to evidence

```cmd
#Inquiry Help
 attestation_cli evidence get -h

#Access to evidence
sudo attestation_cli evidence get \
	--nonce-type "ignore" \
	--out "/tmp/evidence.txt"

sudo attestation_cli evidence get \
	--nonce-type "verifier" \
	--content "{\"iat\": 1745850626, \"value\": \"8g5t/g5xfMJq5duxDaOB3WcCS4UVUlzXb4w4A9TBmmaFBCwokG6Ypsv82IQb0jRjD6ouinoUiwFYYxq/04qI5Q==\", \"signature\": \"mTHGMz62jf2v4MLf151S9Y3sMW80ebwJDn+Fgq7UKJKcABTw5tVx2ewX8tY6eIxBXjaV5BiGcT6Ujnu7W6OWsfydl3YqspJyN4t0VD4rZb498zztKyDuV7RkktlhILxYI8zbAMxfbrSXBsnqnoKcikyBG41O6A3hf7PYW41VV7R2/vHQo/ETUjFa0Ie5oaHYPbTeTrJIUCv+cTL4otM2cyfFtWhHcynVlALmSvkW1fibUaO057ovwJUApRBCu1XPpj9LMP2LZEvl+BselxH5aiayZ9BM7UHqDPeSgT8HdIYjDnq01IhJdiy7SW5QgO3QS9rUyhQhotC9jnqzaLETOzYqlwabAyB4d8PhhUaRYcAo2E95E+yXoviHujik93EGgW6qoP0spdrr3mi/nWhhP329bihI+dIjxy8vL2kTIpbvjZWzfc6wVuBLeQJU6WtrZ8h06UKdloUi57ntFS96GwsJHb85vsXF16kuTYPsL0uUZhXNzlYbmo1PMK1SL+t3\" }" \
	--out "/tmp/evidence.txt"
	
sudo attestation_cli evidence get \
	--nonce-type "verifier" \
	--content @/tmp/nonce.txt \
	--out "/tmp/evidence.txt"
	
sudo attestation_cli evidence get \
	--nonce-type "user" \
	--user-nonce "user_nonce" \
	--out "/tmp/evidence.txt"
```



### Challenge management

```cmd
#Query Challenge Management Command Help
 attestation_cli attest -h

#challenge
sudo attestation_cli -u "test_01" attest \
	--file "/tmp/evidence.txt" \
	--out "/tmp/token.txt"
```



### Token Management

```cmd
#Query Token Management Command Help
 attestation_cli token -h
```

#### Token Validation

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

### APIKey Management
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
