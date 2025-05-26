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
MIIFpzCCA4+gAwIBAgIUbCCXsKwFN0mmuaDQb7aAlgXrWaYwDQYJKoZIhvcNAQEL
BQAwYzELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0Jl
aWppbmcxDjAMBgNVBAoMBU15T3JnMQswCQYDVQQLDAJJVDETMBEGA1UEAwwKTXkg
Um9vdCBDQTAeFw0yNTA0MjQwOTM0NThaFw0zNTA0MjIwOTM0NThaMGMxCzAJBgNV
BAYTAkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdCZWlqaW5nMQ4wDAYD
VQQKDAVNeU9yZzELMAkGA1UECwwCSVQxEzARBgNVBAMMCk15IFJvb3QgQ0EwggIi
MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCce1d5nNvLns4YIyt6+ozUe/Op
QWEic/4lFduP9NuvfWVJeyiDzs8P9uSwhAeUJdm3ZiOJLEwB9qMKJj8nuNoIdu+m
fafdePdYxI63zw7uBN0gQ0YKxHbTUK+9EjuccdHLhs/l6IihkptjsD0yUf1yVckh
NMB3dEdw2eDW0mUyE2twyw701SG5stjQ9EjsrmkLtMqK/GL/UfpBwshgCFovUaA7
XAvNzR4chdEvDGfpxUKbz51uMGb+7YFOak+P9EjkPI7bJ1bicokFetMz1OhYWfJO
/tjCKKMKZEMjNnCaW26k1JbUQGetEUoF24TbDllMDsa8OPROxQ2QNq1H38dtG3Dm
ybHpKj9V+xNkApxv+gqlV8Ne4AtbfCik1eETGUGd6+GMuNGC8dZ0MtrzeJDHJmo6
AdHyITNBZi94LYqt1dq2nbicoW0TjSMIrWLmJBRXxNg1R8V6mrBu7ublOjpMNPKz
YkEOcYE6Wu2WERRxZGmE7gl7jh8R6YONju7zQxnr2qdAVth2wGSq1H0X6Zwubo3q
MZ2YVnHZRQG5PVIibNUOeGM+rK8JBhoqubadqI/yBM9B3CuiC+k1KeoHsSkD0xXd
kX0NDs65aVgKtfIoKBusxVOLR6/B2/hOfHTmlivoK6zj5bSYKXIBgmNlp4OPsnxU
I5UCFQgZRb+XltAENQIDAQABo1MwUTAdBgNVHQ4EFgQUrsPVkJShLvIb8WM9mQbL
zYPZ230wHwYDVR0jBBgwFoAUrsPVkJShLvIb8WM9mQbLzYPZ230wDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAAzYAl/Qwv7qo4M33+adCqlSkk27t
ldhDY/DGXGiFOqKp9ABD2JmKs+XCQN75ZsA5cBAduSr7sL4JhGe8QN3Gvc6G4xMs
dAyHmTk47zoDpTNU2JQbPjPyiueDWUdARQPtpOA/CDEaIfXH4/fQMzpnP6lvsGgx
1tK2pOkOVBF5jPN8udxtvnDjtK2ynPSbfaqrZqur6p47Dwed74IAVQS9YX+n/S9+
CweiAxjf0ic9E2DUE/ysVq/mYuxtkm1UnBJW/UU0fDhisAo3ACiZxTZfTJp6Bs72
iYF7E2KCohkaXzhEU24X/QTNxLdTK3uE3o9+zHJvv2hMl34uHtWrFEuX7hzvHZQQ
3bVubJihQxIQ4XVSJzQuBTG+HROP24CbJgDX1PINeA8G1hY/Tqq2N5Xd3m4ZTKXz
VGLhIbGKKgE4QJKMf3oFqa7XGt4HNFp5QNbbjY3TNHgCGyxWAVvI35Rly3GvwRlT
xF5YNN6cW+lCDPsZei7DxbE8NoRiguhUuiNEu8aQKoNhrBqG5dYoHWplOjqebqpT
2nA7rGDhFN22ql/xMNbT9ooge3THfBcTR9gtVZXLpoH12ZAt1a95VHnnMeqytb9K
McnBnFxJguxcARSqPAbAI/EX/6SjHOIjYF9cDwylFILmz0c1DxCvz7fIltOOoT5P
laZa46J98tGIK7o=
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
	--cert-type "crl" \
	--revoke-certificate-file "/home/openssl/certificate.pem" "/home/openssl/certificate.pem"
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
MIIFpzCCA4+gAwIBAgIUbCCXsKwFN0mmuaDQb7aAlgXrWaYwDQYJKoZIhvcNAQEL
BQAwYzELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0Jl
aWppbmcxDjAMBgNVBAoMBU15T3JnMQswCQYDVQQLDAJJVDETMBEGA1UEAwwKTXkg
Um9vdCBDQTAeFw0yNTA0MjQwOTM0NThaFw0zNTA0MjIwOTM0NThaMGMxCzAJBgNV
BAYTAkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdCZWlqaW5nMQ4wDAYD
VQQKDAVNeU9yZzELMAkGA1UECwwCSVQxEzARBgNVBAMMCk15IFJvb3QgQ0EwggIi
MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCce1d5nNvLns4YIyt6+ozUe/Op
QWEic/4lFduP9NuvfWVJeyiDzs8P9uSwhAeUJdm3ZiOJLEwB9qMKJj8nuNoIdu+m
fafdePdYxI63zw7uBN0gQ0YKxHbTUK+9EjuccdHLhs/l6IihkptjsD0yUf1yVckh
NMB3dEdw2eDW0mUyE2twyw701SG5stjQ9EjsrmkLtMqK/GL/UfpBwshgCFovUaA7
XAvNzR4chdEvDGfpxUKbz51uMGb+7YFOak+P9EjkPI7bJ1bicokFetMz1OhYWfJO
/tjCKKMKZEMjNnCaW26k1JbUQGetEUoF24TbDllMDsa8OPROxQ2QNq1H38dtG3Dm
ybHpKj9V+xNkApxv+gqlV8Ne4AtbfCik1eETGUGd6+GMuNGC8dZ0MtrzeJDHJmo6
AdHyITNBZi94LYqt1dq2nbicoW0TjSMIrWLmJBRXxNg1R8V6mrBu7ublOjpMNPKz
YkEOcYE6Wu2WERRxZGmE7gl7jh8R6YONju7zQxnr2qdAVth2wGSq1H0X6Zwubo3q
MZ2YVnHZRQG5PVIibNUOeGM+rK8JBhoqubadqI/yBM9B3CuiC+k1KeoHsSkD0xXd
kX0NDs65aVgKtfIoKBusxVOLR6/B2/hOfHTmlivoK6zj5bSYKXIBgmNlp4OPsnxU
I5UCFQgZRb+XltAENQIDAQABo1MwUTAdBgNVHQ4EFgQUrsPVkJShLvIb8WM9mQbL
zYPZ230wHwYDVR0jBBgwFoAUrsPVkJShLvIb8WM9mQbLzYPZ230wDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAAzYAl/Qwv7qo4M33+adCqlSkk27t
ldhDY/DGXGiFOqKp9ABD2JmKs+XCQN75ZsA5cBAduSr7sL4JhGe8QN3Gvc6G4xMs
dAyHmTk47zoDpTNU2JQbPjPyiueDWUdARQPtpOA/CDEaIfXH4/fQMzpnP6lvsGgx
1tK2pOkOVBF5jPN8udxtvnDjtK2ynPSbfaqrZqur6p47Dwed74IAVQS9YX+n/S9+
CweiAxjf0ic9E2DUE/ysVq/mYuxtkm1UnBJW/UU0fDhisAo3ACiZxTZfTJp6Bs72
iYF7E2KCohkaXzhEU24X/QTNxLdTK3uE3o9+zHJvv2hMl34uHtWrFEuX7hzvHZQQ
3bVubJihQxIQ4XVSJzQuBTG+HROP24CbJgDX1PINeA8G1hY/Tqq2N5Xd3m4ZTKXz
VGLhIbGKKgE4QJKMf3oFqa7XGt4HNFp5QNbbjY3TNHgCGyxWAVvI35Rly3GvwRlT
xF5YNN6cW+lCDPsZei7DxbE8NoRiguhUuiNEu8aQKoNhrBqG5dYoHWplOjqebqpT
2nA7rGDhFN22ql/xMNbT9ooge3THfBcTR9gtVZXLpoH12ZAt1a95VHnnMeqytb9K
McnBnFxJguxcARSqPAbAI/EX/6SjHOIjYF9cDwylFILmz0c1DxCvz7fIltOOoT5P
laZa46J98tGIK7o=
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

# Extract is_log_valid from first tpm_ima log
is_log_valid = valid {
    some i
    logs := input.evidence.logs
    logs[i].log_type == \"tpm_ima\"
    valid := logs[i].is_log_valid
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
    is_log_valid == true
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
	--name "asd{{$number.int}}" \
    --content "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMyJ9.eyJ1c2VybmFtZSI6Ind3dy5qc29uLmNuIiwicG9saWN5IjoiY0dGamEyRm5aU0IyWlhKcFptbGpZWFJwYjI0S0NpTWdSWGgwY21GamRDQnBjMTlzYjJkZmRtRnNhV1FnWm5KdmJTQm1hWEp6ZENCMGNHMWZhVzFoSUd4dlp3cHBjMTlzYjJkZmRtRnNhV1FnUFNCMllXeHBaQ0I3Q2lBZ0lDQnpiMjFsSUdrS0lDQWdJR3h2WjNNZ09qMGdhVzV3ZFhRdVpYWnBaR1Z1WTJVdWJHOW5jd29nSUNBZ2JHOW5jMXRwWFM1c2IyZGZkSGx3WlNBOVBTQWlkSEJ0WDJsdFlTSUtJQ0FnSUhaaGJHbGtJRG85SUd4dlozTmJhVjB1YVhOZmJHOW5YM1poYkdsa0NuMEtDaU1nUTJobFkyc2dhV1lnY0dOeWN5QXhNQ0JwY3lCd2NtVnpaVzUwSUdsdUlHRnVlU0JvWVhOb0lHRnNaMjl5YVhSb2JTQW9jMmhoTVN3Z2MyaGhNalUyTENCemFHRXpPRFFzSUhOb1lUVXhNaWtLY0dOeVgzQnlaWE5sYm5RZ2V3b2dJQ0FnWVd4c0lEbzlJSHQ0SUh3Z2VDQTZQU0JiTVRCZFcxOWRJSDBLSUNBZ0lHMWxZWE4xY21Wa0lEbzlJSHR3WTNJdWNHTnlYMmx1WkdWNElId2djR055SURvOUlHbHVjSFYwTG1WMmFXUmxibU5sTG5CamNuTXVjR055WDNaaGJIVmxjMXRmWFgwS0lDQWdJR0ZzYkY5d1kzSnpYM04xWW5ObGRDQTZQU0JoYkd3Z0xTQnRaV0Z6ZFhKbFpBb2dJQ0FnWTI5MWJuUW9ZV3hzWDNCamNuTmZjM1ZpYzJWMEtTQTlQU0F3Q24wS0NpTWdRWFIwWlhOMFlYUnBiMjRnZG1Gc2FXUWdhV1lnWVd4c0lHTnZibVJwZEdsdmJuTWdiV1YwQ21SbFptRjFiSFFnWVhSMFpYTjBZWFJwYjI1ZmRtRnNhV1FnUFNCbVlXeHpaUXBoZEhSbGMzUmhkR2x2Ymw5MllXeHBaQ0I3Q2lBZ0lDQnBjMTlzYjJkZmRtRnNhV1FnUFQwZ2RISjFaUW9nSUNBZ2NHTnlYM0J5WlhObGJuUUtmUW9LSXlCUGRYUndkWFFnY21WemRXeDBDbkpsYzNWc2RDQTlJSHNLSUNBZ0lDSmhkSFJsYzNSaGRHbHZibDkyWVd4cFpDSTZJR0YwZEdWemRHRjBhVzl1WDNaaGJHbGtMQW9nSUNBZ0ltTjFjM1J2YlY5a1lYUmhJam9nZXdvZ0lDQWdJQ0FnSUNKb1lYTm9YMkZzWnlJNklHbHVjSFYwTG1WMmFXUmxibU5sTG5CamNuTXVhR0Z6YUY5aGJHY0tJQ0FnSUgwS2ZRbz0ifQ.e68L3J2OE2yylJmwYIw3kpId7rQZ2XoGiY6ZCxg4VJ2cEPEDZtj0me_3Hcp87im0mpZxj9d3O3yVgLNvAfHNBw0MJYd85aoPTUxP2i_8i8Huhgw1mORK4s_hupNS-ryjKHf6uTgJQeKiuWjDM4VJguJCj64YZDH8sB-JLLrYI-Fn9XkQK0aiOrAtL2cOh9btWNKUw5Wpi9s2Be2qGiIArcn2hcmoDdkxcTo4FAbDSw8Hu0HbjVkpli4ionNkBYOnz_IgLD1Mi3SSF1PlY0hJQygpCiA8j4Hb6nY19eSkjqfdZ7C2lTqFlBnj2D89QWupwMufYX7csvJ0h5x5l581KQ" \
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
	--content "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJyZWZlcmVuY2VWYWx1ZXMiOlt7ImZpbGVOYW1lIjoic3l5eC0xLlBBVCIsInNoYTI1NiI6IjEyMzQ1NiJ9XX0.GXywOcuhqz05b-9TVx5cHCkcV8Rxy0v3XY3Aex5H9z5jXdmvl3kfV-wkZXgZJWf2LoOqD8YE3dXG-MhxzLqGAu2GeRoVhg-bXsd1Gzn1QM5_Who3quYXu4jKLbGR4EwVlEoK9M8Oa0eUVeA14R1kKyZ4cdDEir2u_Z_mXa_0RapVUoePAipNsVocs3xXSsppxTE1xOHe6VmV71GbCU-UE9O5GvGu_SeTljvuLV4uFCi4UXmy3VIzULAybPbS_n4vSvOazNeHTTq787ifn6c6n5-kZu0KP7AR96tOnLLG_f1giSu9XbFsntCPu9FNNzx6cO6BHHlDAOQhiJcSK2rzSQ"

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
	--content "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJyZWZlcmVuY2VWYWx1ZXMiOlt7ImZpbGVOYW1lIjoic3l5eC0xLlBBVCIsInNoYTI1NiI6IjEyMzQ1NiJ9XX0.GXywOcuhqz05b-9TVx5cHCkcV8Rxy0v3XY3Aex5H9z5jXdmvl3kfV-wkZXgZJWf2LoOqD8YE3dXG-MhxzLqGAu2GeRoVhg-bXsd1Gzn1QM5_Who3quYXu4jKLbGR4EwVlEoK9M8Oa0eUVeA14R1kKyZ4cdDEir2u_Z_mXa_0RapVUoePAipNsVocs3xXSsppxTE1xOHe6VmV71GbCU-UE9O5GvGu_SeTljvuLV4uFCi4UXmy3VIzULAybPbS_n4vSvOazNeHTTq787ifn6c6n5-kZu0KP7AR96tOnLLG_f1giSu9XbFsntCPu9FNNzx6cO6BHHlDAOQhiJcSK2rzSQ" \
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
	--nonce-type "default" \
	--content "{\"iat\": 1745850626, \"value\": \"8g5t/g5xfMJq5duxDaOB3WcCS4UVUlzXb4w4A9TBmmaFBCwokG6Ypsv82IQb0jRjD6ouinoUiwFYYxq/04qI5Q==\", \"signature\": \"mTHGMz62jf2v4MLf151S9Y3sMW80ebwJDn+Fgq7UKJKcABTw5tVx2ewX8tY6eIxBXjaV5BiGcT6Ujnu7W6OWsfydl3YqspJyN4t0VD4rZb498zztKyDuV7RkktlhILxYI8zbAMxfbrSXBsnqnoKcikyBG41O6A3hf7PYW41VV7R2/vHQo/ETUjFa0Ie5oaHYPbTeTrJIUCv+cTL4otM2cyfFtWhHcynVlALmSvkW1fibUaO057ovwJUApRBCu1XPpj9LMP2LZEvl+BselxH5aiayZ9BM7UHqDPeSgT8HdIYjDnq01IhJdiy7SW5QgO3QS9rUyhQhotC9jnqzaLETOzYqlwabAyB4d8PhhUaRYcAo2E95E+yXoviHujik93EGgW6qoP0spdrr3mi/nWhhP329bihI+dIjxy8vL2kTIpbvjZWzfc6wVuBLeQJU6WtrZ8h06UKdloUi57ntFS96GwsJHb85vsXF16kuTYPsL0uUZhXNzlYbmo1PMK1SL+t3\" }" \
	--out "/tmp/evidence.txt"
	
sudo attestation_cli evidence get \
	--nonce-type "default" \
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
	--token "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6ImprdSIsImtpZCI6ImtpZCJ9.eyJpbnR1c2UiOiJHZW5lcmljIiwidWVpZCI6IlRQTSBBSyIsInRwbV9pbWEiOnsiYXR0ZXN0YXRpb25fc3RhdHVzIjoidW5rbm93biIsImlzX2xvZ192YWxpZCI6dHJ1ZSwicGNycyI6eyJoYXNoX2FsZyI6InNoYTI1NiIsInBjcl92YWx1ZXMiOlt7ImlzX21hdGNoZWQiOmZhbHNlLCJwY3JfaW5kZXgiOjEwLCJwY3JfdmFsdWUiOiJhMDNlZDIwNzkxNWY2YzhjMDk3ZGNlMTNkNjg3NmE4ODNhNTEzZGE2OTgxMDE3NDEyMjU2NTQ4OTFjYmQ0ZmYxIiwicmVwbGF5X3ZhbHVlIjoiZWE2ZGYyOGUyYzc1NzdjZDE5YjI1NTljMzQ2OWE5MjE2ODU0YWMzZTZjZWE4M2M2NTg0NTdjYWJkYTI3ODNmYSJ9XX19LCJ0cG1fYm9vdCI6eyJhdHRlc3RhdGlvbl9zdGF0dXMiOiJ1bmtub3duIiwiaXNfbG9nX3ZhbGlkIjp0cnVlLCJwY3JzIjp7Imhhc2hfYWxnIjoic2hhMjU2IiwicGNyX3ZhbHVlcyI6W3siaXNfbWF0Y2hlZCI6dHJ1ZSwicGNyX2luZGV4IjowLCJwY3JfdmFsdWUiOiJlMjFiNzAzZWU2OWM3NzQ3NmJjY2I0M2VjMDMzNmE5YTFiMjkxNGIzNzg5NDRmN2IwMGExMDIxNGNhOGZlYTkzIiwicmVwbGF5X3ZhbHVlIjoiZTIxYjcwM2VlNjljNzc0NzZiY2NiNDNlYzAzMzZhOWExYjI5MTRiMzc4OTQ0ZjdiMDBhMTAyMTRjYThmZWE5MyJ9LHsiaXNfbWF0Y2hlZCI6dHJ1ZSwicGNyX2luZGV4IjoxLCJwY3JfdmFsdWUiOiJhMzJiZjhiZjMyOTkwN2RjMmI0ODM5ZmYzYzYxYjQ1NmE5ODU2ZDEyMTEwZjQ5ZDQ5MGRmMzNiYWYxODkzNDBlIiwicmVwbGF5X3ZhbHVlIjoiYTMyYmY4YmYzMjk5MDdkYzJiNDgzOWZmM2M2MWI0NTZhOTg1NmQxMjExMGY0OWQ0OTBkZjMzYmFmMTg5MzQwZSJ9LHsiaXNfbWF0Y2hlZCI6dHJ1ZSwicGNyX2luZGV4IjoyLCJwY3JfdmFsdWUiOiJhOWQ1YmRmM2IwYjAzNGE0MzRlZjNhZGRlMmQ1Y2IwYTc1MzM4MDNmOTdmODg4OWYxMTc0YWI2MGJkNGRjYjcwIiwicmVwbGF5X3ZhbHVlIjoiYTlkNWJkZjNiMGIwMzRhNDM0ZWYzYWRkZTJkNWNiMGE3NTMzODAzZjk3Zjg4ODlmMTE3NGFiNjBiZDRkY2I3MCJ9LHsiaXNfbWF0Y2hlZCI6dHJ1ZSwicGNyX2luZGV4IjozLCJwY3JfdmFsdWUiOiJlMjFiNzAzZWU2OWM3NzQ3NmJjY2I0M2VjMDMzNmE5YTFiMjkxNGIzNzg5NDRmN2IwMGExMDIxNGNhOGZlYTkzIiwicmVwbGF5X3ZhbHVlIjoiZTIxYjcwM2VlNjljNzc0NzZiY2NiNDNlYzAzMzZhOWExYjI5MTRiMzc4OTQ0ZjdiMDBhMTAyMTRjYThmZWE5MyJ9LHsiaXNfbWF0Y2hlZCI6dHJ1ZSwicGNyX2luZGV4Ijo0LCJwY3JfdmFsdWUiOiJmY2U3ZjEwODMwODJiMTZjZmUyYjA4NWRkNzg1OGJiMTFhMzdjMDliNzhlMzZjNzllNWEyZmQ1MjkzNTNjNGUyIiwicmVwbGF5X3ZhbHVlIjoiZmNlN2YxMDgzMDgyYjE2Y2ZlMmIwODVkZDc4NThiYjExYTM3YzA5Yjc4ZTM2Yzc5ZTVhMmZkNTI5MzUzYzRlMiJ9LHsiaXNfbWF0Y2hlZCI6dHJ1ZSwicGNyX2luZGV4Ijo1LCJwY3JfdmFsdWUiOiI4ZWRkZTkxMjY5OWNlZGRkZGM3ZDlhM2Q3ZWU0NGE4YjFiMTkxMDgxNTY5MmRlZjZjOWU2MzdlMmI5MzlmOTQxIiwicmVwbGF5X3ZhbHVlIjoiOGVkZGU5MTI2OTljZWRkZGRjN2Q5YTNkN2VlNDRhOGIxYjE5MTA4MTU2OTJkZWY2YzllNjM3ZTJiOTM5Zjk0MSJ9LHsiaXNfbWF0Y2hlZCI6dHJ1ZSwicGNyX2luZGV4Ijo2LCJwY3JfdmFsdWUiOiJlMjFiNzAzZWU2OWM3NzQ3NmJjY2I0M2VjMDMzNmE5YTFiMjkxNGIzNzg5NDRmN2IwMGExMDIxNGNhOGZlYTkzIiwicmVwbGF5X3ZhbHVlIjoiZTIxYjcwM2VlNjljNzc0NzZiY2NiNDNlYzAzMzZhOWExYjI5MTRiMzc4OTQ0ZjdiMDBhMTAyMTRjYThmZWE5MyJ9LHsiaXNfbWF0Y2hlZCI6dHJ1ZSwicGNyX2luZGV4Ijo3LCJwY3JfdmFsdWUiOiJlMjFiNzAzZWU2OWM3NzQ3NmJjY2I0M2VjMDMzNmE5YTFiMjkxNGIzNzg5NDRmN2IwMGExMDIxNGNhOGZlYTkzIiwicmVwbGF5X3ZhbHVlIjoiZTIxYjcwM2VlNjljNzc0NzZiY2NiNDNlYzAzMzZhOWExYjI5MTRiMzc4OTQ0ZjdiMDBhMTAyMTRjYThmZWE5MyJ9XX0sInNlY3VyZV9ib290IjoiTkEifSwiaWF0IjoxNzQ3MDQyMzIyMzgzLCJleHAiOjE3NDcwNDI5MjIzODMsImlzcyI6ImlzcyIsImp0aSI6Ijg4NGY4OWRhLTQwNDUtNGIxYy05YzNlLTIzYjlkM2VkNDY5MyIsInZlciI6IjEuMCIsIm5iZiI6MTc0NzA0MjMyMjM4MywiZWF0X3Byb2ZpbGUiOiJlYXRfcHJvZmlsZSJ9.Djg17u3Ssfz1kKdLvKgawC1kngLqdPrSHFHZN2mrboVrlBtYmyHFXkZzHfWocjsunqzIxzfqBAzHMrKAblivW_JCrO2MwqPQvKfJSHJASt34xcITFra3Xm860upodI32a0n3jPYQhVYSL-qnvqF3za1aTmy2TkDy7LxNDsT44gKxS8I44fS8Rfn26h_-5Jv6h_VQZ41MoFLsEiTih-F5mRaORLVGqA9cenLeDQ5NrggEheXBfLBqlzECNAAhfx-O42JaQEkuIC9KwqdKDUHNOOo6fYUUOZDHZ6g-OHNaFHoWCHM1JqdMRwgCDL24oJby4WrA572w6HcvFcmYecl4wM_dF4sS-3AjQPKdwJ1g5Z4wwG-Hf1sBb6oIOHQQhAOOpQsSEksd3CBKOCJ0xguLviFlthSa7h5-d0nn1QX1EIUdpu_Ox5KyH28DBeFsueO_kd9UYC1DHJfOnBGWxO7Cv4uPN3uR4gsWKwDEmDLxCw5SP5i-8pMa2W0ULj80LDz6"
```

