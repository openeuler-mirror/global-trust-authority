### 证书管理

```cmd
#查询证书管理命令帮助
cargo run -p attestation_cli -- certificate -h
```

#### 证据新增

```cmd
#查询帮助
cargo run -p attestation_cli -- certificate set -h

#插入证书(简略版)
cargo run -p attestation_cli -- -u "test_lyt" certificate set \
	--cert-type "policy" "refvalue" \
	--content @/home/test/rsa_2048_certificate.pem

cargo run -p attestation_cli -- -u "test_lyt" certificate set \
	--name "rsa_2048_certificate.pem" \
    --cert-type "policy" "refvalue" \
	--content "-----BEGIN CERTIFICATE-----
MIIDpTCCAo2gAwIBAgIUGMqfuuY1h68qMF/wF5JvsR8seOwwDQYJKoZIhvcNAQEL
BQAwYjELMAkGA1UEBhMCQUExCzAJBgNVBAgMAkREMQswCQYDVQQHDAJTUzEMMAoG
A1UECgwDU1NTMQswCQYDVQQLDAJTUzELMAkGA1UEAwwCU1MxETAPBgkqhkiG9w0B
CQEWAlNTMB4XDTI1MDQxNDA2NDMzMVoXDTI2MDQxNDA2NDMzMVowYjELMAkGA1UE
BhMCQUExCzAJBgNVBAgMAkREMQswCQYDVQQHDAJTUzEMMAoGA1UECgwDU1NTMQsw
CQYDVQQLDAJTUzELMAkGA1UEAwwCU1MxETAPBgkqhkiG9w0BCQEWAlNTMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAttL/DKMsMmJxpCE19mXJ5LIhCfdq
PYjs3rU8SHOYwYPxUmo8G6r8+70eN4sFfpuSc6ukmMPZcaaxTJ2b9xBx1wGgNhrW
7VLiB8xnf7wj0brI9OXd4emqcw2Y8ujnVmx0YhidclIeeFViBpzeXRT7qcz1J163
wLNWUspkwFRuV+jEd4PBS645Kfnm+ZZJEj36OHIIBZXlBGRktzxnqONzeG1Y3w7+
0vBKEJYGygEJAo1sxtsUmA3is/Z/6Q3lklp+B4OOoo20p+2hjRr2T8gHY+q1h2wS
s4/45tYm+6TN8vNG5o7vAC8319qXMwguP7EftcYWNoxCRwJrtOz19xhSwQIDAQAB
o1MwUTAdBgNVHQ4EFgQUA5UNB2Kuw3bfZI9lbLDCNOMfwi8wHwYDVR0jBBgwFoAU
A5UNB2Kuw3bfZI9lbLDCNOMfwi8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEApeyLoh1ykyTBdMVIkNTQSC0McvFx+DoXo283ORroedO2HtQ8nUmU
QUkV/cEK8ZSF6Vqw8Egspi+64en2liVxhGeyK0cZPGPFfqiZd6IUxaeXxLn7EMEw
YTaXBqMhc20J31pIa/MrNaVemgd24sPyEwJ/SpFQPnwtqe6mV8jwinQdwXK7McU8
RFPXvi3T+R7oG285ZyCY4hJvpkGxoOFEmLmIjnH0bJ9OFAVCi0LU9wdDJ+2yGU6U
xq4CpSwSWpCGJIZDLKHX1YHMrYTve2IZGYQYp0+MMg4oae6kBQySDDuXTTq90fKS
JwOtYemt8vUWlASpzNlGqVmj4RdRs2wGaw==
-----END CERTIFICATE-----"
	
	
#插入证书(完整版)
cargo run -p attestation_cli -- -u "test_lyt" certificate set \
	--name "certificate.pem" \
	--description "This is certificate" \
	--cert-type "policy" "refvalue" \
	--content @/home/test/rsa_2048_certificate.pem \
	--is-default

#插入吊销证书
cargo run -p attestation_cli -- -u "test_lyt" certificate set \
	--cert-type "crl" \
	--revoke-certificate-file "/home/openssl/certificate.pem" "/home/openssl/certificate.pem"
```

#### 证书删除

```cmd
#查询帮助
cargo run -p attestation_cli -- certificate delete -h

#全部删除
cargo run -p attestation_cli -- -u "test_lyt" certificate delete \
	--delete-type "all"

#根据id删除
cargo run -p attestation_cli -- -u "test_lyt" certificate delete \
	--delete-type "id" \
	--ids "id1" "id2"

#根据证书类型删除
cargo run -p attestation_cli -- -u "test_lyt" certificate delete \
	--delete-type "type" \
	--cert-type "policy" 
```

#### 证书修改

```cmd
#查询帮助
cargo run -p attestation_cli -- certificate update -h

#修改证书
cargo run -p attestation_cli -- -u "test_lyt" certificate update \
	--id "b8481f3e58525f359e12bda53a5779a9" \
	--name "new_name" \
	--description "new_description" \
	--content @/home/test/rsa_2048_certificate.pem
	--cert-type "policy" "refvalue" \
	--is-default true
```

#### 证书查询

```cmd
#查询帮助
cargo run -p attestation_cli -- certificate get -h

#查询全部证书
cargo run -p attestation_cli -- -u "test_lyt" certificate get

#根据证书类型查询
cargo run -p attestation_cli -- -u "test_lyt" certificate get \
	--cert-type "refvalue" 

#根据证书id查询
cargo run -p attestation_cli -- -u "test_lyt" certificate get \
	--ids "id1" "id2"
```



### 策略管理

```cmd
#查询策略管理命令帮助
cargo run -p attestation_cli -- policy -h
```

#### 策略新增

```cmd
#查询帮助
cargo run -p attestation_cli -- policy set -h

#新增text类型的策略(简略版)
cargo run -p attestation_cli -- -u "test_lyt" policy set \
	--name "test_policy{{$number.int}}" \
	--content "cGFja2FnZSB2ZXJpZmljYXRpb24KCiMgRXh0cmFjdCBpc19sb2dfdmFsaWQgZnJvbSBmaXJzdCB0cG1faW1hIGxvZwppc19sb2dfdmFsaWQgPSB2YWxpZCB7CiAgICBzb21lIGkKICAgIGxvZ3MgOj0gaW5wdXQuZXZpZGVuY2UubG9ncwogICAgbG9nc1tpXS5sb2dfdHlwZSA9PSAidHBtX2ltYSIKICAgIHZhbGlkIDo9IGxvZ3NbaV0uaXNfbG9nX3ZhbGlkCn0KCiMgQ2hlY2sgaWYgcGNycyAxMCBpcyBwcmVzZW50IGluIGFueSBoYXNoIGFsZ29yaXRobSAoc2hhMSwgc2hhMjU2LCBzaGEzODQsIHNoYTUxMikKcGNyX3ByZXNlbnQgewogICAgYWxsIDo9IHt4IHwgeCA6PSBbMTBdW19dIH0KICAgIG1lYXN1cmVkIDo9IHtwY3IucGNyX2luZGV4IHwgcGNyIDo9IGlucHV0LmV2aWRlbmNlLnBjcnMucGNyX3ZhbHVlc1tfXX0KICAgIGFsbF9wY3JzX3N1YnNldCA6PSBhbGwgLSBtZWFzdXJlZAogICAgY291bnQoYWxsX3BjcnNfc3Vic2V0KSA9PSAwCn0KCiMgQXR0ZXN0YXRpb24gdmFsaWQgaWYgYWxsIGNvbmRpdGlvbnMgbWV0CmRlZmF1bHQgYXR0ZXN0YXRpb25fdmFsaWQgPSBmYWxzZQphdHRlc3RhdGlvbl92YWxpZCB7CiAgICBpc19sb2dfdmFsaWQgPT0gdHJ1ZQogICAgcGNyX3ByZXNlbnQKfQoKIyBPdXRwdXQgcmVzdWx0CnJlc3VsdCA9IHsKICAgICJhdHRlc3RhdGlvbl92YWxpZCI6IGF0dGVzdGF0aW9uX3ZhbGlkLAogICAgImN1c3RvbV9kYXRhIjogewogICAgICAgICJoYXNoX2FsZyI6IGlucHV0LmV2aWRlbmNlLnBjcnMuaGFzaF9hbGcKICAgIH0KfQo=" \
	--attester-type "tpm_ima" "tpm_boot" \
	--content-type "text" 

cargo run -p attestation_cli -- -u "test_lyt" policy set \
	--content @/home/test/digest_verification.rego \
	--attester-type "tpm_ima" "tpm_boot" \
	--content-type "text" 
		
#新增jwt类型的策略（简略版）
cargo run -p attestation_cli -- -u "test_lyt" policy set \
	--name "asd{{$number.int}}" \
    --content "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMyJ9.eyJ1c2VybmFtZSI6Ind3dy5qc29uLmNuIiwicG9saWN5IjoiY0dGamEyRm5aU0IyWlhKcFptbGpZWFJwYjI0S0NpTWdSWGgwY21GamRDQnBjMTlzYjJkZmRtRnNhV1FnWm5KdmJTQm1hWEp6ZENCMGNHMWZhVzFoSUd4dlp3cHBjMTlzYjJkZmRtRnNhV1FnUFNCMllXeHBaQ0I3Q2lBZ0lDQnpiMjFsSUdrS0lDQWdJR3h2WjNNZ09qMGdhVzV3ZFhRdVpYWnBaR1Z1WTJVdWJHOW5jd29nSUNBZ2JHOW5jMXRwWFM1c2IyZGZkSGx3WlNBOVBTQWlkSEJ0WDJsdFlTSUtJQ0FnSUhaaGJHbGtJRG85SUd4dlozTmJhVjB1YVhOZmJHOW5YM1poYkdsa0NuMEtDaU1nUTJobFkyc2dhV1lnY0dOeWN5QXhNQ0JwY3lCd2NtVnpaVzUwSUdsdUlHRnVlU0JvWVhOb0lHRnNaMjl5YVhSb2JTQW9jMmhoTVN3Z2MyaGhNalUyTENCemFHRXpPRFFzSUhOb1lUVXhNaWtLY0dOeVgzQnlaWE5sYm5RZ2V3b2dJQ0FnWVd4c0lEbzlJSHQ0SUh3Z2VDQTZQU0JiTVRCZFcxOWRJSDBLSUNBZ0lHMWxZWE4xY21Wa0lEbzlJSHR3WTNJdWNHTnlYMmx1WkdWNElId2djR055SURvOUlHbHVjSFYwTG1WMmFXUmxibU5sTG5CamNuTXVjR055WDNaaGJIVmxjMXRmWFgwS0lDQWdJR0ZzYkY5d1kzSnpYM04xWW5ObGRDQTZQU0JoYkd3Z0xTQnRaV0Z6ZFhKbFpBb2dJQ0FnWTI5MWJuUW9ZV3hzWDNCamNuTmZjM1ZpYzJWMEtTQTlQU0F3Q24wS0NpTWdRWFIwWlhOMFlYUnBiMjRnZG1Gc2FXUWdhV1lnWVd4c0lHTnZibVJwZEdsdmJuTWdiV1YwQ21SbFptRjFiSFFnWVhSMFpYTjBZWFJwYjI1ZmRtRnNhV1FnUFNCbVlXeHpaUXBoZEhSbGMzUmhkR2x2Ymw5MllXeHBaQ0I3Q2lBZ0lDQnBjMTlzYjJkZmRtRnNhV1FnUFQwZ2RISjFaUW9nSUNBZ2NHTnlYM0J5WlhObGJuUUtmUW9LSXlCUGRYUndkWFFnY21WemRXeDBDbkpsYzNWc2RDQTlJSHNLSUNBZ0lDSmhkSFJsYzNSaGRHbHZibDkyWVd4cFpDSTZJR0YwZEdWemRHRjBhVzl1WDNaaGJHbGtMQW9nSUNBZ0ltTjFjM1J2YlY5a1lYUmhJam9nZXdvZ0lDQWdJQ0FnSUNKb1lYTm9YMkZzWnlJNklHbHVjSFYwTG1WMmFXUmxibU5sTG5CamNuTXVhR0Z6YUY5aGJHY0tJQ0FnSUgwS2ZRbz0ifQ.e68L3J2OE2yylJmwYIw3kpId7rQZ2XoGiY6ZCxg4VJ2cEPEDZtj0me_3Hcp87im0mpZxj9d3O3yVgLNvAfHNBw0MJYd85aoPTUxP2i_8i8Huhgw1mORK4s_hupNS-ryjKHf6uTgJQeKiuWjDM4VJguJCj64YZDH8sB-JLLrYI-Fn9XkQK0aiOrAtL2cOh9btWNKUw5Wpi9s2Be2qGiIArcn2hcmoDdkxcTo4FAbDSw8Hu0HbjVkpli4ionNkBYOnz_IgLD1Mi3SSF1PlY0hJQygpCiA8j4Hb6nY19eSkjqfdZ7C2lTqFlBnj2D89QWupwMufYX7csvJ0h5x5l581KQ" \
	--attester-type "tpm_ima" "tpm_boot" \
	--content-type "jwt" 
	
cargo run -p attestation_cli -- -u "test_lyt" policy set \
	--content @/home/test/policy_jwt.txt \
	--attester-type "tpm_ima" "tpm_boot" \
	--content-type "jwt" 

#新增策略(完整版)
cargo run -p attestation_cli -- -u "test_lyt" policy set \
	--name "digest_verification.rego" \
	--description "This is policy" \
	--attester-type "tpm_ima" "tpm_boot" \
	--content @/home/test/policy_jwt.txt \
	--content-type "jwt" \
	--is-default
```

#### 策略删除

```cmd
#查询帮助
cargo run -p attestation_cli -- policy delete -h

#全部删除
cargo run -p attestation_cli -- -u "test_lyt" policy delete \
	--delete-type "all"

#根据id删除
cargo run -p attestation_cli -- -u "test_lyt" policy delete \
	--delete-type "id" \
	--ids "id1" "id2"

#根据插件类型删除
cargo run -p attestation_cli -- -u "test_lyt" policy delete \
	--delete-type "attester_type" \
	--attester-type "tpm_ima" 

```

#### 策略修改

```cmd
#查询帮助
cargo run -p attestation_cli -- policy update -h

#修改证书
cargo run -p attestation_cli -- -u "test_lyt" policy update \
	--id "be8c820d-55d3-4645-b54b-fe2cb5f84f81" \
	--name "new_name" \
	--description "new_description" \
	--content @/home/test/policy_jwt.txt \
	--attester-type "tpm_ima" "tpm_boot" \
	--content-type "jwt" \
	--is-default true

```

#### 策略查询

```cmd
#查询帮助
cargo run -p attestation_cli -- policy get -h

#查询全部策略
cargo run -p attestation_cli -- -u "test_lyt" policy get

#根据策略类型查询
cargo run -p attestation_cli -- -u "test_lyt" policy get \
	--attester-type "tpm_ima" 

#根据策略id查询
cargo run -p attestation_cli -- -u "test_lyt" policy get \
	--ids "id1" "be8c820d-55d3-4645-b54b-fe2cb5f84f81"

```



### 基线管理

```cmd
#查询基线管理命令帮助
cargo run -p attestation_cli -- baseline -h
```

#### 基线新增

```cmd
#查询帮助
cargo run -p attestation_cli -- baseline set -h

#新增基线(简略版)
cargo run -p attestation_cli -- -u "test_lyt" baseline set \
	--content @/home/test/baseline.txt

cargo run -p attestation_cli -- -u "test_lyt" baseline set \
	--name "baseline.txt" \
	--content "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJyZWZlcmVuY2VWYWx1ZXMiOlt7ImZpbGVOYW1lIjoic3l5eC0xLlBBVCIsInNoYTI1NiI6IjEyMzQ1NiJ9XX0.GXywOcuhqz05b-9TVx5cHCkcV8Rxy0v3XY3Aex5H9z5jXdmvl3kfV-wkZXgZJWf2LoOqD8YE3dXG-MhxzLqGAu2GeRoVhg-bXsd1Gzn1QM5_Who3quYXu4jKLbGR4EwVlEoK9M8Oa0eUVeA14R1kKyZ4cdDEir2u_Z_mXa_0RapVUoePAipNsVocs3xXSsppxTE1xOHe6VmV71GbCU-UE9O5GvGu_SeTljvuLV4uFCi4UXmy3VIzULAybPbS_n4vSvOazNeHTTq787ifn6c6n5-kZu0KP7AR96tOnLLG_f1giSu9XbFsntCPu9FNNzx6cO6BHHlDAOQhiJcSK2rzSQ"

#新增策略(完整版)
cargo run -p attestation_cli -- -u "test_lyt" baseline set \
	--name "baseline" \
	--description "This is baseline" \
	--attester-type "tpm_ima" \
	--content @/home/test/baseline.txt \
    --is-default
```
#### 基线删除

```cmd
#查询帮助
cargo run -p attestation_cli -- baseline delete -h

#全部删除
cargo run -p attestation_cli -- -u "test_lyt" baseline delete \
	--delete-type "all"

#根据id删除
cargo run -p attestation_cli -- -u "test_lyt" baseline delete \
	--delete-type "id" \
	--ids "id1" "id2"

#根据插件类型删除
cargo run -p attestation_cli -- -u "test_lyt" baseline delete \
	--delete-type "type" \
	--attester-type "tpm_ima" 
```
#### 基线修改

```cmd
#查询帮助
cargo run -p attestation_cli -- baseline update -h

#修改基线
cargo run -p attestation_cli -- -u "test_lyt" baseline update \
	--id "757737811267856835" \
	--name "new_name" \
	--description "new_description" \
	--content @/home/test/baseline.txt \
	--attester-type "tpm_ima" \
	--is-default false
	
cargo run -p attestation_cli -- -u "test_lyt" baseline update \
	--id "757737811267856835" \
	--name "new_name" \
	--description "new_description" \
	--content "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJyZWZlcmVuY2VWYWx1ZXMiOlt7ImZpbGVOYW1lIjoic3l5eC0xLlBBVCIsInNoYTI1NiI6IjEyMzQ1NiJ9XX0.GXywOcuhqz05b-9TVx5cHCkcV8Rxy0v3XY3Aex5H9z5jXdmvl3kfV-wkZXgZJWf2LoOqD8YE3dXG-MhxzLqGAu2GeRoVhg-bXsd1Gzn1QM5_Who3quYXu4jKLbGR4EwVlEoK9M8Oa0eUVeA14R1kKyZ4cdDEir2u_Z_mXa_0RapVUoePAipNsVocs3xXSsppxTE1xOHe6VmV71GbCU-UE9O5GvGu_SeTljvuLV4uFCi4UXmy3VIzULAybPbS_n4vSvOazNeHTTq787ifn6c6n5-kZu0KP7AR96tOnLLG_f1giSu9XbFsntCPu9FNNzx6cO6BHHlDAOQhiJcSK2rzSQ" \
	--attester-type "tpm_ima" \
	--is-default false
```
#### 基线查询

```cmd
#查询帮助
cargo run -p attestation_cli -- baseline get -h

#查询全部基线
cargo run -p attestation_cli -- -u "test_lyt" baseline get

#根据基线类型查询
cargo run -p attestation_cli -- -u "test_lyt" baseline get \
	--attester-type "tpm_ima" 

#根据基线id查询
cargo run -p attestation_cli -- -u "test_lyt" baseline get \
	--ids "id1" "id2"
```



### Nonce管理

```cmd
#查询Nonce管理命令帮助
cargo run -p attestation_cli -- nonce -h
```

#### 获取Nonce

```cmd
#查询帮助
cargo run -p attestation_cli -- nonce get -h
	
#获取Nonce
cargo run -p attestation_cli -- -u "test_lyt" nonce get --out "/tmp/nonce.txt"
```



### 证据管理

```cmd
#查询证据管理命令帮助
cargo run -p attestation_cli -- evidence -h
```

#### 获取证据

```cmd
#查询帮助
cargo run -p attestation_cli -- evidence get -h

#获取证据
cargo run -p attestation_cli -- evidence get \
	--nonce-type "ignore" \
	--content @/tmp/nonce.txt \
	--out "/tmp/evidence.txt"

cargo run -p attestation_cli -- evidence get \
	--nonce-type "default" \
	--user-nonce "user_nonce" \
	--content "{iat: 1745850626, value: "8g5t/g5xfMJq5duxDaOB3WcCS4UVUlzXb4w4A9TBmmaFBCwokG6Ypsv82IQb0jRjD6ouinoUiwFYYxq/04qI5Q==", signature: "mTHGMz62jf2v4MLf151S9Y3sMW80ebwJDn+Fgq7UKJKcABTw5tVx2ewX8tY6eIxBXjaV5BiGcT6Ujnu7W6OWsfydl3YqspJyN4t0VD4rZb498zztKyDuV7RkktlhILxYI8zbAMxfbrSXBsnqnoKcikyBG41O6A3hf7PYW41VV7R2/vHQo/ETUjFa0Ie5oaHYPbTeTrJIUCv+cTL4otM2cyfFtWhHcynVlALmSvkW1fibUaO057ovwJUApRBCu1XPpj9LMP2LZEvl+BselxH5aiayZ9BM7UHqDPeSgT8HdIYjDnq01IhJdiy7SW5QgO3QS9rUyhQhotC9jnqzaLETOzYqlwabAyB4d8PhhUaRYcAo2E95E+yXoviHujik93EGgW6qoP0spdrr3mi/nWhhP329bihI+dIjxy8vL2kTIpbvjZWzfc6wVuBLeQJU6WtrZ8h06UKdloUi57ntFS96GwsJHb85vsXF16kuTYPsL0uUZhXNzlYbmo1PMK1SL+t3" }"
	--out "/tmp/evidence.txt"
```



### 挑战管理

```cmd
#查询挑战管理命令帮助
cargo run -p attestation_cli -- attest -h

#挑战
cargo run -p attestation_cli -- -u "test_lyz" attest \
	--file "/tmp/evidence.txt" \
	--out "/tmp/token.txt"
```



### Token管理

```cmd
#查询Token管理命令帮助
cargo run -p attestation_cli -- token -h
```

#### Token验证

```cmd
#查询帮助
cargo run -p attestation_cli -- token verify -h

#验证Token,根据文件
cargo run -p attestation_cli -- token verify \
	--file "/tmp/token.txt"

#验证Token,根据输入
cargo run -p attestation_cli -- token verify \
	--token "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6ImprdSIsImtpZCI6ImtpZCJ9.eyJpbnR1c2UiOiJHZW5lcmljIiwic3RhdHVzIjoidW5rbm93biIsInVlaWQiOiJUUE0gQUsiLCJ0cG1fYm9vdCI6eyJhdHRlc3RhdGlvbl9zdGF0dXMiOiJ1bmtub3duIiwiaXNfbG9nX3ZhbGlkIjp0cnVlLCJwY3JzIjp7Imhhc2hfYWxnIjoic2hhMjU2IiwicGNyX3ZhbHVlcyI6W3siaXNfbWF0Y2hlZCI6dHJ1ZSwicGNyX2luZGV4IjowLCJwY3JfdmFsdWUiOiJlMjFiNzAzZWU2OWM3NzQ3NmJjY2I0M2VjMDMzNmE5YTFiMjkxNGIzNzg5NDRmN2IwMGExMDIxNGNhOGZlYTkzIiwicmVwbGF5X3ZhbHVlIjoiZTIxYjcwM2VlNjljNzc0NzZiY2NiNDNlYzAzMzZhOWExYjI5MTRiMzc4OTQ0ZjdiMDBhMTAyMTRjYThmZWE5MyJ9LHsiaXNfbWF0Y2hlZCI6dHJ1ZSwicGNyX2luZGV4IjoxLCJwY3JfdmFsdWUiOiJhMzJiZjhiZjMyOTkwN2RjMmI0ODM5ZmYzYzYxYjQ1NmE5ODU2ZDEyMTEwZjQ5ZDQ5MGRmMzNiYWYxODkzNDBlIiwicmVwbGF5X3ZhbHVlIjoiYTMyYmY4YmYzMjk5MDdkYzJiNDgzOWZmM2M2MWI0NTZhOTg1NmQxMjExMGY0OWQ0OTBkZjMzYmFmMTg5MzQwZSJ9LHsiaXNfbWF0Y2hlZCI6dHJ1ZSwicGNyX2luZGV4IjoyLCJwY3JfdmFsdWUiOiJhOWQ1YmRmM2IwYjAzNGE0MzRlZjNhZGRlMmQ1Y2IwYTc1MzM4MDNmOTdmODg4OWYxMTc0YWI2MGJkNGRjYjcwIiwicmVwbGF5X3ZhbHVlIjoiYTlkNWJkZjNiMGIwMzRhNDM0ZWYzYWRkZTJkNWNiMGE3NTMzODAzZjk3Zjg4ODlmMTE3NGFiNjBiZDRkY2I3MCJ9LHsiaXNfbWF0Y2hlZCI6dHJ1ZSwicGNyX2luZGV4IjozLCJwY3JfdmFsdWUiOiJlMjFiNzAzZWU2OWM3NzQ3NmJjY2I0M2VjMDMzNmE5YTFiMjkxNGIzNzg5NDRmN2IwMGExMDIxNGNhOGZlYTkzIiwicmVwbGF5X3ZhbHVlIjoiZTIxYjcwM2VlNjljNzc0NzZiY2NiNDNlYzAzMzZhOWExYjI5MTRiMzc4OTQ0ZjdiMDBhMTAyMTRjYThmZWE5MyJ9LHsiaXNfbWF0Y2hlZCI6dHJ1ZSwicGNyX2luZGV4Ijo0LCJwY3JfdmFsdWUiOiJmY2U3ZjEwODMwODJiMTZjZmUyYjA4NWRkNzg1OGJiMTFhMzdjMDliNzhlMzZjNzllNWEyZmQ1MjkzNTNjNGUyIiwicmVwbGF5X3ZhbHVlIjoiZmNlN2YxMDgzMDgyYjE2Y2ZlMmIwODVkZDc4NThiYjExYTM3YzA5Yjc4ZTM2Yzc5ZTVhMmZkNTI5MzUzYzRlMiJ9LHsiaXNfbWF0Y2hlZCI6dHJ1ZSwicGNyX2luZGV4Ijo1LCJwY3JfdmFsdWUiOiI4ZWRkZTkxMjY5OWNlZGRkZGM3ZDlhM2Q3ZWU0NGE4YjFiMTkxMDgxNTY5MmRlZjZjOWU2MzdlMmI5MzlmOTQxIiwicmVwbGF5X3ZhbHVlIjoiOGVkZGU5MTI2OTljZWRkZGRjN2Q5YTNkN2VlNDRhOGIxYjE5MTA4MTU2OTJkZWY2YzllNjM3ZTJiOTM5Zjk0MSJ9LHsiaXNfbWF0Y2hlZCI6dHJ1ZSwicGNyX2luZGV4Ijo2LCJwY3JfdmFsdWUiOiJlMjFiNzAzZWU2OWM3NzQ3NmJjY2I0M2VjMDMzNmE5YTFiMjkxNGIzNzg5NDRmN2IwMGExMDIxNGNhOGZlYTkzIiwicmVwbGF5X3ZhbHVlIjoiZTIxYjcwM2VlNjljNzc0NzZiY2NiNDNlYzAzMzZhOWExYjI5MTRiMzc4OTQ0ZjdiMDBhMTAyMTRjYThmZWE5MyJ9LHsiaXNfbWF0Y2hlZCI6dHJ1ZSwicGNyX2luZGV4Ijo3LCJwY3JfdmFsdWUiOiJlMjFiNzAzZWU2OWM3NzQ3NmJjY2I0M2VjMDMzNmE5YTFiMjkxNGIzNzg5NDRmN2IwMGExMDIxNGNhOGZlYTkzIiwicmVwbGF5X3ZhbHVlIjoiZTIxYjcwM2VlNjljNzc0NzZiY2NiNDNlYzAzMzZhOWExYjI5MTRiMzc4OTQ0ZjdiMDBhMTAyMTRjYThmZWE5MyJ9XX0sInNlY3VyZV9ib290IjoiTkEifSwidHBtX2ltYSI6eyJhdHRlc3RhdGlvbl9zdGF0dXMiOiJ1bmtub3duIiwiaXNfbG9nX3ZhbGlkIjpmYWxzZSwicGNycyI6eyJoYXNoX2FsZyI6InNoYTI1NiIsInBjcl92YWx1ZXMiOlt7ImlzX21hdGNoZWQiOmZhbHNlLCJwY3JfaW5kZXgiOjEwLCJwY3JfdmFsdWUiOiJhNmE2ZjI3NWY0OTVkYjExZTY2YTVjNmI4YTIzMzk1ZWFiNzU0N2Q0ZTdlZWNjNDNjODJjNDM4NmUzNmUwYWUxIiwicmVwbGF5X3ZhbHVlIjoiMjFiNTMwNzE5NzYwNTRlNzc1MzMyNTVmMTI2MjhiZmU1MjM0NDM4OGZjMmY0MjVhMjhmZDRkNDg3YWFiZDcxNCJ9XX19LCJpYXQiOjE3NDU4OTYyNDE5NzksImV4cCI6MTc0NTg5Njg0MTk3OSwiaXNzIjoiaXNzIiwianRpIjoiN2E0NTJkYTMtZWViNC00ZTA4LTk1NDgtMzA1MDBiODU3ZWFjIiwidmVyIjoiMS4wIiwibmJmIjoxNzQ1ODk2MjQxOTc5LCJlYXRfcHJvZmlsZSI6ImVhdF9wcm9maWxlIn0.REN8JXOwM6grjCJ3u4BO6DGrXTzx8kRIDv8WSo6Aod572tPgc3BbOKGCIdd7C3BBL-gwqlEXMAy0JAcU7LwsgIE7rZhvAsEmLZnActhObt8jXCAB3gqyyx1q3_mMZw4uDTzYelE20p1T0Cio_JBUjzYmRUzin2rjt1ObKJBwnrKJW8DUxNSNOf1NO0xWlpHdZ32XkdXgjJidIye14HC8guWqFpQPHTSbfO8vOAxH5TGheBUsWdCvWTPDel3NwYaqyJwB5ypdOsISJvXkf3zW3h6V-enfb6sCCAFbuOirNi4dkwSiYs8k7U71VMN7rMS9OcA7pYpkmT9XjWopRhe-RKRcKpOpTKu1DrxgwFMpK6EfqAmZSBjnhyi92qbg-HsaJvUSIQY44Cf0ZtZxcQUR-fDVgrzLUm4VUyPMzRMHKkyaQLbjlm0fgfv0VupbHGZkhH61z7yuH7pUJBvG-xAWJlrqGSvRXWYk-PuklPTYdXs0SHfKKlkB5fT6kyqJEVl0" "token2"
```

