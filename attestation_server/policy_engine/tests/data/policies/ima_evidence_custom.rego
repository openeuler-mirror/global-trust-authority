package verification

# Extract log_status from first tpm_ima log
log_status = status {
    some i
    logs := input.evidence.logs
    logs[i].log_type == "tpm_ima"
    status := logs[i].log_status
}

# Extract ref_value_match_status from first tpm_ima log
ref_value_match_status = status {
    some i
    logs := input.evidence.logs
    logs[i].log_type == "tpm_ima"
    status := logs[i].ref_value_match_status
}

# Check if pcrs 10 is present in any hash algorithm (sha1, sha256, sha384, sha512)
pcr_present {
    all := {x | x := [10][_]}
    measured := {input.evidence.pcrs.pcr_values[i].pcr_index | some i}
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
    "attestation_valid": attestation_valid,
    "custom_data": {
        "hash_alg": input.evidence.pcrs.hash_alg
    }
}
