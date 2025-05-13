package verification

# Extract secure_boot status: yes if any matching entry found with yes, else no
default secure_boot = "no"
secure_boot = "yes" {
    some i, j
    logs := input.evidence.logs
    logs[i].log_type == "TcgEventLog"
    event := logs[i].log_data.event_log[j]
    event.event_type == "EV_EFI_VARIABLE_DRIVER_CONFIG"
    event.event.unicode_name == "SecureBoot"
    lower(event.event.variable_data.SecureBoot.enabled) == "yes"
}

# Extract is_log_valid from first TcgEventLog log
is_log_valid = valid {
    some i
    logs := input.evidence.logs
    logs[i].log_type == "TcgEventLog"
    valid := logs[i].is_log_valid
}

# Check if pcrs 0-7 are present in any hash algorithm (sha1, sha256, sha384, sha512)
pcr_present {
    all := {x | x := [0,1,2,3,4,5,6,7][_]}
    measured := {pcr | input.evidence.pcrs.pcr_values[_].pcr_index == pcr}
    all_pcrs_subset := all - measured
    count(all_pcrs_subset) == 0
}

# Attestation valid if all conditions met
default attestation_valid = false
attestation_valid {
    secure_boot == "yes"
    is_log_valid == true
    pcr_present
}

# Output result
result = {
    "attestation_valid": attestation_valid,
    "custom_data": {
        "hash_alg": input.evidence.pcrs.hash_alg
    }
}
