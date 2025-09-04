package verification

default secure_boot = "NA"

# Extract secure_boot status
secure_boot = "enabled" {
    some i
    logs := input.evidence.logs
    logs[i].log_type == "TcgEventLog"
    some j
    event := logs[i].log_data.event_log[j]
    event.event_type == "EV_EFI_VARIABLE_DRIVER_CONFIG"
    event.event.unicode_name == "SecureBoot"
    lower(event.event.variable_data.SecureBoot.enabled) == "yes"
}

secure_boot = "disabled" {
    some i
    logs := input.evidence.logs
    logs[i].log_type == "TcgEventLog"
    some j
    event := logs[i].log_data.event_log[j]
    event.event_type == "EV_EFI_VARIABLE_DRIVER_CONFIG"
    event.event.unicode_name == "SecureBoot"
    lower(event.event.variable_data.SecureBoot.enabled) == "no"
}

# Extract log status
log_status = status {
    some i
    logs := input.evidence.logs
    logs[i].log_type == "TcgEventLog"
    status := logs[i].log_status
}

# Extract ref_value_match_status
ref_value_match_status = status {
    some i
    logs := input.evidence.logs
    logs[i].log_type == "TcgEventLog"
    status := logs[i].ref_value_match_status
}

# Extract pcrs (if present)
pcrs = pcrs_out {
    pcrs_out := input.evidence.pcrs
} else = pcrs_out {
    # If not present, output null
    not input.evidence.pcrs
    pcrs_out := null
}

# Hardware value calculation
hardware_value = 2 {
    log_status == "replay_success"
    ref_value_match_status == "ignore"
}

hardware_value = 0 {
    log_status == "no_log"
}

hardware_value = 96 {
    not (log_status == "replay_success"); not (ref_value_match_status == "ignore")
    not (log_status == "no_log")
}

# Output object
result = {
    "annotated_evidence": {
        "secure_boot": secure_boot,
        "log_status": log_status,
        "ref_value_match_status": ref_value_match_status,
        "pcrs": pcrs,
    },
    "ear_trustworthiness_vector": {
        "hardware": hardware_value
    }
}
