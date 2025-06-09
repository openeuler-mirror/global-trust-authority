package verification

default secure_boot = "NA"

# 1. Extract secure_boot status
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

# 2. Extract is_log_valid
is_log_valid = valid {
    some i
    logs := input.evidence.logs
    logs[i].log_type == "TcgEventLog"
    valid := logs[i].is_log_valid
}

# 3. Extract pcrs (if present)
pcrs = pcrs_out {
    pcrs_out := input.evidence.pcrs
} else = pcrs_out {
    # If not present, output null
    not input.evidence.pcrs
    pcrs_out := null
}

# Output object
result = {
    "secure_boot": secure_boot,
    "is_log_valid": is_log_valid,
    "pcrs": pcrs,
}