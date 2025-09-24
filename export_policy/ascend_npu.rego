package verification

default log_status = "no_log"
default ref_value_match_status = "ignore"
default executables_value = 96

# Extract log status from runtime measurement logs
log_status = status {
    some i
    logs := input.evidence.logs
    logs[i].log_type == "runtime_measurement"
    status := logs[i].log_status
}

# Extract ref_value_match_status from runtime measurement logs
ref_value_match_status = status {
    some i
    logs := input.evidence.logs
    logs[i].log_type == "runtime_measurement"
    status := logs[i].ref_value_match_status
}

# Extract pcrs (if present)
pcrs = pcrs_out {
    pcrs_out := input.evidence.pcrs
} else = pcrs_out {
    not input.evidence.pcrs
    pcrs_out := null
}

# Executables value calculation for AscendNPU runtime measurement
executables_value = 2 {
    log_status == "replay_success"
    ref_value_match_status == "matched"
}

executables_value = 1 {
    log_status == "replay_success"
    ref_value_match_status == "ignore"
}

executables_value = 0 {
    log_status == "no_log"
}

# Output object
result = {
    "annotated_evidence": {
        "log_status": log_status,
        "ref_value_match_status": ref_value_match_status,
        "pcrs": pcrs,
    },
    "ear_trustworthiness_vector": {
        "executables": executables_value
    }
}