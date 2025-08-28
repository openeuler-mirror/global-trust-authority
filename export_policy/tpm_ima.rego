package verification

default log_status = "no_log"
default ref_value_match_status = "ignore"

log_status = status {
    some i
    logs := input.evidence.logs
    logs[i].log_type == "ImaLog"
    status := logs[i].log_status
}

ref_value_match_status = status {
    some i
    logs := input.evidence.logs
    logs[i].log_type == "ImaLog"
    status := logs[i].ref_value_match_status
}

pcrs = pcrs_out {
    pcrs_out := input.evidence.pcrs
} else = pcrs_out {
    not input.evidence.pcrs
    pcrs_out := null
}

# executables value calculation
executables_value = 2 {
    log_status == "replay_success"
    ref_value_match_status == "matched"
}

executables_value = 0 {
    log_status == "no_log"
}

executables_value = 96 {
    not (log_status == "replay_success"); not (ref_value_match_status == "matched")
    not (log_status == "no_log")
}

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
