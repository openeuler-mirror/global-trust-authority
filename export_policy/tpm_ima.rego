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

result = {
    "log_status": log_status,
    "ref_value_match_status": ref_value_match_status,
    "pcrs": pcrs,
}