package verification

default is_log_valid = false

is_log_valid {
    some i
    logs := input.evidence.logs
    logs[i].log_type == "DimLog"
    logs[i].is_log_valid == true
}

pcrs = pcrs_out {
    pcrs_out := input.evidence.pcrs
} else = pcrs_out {
    not input.evidence.pcrs
    pcrs_out := null
}

result = {
    "is_log_valid": is_log_valid,
    "pcrs": pcrs,
}