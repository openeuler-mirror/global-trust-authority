package verification

get(key) := object.get(input, [key], null)

base_fields = {
    "vcca_rpv": get("vcca_rpv"),
    "vcca_rim": get("vcca_rim"),
    "vcca_rem0": get("vcca_rem0"),
    "vcca_rem1": get("vcca_rem1"),
    "vcca_rem2": get("vcca_rem2"),
    "vcca_rem3": get("vcca_rem3"),
    "vcca_cvm_token_hash_alg": get("vcca_cvm_token_hash_alg"),
    "vcca_ima_log_status": get("vcca_ima_log_status"),
    "vcca_ima_ref_value_match_status": get("vcca_ima_ref_value_match_status"),
    "vcca_ccel_log_status": get("vcca_ccel_log_status"),
    "vcca_ccel_ref_value_match_status": get("vcca_ccel_ref_value_match_status")
}

firmware_state := object.get(input, ["vcca_ccel_log_data", "firmware_state"], null)

extra_fields = {"vcca_firmware_state": firmware_state} {
    firmware_state != null
}
extra_fields = {} {
    firmware_state == null
}

result := object.union(base_fields, extra_fields)