package verification

default hardware_value = 96
default executables_value = 96

get(key) = value {
    value := object.get(input, key, "___KEY_NOT_EXIST___")
    value != "___KEY_NOT_EXIST___"
} else = "___KEY_NOT_EXIST___"

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
    "vcca_ccel_ref_value_match_status": get("vcca_ccel_ref_value_match_status"),
    "vcca_platform_token_profile": get("vcca_platform_token_profile"),
    "vcca_platform_token_implementation": get("vcca_platform_token_implementation"),
    "vcca_platform_token_instance": get("vcca_platform_token_instance"),
    "vcca_platform_token_config": get("vcca_platform_token_config"),
    "vcca_platform_token_lifecycle": get("vcca_platform_token_lifecycle"),
    "vcca_platform_token_sw_components": get("vcca_platform_token_sw_components"),
    "vcca_platform_token_verification_service": get("vcca_platform_token_verification_service"),
    "vcca_platform_token_hash_algo": get("vcca_platform_token_hash_algo"),
}

filtered_base_fields[filtered_key] = filtered_value {
    some key
    value := base_fields[key]
    value != "___KEY_NOT_EXIST___"
    filtered_key = key
    filtered_value = value
}

firmware_state := object.get(input, ["vcca_ccel_log_data", "firmware_state"], null)

extra_fields = {"vcca_firmware_state": firmware_state} {
    firmware_state != null
}
extra_fields = {} {
    firmware_state == null
}

# hardware value calculation
hardware_value = 2 {
    filtered_base_fields.vcca_ccel_log_status == "replay_success"
    filtered_base_fields.vcca_ccel_ref_value_match_status == "ignore"
}

hardware_value = 0 {
    filtered_base_fields.vcca_ccel_log_status == "no_log"
}

# executables value calculation
executables_value = 2 {
    filtered_base_fields.vcca_ima_log_status == "replay_success"
    filtered_base_fields.vcca_ima_ref_value_match_status == "matched"
}

executables_value = 0 {
    filtered_base_fields.vcca_ima_log_status == "no_log"
}

result := {
    "annotated_evidence": object.union(filtered_base_fields, extra_fields),
    "ear_trustworthiness_vector": {
        "hardware": hardware_value,
        "executables": executables_value
    }
}