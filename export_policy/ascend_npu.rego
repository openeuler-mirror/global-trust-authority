package verification

default hardware_value = 96
default executables_value = 96

get(key) = value {
    value := object.get(input, key, "___KEY_NOT_EXIST___")
    value != "___KEY_NOT_EXIST___"
} else = "___KEY_NOT_EXIST___"

base_fields = {
    "ak_cert_verified": get("ak_cert_verified"),
    "quote_verified": get("quote_verified"),
    "pcr_verified": get("pcr_verified"),
    "hash_algorithm": get("hash_algorithm"),
    "pcr_count": get("pcr_count"),
    "pcr_indices": get("pcr_indices"),
    "boot_measurement_verified": get("boot_measurement_verified"),
    "runtime_measurement_verified": get("runtime_measurement_verified"),
    "boot_measurement_message": get("boot_measurement_message"),
    "runtime_measurement_message": get("runtime_measurement_message"),
}

filtered_base_fields[filtered_key] = filtered_value {
    some key
    value := base_fields[key]
    value != "___KEY_NOT_EXIST___"
    filtered_key = key
    filtered_value = value
}

# hardware value calculation based on AK cert and Quote verification
hardware_value = 2 {
    filtered_base_fields.ak_cert_verified == true
    filtered_base_fields.quote_verified == true
    filtered_base_fields.pcr_verified == true
}

hardware_value = 1 {
    filtered_base_fields.ak_cert_verified == true
    filtered_base_fields.quote_verified == true
    filtered_base_fields.pcr_verified != true
}

hardware_value = 0 {
    filtered_base_fields.ak_cert_verified != true
}

# executables value calculation based on measurement logs
executables_value = 2 {
    filtered_base_fields.boot_measurement_verified == true
    filtered_base_fields.runtime_measurement_verified == true
}

executables_value = 1 {
    filtered_base_fields.boot_measurement_verified == true
    filtered_base_fields.runtime_measurement_verified != true
}

executables_value = 1 {
    filtered_base_fields.boot_measurement_verified != true
    filtered_base_fields.runtime_measurement_verified == true
}

executables_value = 0 {
    filtered_base_fields.boot_measurement_verified != true
    filtered_base_fields.runtime_measurement_verified != true
}

result := {
    "annotated_evidence": filtered_base_fields,
    "ear_trustworthiness_vector": {
        "hardware": hardware_value,
        "executables": executables_value
    }
}
