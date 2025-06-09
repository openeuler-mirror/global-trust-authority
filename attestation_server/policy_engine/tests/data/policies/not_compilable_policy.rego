package verification

# Intentionally invalid Rego policy with syntax errors
result = {
    "attestation_valid": attestation_valid
    "custom_data": {  
        "matching_pcrs": matching_pcrs
        "measured_values": input.pcrs.sha256,  
        "reference_values": reference_pcr_values
    }
}

# Undefined variable
attestation_valid = undefined_var

# Invalid rule syntax
matching_pcrs = [ pcr_idx | input.pcrs.sha256[pcr_idx] = reference_pcr_values[pcr_idx] ]  
