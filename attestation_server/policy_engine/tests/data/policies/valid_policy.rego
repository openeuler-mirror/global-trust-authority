package verification

# Check if PCR values match
pcr_values_match {
    some pcr_idx
    input.pcrs.sha256[pcr_idx] == reference_pcr_values[pcr_idx]
}

# Get list of matching PCRs
matching_pcrs = pcrs {
    pcrs := {pcr_idx | 
        some pcr_idx
        input.pcrs.sha256[pcr_idx] == reference_pcr_values[pcr_idx]
    }
}

# Define reference PCR values
reference_pcr_values = {
    "0": "0x737f767a12f54e70eecbc8684011323ae2fe2dd9f90785577969d7a2013e8c12",
    "1": "0x6b0bbcc0d97a82a589af03335e6ed7bd00e07129e884c56bb7dca49a4282814a",
    "2": "0x3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
    "3": "0x3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
    "4": "0xabe8b3fa6aecb36c2fd93c6f6edde661c21b353d007410a2739d69bfa7e1b9be"
}

# Check if attestation is valid
attestation_valid = true {
    count(matching_pcrs) == count(reference_pcr_values)
}

default attestation_valid = false

# Return final result
result = {
    "attestation_valid": attestation_valid,
    "custom_data": {
        "matching_pcrs": matching_pcrs,
        "measured_values": input.pcrs.sha256,
        "reference_values": reference_pcr_values
    }
}
