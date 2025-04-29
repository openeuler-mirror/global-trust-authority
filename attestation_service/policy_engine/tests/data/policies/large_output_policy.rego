package verification

# Generate a large string by repeating a fixed pattern
base_string := concat("", [
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
])

# Generate arrays with repeated elements
array1 := [base_string | _ := numbers.range(0, 500)]
array2 := [base_string | _ := numbers.range(0, 500)]
large_array := array.concat(array1, array2)

# Generate a large map with unique keys
large_map := {num: base_string |
    num := format_int(numbers.range(0, 1000)[_], 10)
}

# Return a large result object that should exceed 500KB
result = {
    "attestation_valid": true,
    "custom_data": {
        "data1": large_array,
        "data2": large_array,
        "data3": large_array,
        "data4": large_array,
        "map1": large_map,
        "map2": large_map,
        "map3": large_map,
        "map4": large_map
    }
}
