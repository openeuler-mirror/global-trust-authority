#!/bin/bash

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Initialize variables
mode=""
file_path=""  # Universal path parameter: directory path for IMA mode, firmware path for RIM mode
algorithm="sha256"  # Default algorithm
supported_algs=("sha256" "sha384" "sha512" "sm3")  # Supported algorithms
output_file="reference_value.json"  # Output file name for IMA mode
gen_rim_path="/usr/bin/gen_rim_ref"  # Path to RIM tool


# Help information function
show_help() {
    echo -e "${BLUE}Script function:${NC} Generate IMA baseline or RIM baseline"
    echo -e "${BLUE}Parameter description:${NC}"
    echo "  -m    Generation mode, required, supports ima/rim"
    echo "  -f    Path parameter:"
    echo "        - IMA mode: Specify directory path for measurement, optional, default is current directory"
    echo "        - RIM mode: Specify firmware path, required when using with -d/-v"
    echo "  -a    Select hash algorithm, used only in IMA mode, optional, default is sha256, supports: sha256/sha384/sha512/sm3"
    echo "  -d    DTB file path, required for RIM mode"
    echo "  -v    vcpu_nums: number of virtual CPUs, required for RIM mode"
    echo "  -k    kernel_path: guest kernel path, required for RIM mode combo 2"
    echo "  -i    initramfs_path: initramfs path, optional for RIM mode combo 2"
    echo "  -h    Show help information"
    echo -e "${BLUE}Usage examples:${NC}"
    echo "  IMA mode: ./reference_value_generate_tool.sh -m ima -f /opt -a sha256"
    echo "  RIM mode (combo 1): ./reference_value_generate_tool.sh -m rim -f /firmware -d /dtb -v 2"
    echo "  RIM mode (combo 2): ./reference_value_generate_tool.sh -m rim -k /kernel -d /dtb -v 2"
    echo "  RIM mode (combo 2 with initramfs): ./reference_value_generate_tool.sh -m rim -k /kernel -d /dtb -i /initramfs -v 2"
}


# Parse command line parameters
while getopts "m:f:a:d:v:k:i:h" opt; do
    case $opt in
        m) mode="$OPTARG" ;;
        f) file_path="$OPTARG" ;;
        a) algorithm="$OPTARG" ;;
        d) dtb_path="$OPTARG" ;;
        v) vcpu_nums="$OPTARG" ;;
        k) kernel_path="$OPTARG" ;;
        i) initramfs_path="$OPTARG" ;;
        h) show_help; exit 0 ;;
        \?) echo -e "${RED}Error:${NC} Invalid parameter -$OPTARG" >&2; exit 1 ;;
        :) echo -e "${RED}Error:${NC} Parameter -$OPTARG requires a value" >&2; exit 1 ;;
    esac
done


# Verify required parameters
if [ -z "$mode" ]; then
    echo -e "${RED}Error:${NC} -m is a required parameter, specify mode (ima/rim)" >&2; exit 1
fi


# IMA mode processing
if [ "$mode" = "ima" ]; then
    # Process file path (default to current directory) and convert to absolute path
    if [ -z "$file_path" ]; then
        file_path="$PWD"
        echo -e "${YELLOW}Notice:${NC} -f not specified, default processing directory: $file_path"
    else
        # Convert user input path to absolute path
        file_path=$(realpath "$file_path")
    fi

    # Verify directory validity
    if [ ! -d "$file_path" ]; then
        echo -e "${RED}Error:${NC} $file_path is not a valid directory" >&2; exit 1
    fi

    # Verify algorithm validity
    if ! [[ " ${supported_algs[@]} " =~ " $algorithm " ]]; then
        echo -e "${RED}Error:${NC} Unsupported algorithm $algorithm, supported algorithms: ${supported_algs[*]}" >&2; exit 1
    fi

    # Check if hash command exists
    hash_cmd="${algorithm}sum"
    if ! command -v "$hash_cmd" &> /dev/null; then
        # Special handling for sm3, some systems may use gmssl sm3
        if [ "$algorithm" = "sm3" ] && command -v "gmssl" &> /dev/null; then
            hash_cmd="gmssl sm3 -r"
        else
            echo -e "${RED}Error:${NC} $hash_cmd command not found, please install the corresponding tool (sm3 requires national cryptographic library)" >&2; exit 1
        fi
    fi

    # Simple path escape processing (only escape double quotes)
    escape_path() {
        local path="$1"
        echo "$path" | sed 's/"/\\"/g'
    }

    # Generate standard JSON format
    {
        echo "{"
        echo "    \"referenceValues\": ["

        files=$(find "$file_path" -type f | sort)
        total=$(echo "$files" | wc -l | awk '{print $1}')
        count=0

        if [ "$total" -gt 0 ]; then
            while IFS= read -r file; do
                count=$((count + 1))

                # Get absolute path of file
                abs_path=$(realpath "$file")

                # Process path escaping
                escaped_name=$(escape_path "$abs_path")

                # Calculate hash value
                if [ "$algorithm" = "sm3" ] && [ "$hash_cmd" = "gmssl sm3 -r" ]; then
                    hash_value=$(gmssl sm3 -r "$file" | awk '{print $1}')
                else
                    hash_value=$("$hash_cmd" "$file" | awk '{print $1}')
                fi

                # Output JSON object
                echo "        {"
                echo "            \"fileName\": \"$escaped_name\","
                echo "            \"$algorithm\": \"$hash_value\""

                # No comma for last element
                if [ $count -eq $total ]; then
                    echo "        }"
                else
                    echo "        },"
                fi
            done <<< "$files"
        fi

        echo "    ]"
        echo "}"
    } > "$output_file"

    echo -e "${GREEN}IMA baseline generated:${NC} $(realpath "$output_file")"
    exit 0
fi


# RIM mode processing
if [ "$mode" = "rim" ]; then
    # Check if RIM tool exists
    if [ ! -x "$gen_rim_path" ]; then
        echo -e "${RED}Error:${NC} $gen_rim_path tool not found, please install first: sudo yum install virtCCA_sdk" >&2
        exit 1
    fi

    # Verify one of the two parameter combinations
    combo1=false  # Combo 1: -f (firmware) -d -v
    combo2=false  # Combo 2: -k -d -v (-i optional)

    # Check combo 1: whether -f, -d, -v all exist
    if [ -n "$file_path" ] && [ -n "$dtb_path" ] && [ -n "$vcpu_nums" ]; then
        combo1=true
    fi

    # Check combo 2: whether -k, -d, -v all exist (-i optional)
    if [ -n "$kernel_path" ] && [ -n "$dtb_path" ] && [ -n "$vcpu_nums" ]; then
        combo2=true
    fi

    # Verify parameter combination validity
    if [ "$combo1" = false ] && [ "$combo2" = false ]; then
        echo -e "${RED}Error:${NC} RIM mode requires one of the following parameter combinations:" >&2
        echo "  Combo 1: -f <firmware_path> -d <dtb_path> -v <vcpu_nums>" >&2
        echo "  Combo 2: -k <kernel_path> -d <dtb_path> -v <vcpu_nums> [-i <initramfs_path>]" >&2
        echo "         where -i parameter in combo 2 is optional" >&2
        exit 1
    fi

    # Build RIM tool command
    if [ "$combo1" = true ]; then
        # Combo 1: use -f as firmware path
        cmd="$gen_rim_path -f \"$file_path\" -d \"$dtb_path\" -v \"$vcpu_nums\""
    else
        # Combo 2: use -k, -d, -v parameters, -i optional
        cmd="$gen_rim_path -k \"$kernel_path\" -d \"$dtb_path\" -v \"$vcpu_nums\""
        # If initramfs path is provided, add to command
        if [ -n "$initramfs_path" ]; then
            cmd="$cmd -i \"$initramfs_path\""
        fi
    fi

    # Execute command and output results directly
    echo -e "${BLUE}Executing RIM baseline generation command:${NC} $cmd"
    eval "$cmd"
    exit $?
fi


# Invalid mode handling
echo -e "${RED}Error:${NC} Unsupported mode $mode, only ima/rim are supported" >&2
exit 1
