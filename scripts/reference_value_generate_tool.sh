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
source_type="file"  # Default source type for IMA mode, can be "file", "log" or "digest"
digest_tool="manage_digest_lists"
digest_dir="/etc/ima/digest_lists.tlv/"


# Help information function
show_help() {
    echo -e "${BLUE}Script function:${NC} Generate IMA baseline or RIM baseline"
    echo -e "${BLUE}Parameter description:${NC}"
    echo "  -m    Generation mode, required, supports ima/rim"
    echo "  -f    Path parameter, required for certain modes:"
    echo "        - IMA mode with -s file: Specify directory path for measurement (required)"
    echo "        - RIM mode combo 1: Specify firmware path (required with -d/-v)"
    echo "  -a    Select hash algorithm, used only in IMA mode, optional, default is sha256, supports: sha256/sha384/sha512/sm3"
    echo "  -s    Source type for IMA mode, optional, default is file, supports: file/log/digest"
    echo "        - file: Generate from files in specified directory (requires -f)"
    echo "        - log: Generate from /sys/kernel/security/ima/ascii_runtime_measurements"
    echo "        - digest: Generate from $digest_dir using $digest_tool"
    echo "  -d    DTB file path, required for RIM mode"
    echo "  -v    vcpu_nums: number of virtual CPUs, required for RIM mode"
    echo "  -k    kernel_path: guest kernel path, required for RIM mode combo 2"
    echo "  -i    initramfs_path: initramfs path, optional for RIM mode combo 2"
    echo "  -h    Show help information"
    echo -e "${BLUE}Usage examples:${NC}"
    echo "  IMA mode from files: ./reference_value_generate_tool.sh -m ima -f /opt -a sha256 -s file"
    echo "  IMA mode from log: ./reference_value_generate_tool.sh -m ima -a sha256 -s log"
    echo "  IMA mode from digest: ./reference_value_generate_tool.sh -m ima -a sha256 -s digest"
    echo "  RIM mode (combo 1): ./reference_value_generate_tool.sh -m rim -f /firmware -d /dtb -v 2"
    echo "  RIM mode (combo 2): ./reference_value_generate_tool.sh -m rim -k /kernel -d /dtb -v 2"
    echo "  RIM mode (combo 2 with initramfs): ./reference_value_generate_tool.sh -m rim -k /kernel -d /dtb -i /initramfs -v 2"
}


# Parse command line parameters
while getopts "m:f:a:d:v:k:i:hs:" opt; do
    case $opt in
        m) mode="$OPTARG" ;;
        f) file_path="$OPTARG" ;;
        a) algorithm="$OPTARG" ;;
        d) dtb_path="$OPTARG" ;;
        v) vcpu_nums="$OPTARG" ;;
        k) kernel_path="$OPTARG" ;;
        i) initramfs_path="$OPTARG" ;;
        s) source_type="$OPTARG" ;;
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
    # Verify source type validity
    if ! [[ " file log digest " =~ " $source_type " ]]; then
        echo -e "${RED}Error:${NC} Unsupported source type $source_type, supported types: file log digest" >&2; exit 1
    fi

    # For file source type, -f is required
    if [ "$source_type" = "file" ] && [ -z "$file_path" ]; then
        echo -e "${RED}Error:${NC} -f is required when using -s file (specify directory path)" >&2; exit 1
    fi

    # For non-file source types, warn if -f is provided
    if [ "$source_type" != "file" ] && [ -n "$file_path" ]; then
        echo -e "${YELLOW}Warning:${NC} -f parameter is ignored for source type $source_type" >&2
    fi

    # Verify algorithm validity
    if ! [[ " ${supported_algs[@]} " =~ " $algorithm " ]]; then
        echo -e "${RED}Error:${NC} Unsupported algorithm $algorithm, supported algorithms: ${supported_algs[*]}" >&2; exit 1
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

        if [ "$source_type" = "file" ]; then
            # Convert user input path to absolute path
            file_path=$(realpath "$file_path")

            # Verify directory validity
            if [ ! -d "$file_path" ]; then
                echo -e "${RED}Error:${NC} $file_path is not a valid directory" >&2; exit 1
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
        elif [ "$source_type" = "log" ]; then
            ima_log="/sys/kernel/security/ima/ascii_runtime_measurements"

            # Verify IMA log file exists and is readable
            if [ ! -r "$ima_log" ]; then
                echo -e "${RED}Error:${NC} IMA log file $ima_log not found or not readable" >&2
                echo -e "${YELLOW}Notice:${NC} Ensure IMA is enabled in kernel and securityfs is mounted" >&2
                exit 1
            fi

            # Filter lines that contain the specified algorithm and extract relevant information
            # Format of ascii_runtime_measurements lines: <pcr> <template_hash> <algorithm>:<hash> <path>
            filtered_lines=$(grep "$algorithm:" "$ima_log")
            total=$(echo "$filtered_lines" | wc -l | awk '{print $1}')
            count=0

            if [ "$total" -gt 0 ]; then
                while IFS= read -r line; do
                    count=$((count + 1))

                    # Extract hash value and file path
                    # Format: <pcr> <template_hash> <template_name> <algorithm>:<hash> <path>
                    hash_value=$(echo "$line" | awk -v alg="$algorithm:" '{for(i=1;i<=NF;i++) if($i ~ alg) {split($i,arr,":"); print arr[2]; break}}')
                    file_path=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i ~ /:/) {for(j=i+1;j<=NF;j++) printf "%s ", $j; break}}' | sed 's/ $//')

                    # Process path escaping
                    escaped_name=$(escape_path "$file_path")

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
                done <<< "$filtered_lines"
            else
                echo -e "${YELLOW}Notice:${NC} No entries found in $ima_log with $algorithm algorithm" >&2
            fi
        else  # source_type is "digest"
            # Check if manage_digest_lists tool exists
            if ! command -v "$digest_tool" &> /dev/null; then
                echo -e "${RED}Error:${NC} $digest_tool tool not found, please install it first: yum install digest-list-tools" >&2
                exit 1
            fi

            # Check if digest directory exists
            if [ ! -d "$digest_dir" ]; then
                echo -e "${RED}Error:${NC} Digest directory $digest_dir not found" >&2
                exit 1
            fi

            # Get digest list using the tool
            echo -e "${BLUE}Extracting digest information using $digest_tool...${NC}"
            digest_output=$($digest_tool -p dump -d "$digest_dir")

            # Check if command succeeded
            if [ $? -ne 0 ]; then
                echo -e "${RED}Error:${NC} Failed to extract digest information from $digest_dir" >&2
                exit 1
            fi

            # Process output lines
            total=$(echo "$digest_output" | wc -l | awk '{print $1}')
            count=0

            if [ "$total" -gt 0 ]; then
                while IFS= read -r line; do
                    count=$((count + 1))

                    # Extract IMA digest and path using regex
                    ima_digest=$(echo "$line" | sed -n 's/.*IMA digest: \([^|]*\).*/\1/p')
                    file_path=$(echo "$line" | sed -n 's/.*path: \([^|]*\).*/\1/p')

                    # Skip if we couldn't extract required fields
                    if [ -z "$ima_digest" ] || [ -z "$file_path" ]; then
                        continue
                    fi

                    # Process path escaping
                    escaped_name=$(escape_path "$file_path")

                    # Output JSON object
                    echo "        {"
                    echo "            \"fileName\": \"$escaped_name\","
                    echo "            \"$algorithm\": \"$ima_digest\""

                    # No comma for last element
                    if [ $count -eq $total ]; then
                        echo "        }"
                    else
                        echo "        },"
                    fi
                done <<< "$digest_output"
            else
                echo -e "${YELLOW}Notice:${NC} No digest entries found in $digest_dir" >&2
            fi
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
