#!/bin/sh

# ==============================================
# Kafka Topic Creation Script
# Usage: ./create_kafka_topic.sh [options]
# ==============================================

# Default configuration
DEFAULT_BOOTSTRAP_SERVER="localhost:9092"
DEFAULT_TOPIC_NAME="ra_token_topic"
DEFAULT_PARTITIONS=3
DEFAULT_REPLICATION_FACTOR=1

# Script directory and Kafka topics script path
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KAFKA_TOPICS_SCRIPT="./kafka-topics.sh"

# Color definitions for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Display usage information
usage() {
    printf "${BLUE}Usage:${NC} %s [options]\n" "$0"
    printf "${BLUE}Options:${NC}\n"
    printf "  -s, --bootstrap-server <address>  Kafka broker address (default: %s)\n" "${DEFAULT_BOOTSTRAP_SERVER}"
    printf "  -t, --topic <name>                Topic name (default: %s)\n" "${DEFAULT_TOPIC_NAME}"
    printf "  -p, --partitions <number>         Number of partitions (default: %s)\n" "${DEFAULT_PARTITIONS}"
    printf "  -r, --replication-factor <number> Replication factor (default: %s)\n" "${DEFAULT_REPLICATION_FACTOR}"
    printf "  -c, --config <key=value>          Topic configuration parameter, can be used multiple times\n"
    printf "                                   Example: -c retention.ms=604800000 -c cleanup.policy=delete\n"
    printf "  -h, --help                       Show this help message\n"
    printf "\n"
    printf "${YELLOW}Examples:${NC}\n"
    printf "  %s -s kafka-server:9092 -t my_topic -p 3 -r 1\n" "$0"
    printf "  %s --topic test_topic --partitions 3 --config retention.ms=86400000 --config max.message.bytes=1048576\n" "$0"
    printf "  %s -s 192.168.1.100:9092 -t logs -p 10 -r 3 -c cleanup.policy=delete -c retention.ms=259200000\n" "$0"
}

# Check if required tools exist
check_dependencies() {
    if [ ! -f "$KAFKA_TOPICS_SCRIPT" ]; then
        printf "${RED}Error: kafka-topics.sh script not found${NC}\n"
        printf "Please ensure the script is in the current directory or provide correct path\n"
        exit 1
    fi

    if ! command -v java >/dev/null 2>&1; then
        printf "${YELLOW}Warning: Java environment not detected, may affect Kafka tools execution${NC}\n"
    fi
}

# Parse command line arguments
parse_arguments() {
    CONFIGS=""
    while [ $# -gt 0 ]; do
        case $1 in
            -s|--bootstrap-server)
                BOOTSTRAP_SERVER="$2"
                shift 2
                ;;
            -t|--topic)
                TOPIC_NAME="$2"
                shift 2
                ;;
            -p|--partitions)
                PARTITIONS="$2"
                shift 2
                ;;
            -r|--replication-factor)
                REPLICATION_FACTOR="$2"
                shift 2
                ;;
            -c|--config)
                CONFIGS="$CONFIGS --config $2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                printf "${RED}Error: Unknown option '%s'${NC}\n" "$1"
                usage
                exit 1
                ;;
        esac
    done
}

# Create Kafka topic
create_topic() {
    cmd="$KAFKA_TOPICS_SCRIPT --create --bootstrap-server $BOOTSTRAP_SERVER --topic $TOPIC_NAME --partitions $PARTITIONS --replication-factor $REPLICATION_FACTOR $CONFIGS"

    printf "${BLUE}Executing command:${NC} %s\n" "$cmd"
    printf "${YELLOW}Creating topic...${NC}\n"

    # Execute the creation command
    if eval "$cmd"; then
        printf "${GREEN}✓ Topic '%s' created successfully!${NC}\n" "$TOPIC_NAME"
        return 0
    else
        printf "${RED}✗ Topic creation failed${NC}\n"
        return 1
    fi
}

# Verify topic was created successfully
verify_topic() {
    printf "${YELLOW}Verifying topic creation...${NC}\n"

    verify_cmd="$KAFKA_TOPICS_SCRIPT --describe --topic $TOPIC_NAME --bootstrap-server $BOOTSTRAP_SERVER"

    if eval "$verify_cmd" 2>/dev/null | grep -q "Topic: $TOPIC_NAME"; then
        printf "${GREEN}✓ Verification successful: Topic exists in Kafka${NC}\n"
        printf "\n"
        printf "${BLUE}Topic details:${NC}\n"
        eval "$verify_cmd"
        return 0
    else
        printf "${RED}✗ Verification failed: Topic not found${NC}\n"
        return 1
    fi
}

# Main function
main() {
    # Set default values
    BOOTSTRAP_SERVER="$DEFAULT_BOOTSTRAP_SERVER"
    TOPIC_NAME="$DEFAULT_TOPIC_NAME"
    PARTITIONS="$DEFAULT_PARTITIONS"
    REPLICATION_FACTOR="$DEFAULT_REPLICATION_FACTOR"
    CONFIGS=""

    # Check dependencies
    check_dependencies

    # Parse arguments
    parse_arguments "$@"

    # Display configuration summary
    printf "${BLUE}=================================${NC}\n"
    printf "${BLUE}      Kafka Topic Creation       ${NC}\n"
    printf "${BLUE}=================================${NC}\n"
    printf "Bootstrap Server: ${GREEN}%s${NC}\n" "$BOOTSTRAP_SERVER"
    printf "Topic Name:       ${GREEN}%s${NC}\n" "$TOPIC_NAME"
    printf "Partitions:       ${GREEN}%s${NC}\n" "$PARTITIONS"
    printf "Replication:      ${GREEN}%s${NC}\n" "$REPLICATION_FACTOR"

    if [ -n "$CONFIGS" ]; then
        printf "Custom Configs:%s\n" "$CONFIGS"
    fi
    printf "${BLUE}=================================${NC}\n"

    # Confirm operation
    printf "Continue with creation? (y/N): "
    read -r reply
    if [ "$reply" != "y" ] && [ "$reply" != "Y" ]; then
        printf "${YELLOW}Operation cancelled${NC}\n"
        exit 0
    fi

    # Create topic
    if create_topic; then
        verify_topic
    else
        exit 1
    fi
}

# Execute main function
main "$@"
