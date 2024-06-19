#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <Linux version>"
    exit 1
fi

VERSION=$1
URL="https://raw.githubusercontent.com/torvalds/linux/v${VERSION}/arch/x86/entry/syscalls/syscall_64.tbl"
INPUT_FILE="syscall_${VERSION}.tbl"
OUTPUT_FILE="../src/tracer/ebpf/syscalls.h"

# Fetch the file
echo "Fetching syscall table from $URL ..."
wget -q "$URL" -O "$INPUT_FILE"

# Check if download was successful
if [ $? -ne 0 ]; then
    echo "Failed to download file from $URL"
    exit 1
fi

# Run getsyscalls program
echo "Running getsyscalls on $INPUT_FILE and storing output in $OUTPUT_FILE ..."
./getsyscalls "$INPUT_FILE" "$OUTPUT_FILE"

# Check if parse_syscalls ran successfully
if [ $? -ne 0 ]; then
    echo "Failed to run getsyscalls on $INPUT_FILE"
    exit 1
fi
