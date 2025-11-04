#!/bin/bash
# SAM Analyzer Test Suite
# Demonstrates the capabilities of the SAM Packet Analyzer

set -e

YELLOW='\033[1;33m'
GREEN='\033[1;32m'
RED='\033[1;31m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

echo -e "${GREEN}SAM Analyzer Test Suite${NC}"
echo "================================"

# Function to print test headers
test_header() {
    echo -e "\n${YELLOW}TEST: $1${NC}"
    echo "------------------------"
}

# Function to check module status
check_module() {
    if lsmod | grep -q sam_analyzer; then
        echo -e "${GREEN}✓ Module loaded${NC}"
        return 0
    else
        echo -e "${RED}✗ Module not loaded${NC}"
        return 1
    fi
}

# Test 1: Build the module
test_header "Building the kernel module"
make clean
make
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi

# Test 2: Load the module
test_header "Loading the kernel module"
if check_module; then
    rmmod sam_analyzer
fi
insmod sam_analyzer.ko
sleep 1
if check_module; then
    echo -e "${GREEN}✓ Module loaded successfully${NC}"
else
    echo -e "${RED}✗ Failed to load module${NC}"
    exit 1
fi

# Test 3: Check debugfs interface
test_header "Verifying debugfs interface"
DEBUGFS_PATH="/sys/kernel/debug/sam_analyzer"
if [ -d "$DEBUGFS_PATH" ]; then
    echo -e "${GREEN}✓ Debugfs directory created${NC}"
    
    # List available files
    echo "Available controls:"
    ls -la $DEBUGFS_PATH | grep -v "^total"
    
    # Check each file
    for file in stats enable capture_payload filter_mask; do
        if [ -e "$DEBUGFS_PATH/$file" ]; then
            echo -e "${GREEN}  ✓ $file exists${NC}"
        else
            echo -e "${RED}  ✗ $file missing${NC}"
        fi
    done
else
    echo -e "${RED}✗ Debugfs directory not found${NC}"
    exit 1
fi

# Test 4: Enable/Disable analyzer
test_header "Testing enable/disable functionality"
echo 1 > $DEBUGFS_PATH/enable
STATUS=$(cat $DEBUGFS_PATH/enable)
if [ "$STATUS" = "1" ]; then
    echo -e "${GREEN}✓ Analyzer enabled${NC}"
else
    echo -e "${RED}✗ Failed to enable analyzer${NC}"
fi

echo 0 > $DEBUGFS_PATH/enable
STATUS=$(cat $DEBUGFS_PATH/enable)
if [ "$STATUS" = "0" ]; then
    echo -e "${GREEN}✓ Analyzer disabled${NC}"
else
    echo -e "${RED}✗ Failed to disable analyzer${NC}"
fi

# Test 5: Read statistics
test_header "Reading statistics"
echo 1 > $DEBUGFS_PATH/enable
sleep 2  # Let it capture some packets
cat $DEBUGFS_PATH/stats

# Test 6: Test payload capture
test_header "Testing payload capture"
echo 1 > $DEBUGFS_PATH/capture_payload
echo -e "${GREEN}✓ Payload capture enabled${NC}"
sleep 1
echo 0 > $DEBUGFS_PATH/capture_payload
echo -e "${GREEN}✓ Payload capture disabled${NC}"

# Test 7: Test filtering
test_header "Testing category filtering"
echo 0x100 > $DEBUGFS_PATH/filter_mask
echo -e "${GREEN}✓ Filter set to 0x100 (Keyboard)${NC}"
echo 0x0 > $DEBUGFS_PATH/filter_mask
echo -e "${GREEN}✓ Filter cleared${NC}"

# Test 8: Performance test
test_header "Performance impact test"
echo "Measuring system load with analyzer disabled..."
echo 0 > $DEBUGFS_PATH/enable
LOAD_BEFORE=$(uptime | awk '{print $10}' | sed 's/,//')

echo "Measuring system load with analyzer enabled..."
echo 1 > $DEBUGFS_PATH/enable
echo 1 > $DEBUGFS_PATH/capture_payload
sleep 5
LOAD_AFTER=$(uptime | awk '{print $10}' | sed 's/,//')

echo "Load before: $LOAD_BEFORE"
echo "Load after:  $LOAD_AFTER"

# Test 9: Check kernel logs
test_header "Checking kernel logs"
dmesg | grep "SAM Analyzer" | tail -5

# Test 10: Python monitor tool
test_header "Testing Python monitor tool"
if [ -f "sam_monitor.py" ]; then
    chmod +x sam_monitor.py
    echo "Testing monitor tool..."
    timeout 3 ./sam_monitor.py --stats || true
    echo -e "${GREEN}✓ Monitor tool functional${NC}"
else
    echo -e "${YELLOW}⚠ Monitor tool not found${NC}"
fi

# Summary
echo -e "\n${GREEN}================================${NC}"
echo -e "${GREEN}Test Suite Complete!${NC}"
echo -e "${GREEN}================================${NC}"

# Final statistics
echo -e "\nFinal Statistics:"
cat $DEBUGFS_PATH/stats | grep -E "Packets|Bytes|Errors"

# Cleanup option
echo -e "\n${YELLOW}To unload the module, run:${NC}"
echo "  sudo rmmod sam_analyzer"

echo -e "\n${YELLOW}To start monitoring, run:${NC}"
echo "  sudo ./sam_monitor.py --monitor"
