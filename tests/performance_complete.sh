#!/bin/bash
# RUBIX COMPLETE PERFORMANCE TEST SUITE

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

print_section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}  ✅ PASSED: $2${NC}"
        ((PASSED_TESTS++))
    else
        echo -e "${RED}  ❌ FAILED: $2${NC}"
        ((FAILED_TESTS++))
    fi
    ((TOTAL_TESTS++))
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo)$NC"
    exit 1
fi

# Main banner
clear
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                    RUBIX PERFORMANCE TEST SUITE                       ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
sleep 1

# ============================================================================
# SECTION 1: SYSTEM INFORMATION
# ============================================================================
print_section "1. SYSTEM INFORMATION"

echo -e "${YELLOW}OS:${NC}        $(uname -o)"
echo -e "${YELLOW}Kernel:${NC}    $(uname -r)"
echo -e "${YELLOW}CPU Cores:${NC} $(nproc)"
echo -e "${YELLOW}RAM Total:${NC} $(free -h | awk '/^Mem:/ {print $2}')"

# ============================================================================
# SECTION 2: RUBIX DAEMON STATUS
# ============================================================================
print_section "2. RUBIX DAEMON STATUS"

RUBIX_PID=$(pgrep -x "rubix" | head -1)

if [ -n "$RUBIX_PID" ]; then
    echo -e "${GREEN}✓ RUBIX Daemon: RUNNING${NC}"
    echo -e "  PID: $RUBIX_PID"
    
    CPU=$(ps -p $RUBIX_PID -o %cpu= 2>/dev/null | xargs)
    MEM=$(ps -p $RUBIX_PID -o rss= 2>/dev/null | xargs)
    MEM_MB=$((MEM / 1024))
    echo -e "  CPU: ${CPU:-0}%"
    echo -e "  Memory: ${MEM_MB}MB"
    
    THREADS=$(cat /proc/$RUBIX_PID/status 2>/dev/null | grep Threads | awk '{print $2}')
    echo -e "  Threads: ${THREADS:-0}"
    
    print_result 0 "RUBIX daemon running"
else
    echo -e "${RED}✗ RUBIX Daemon: NOT RUNNING${NC}"
    print_result 1 "RUBIX daemon not running"
    exit 1
fi

# ============================================================================
# SECTION 3: IPTABLES RULES
# ============================================================================
print_section "3. KERNEL BLOCKING RULES"

if iptables -L RUBIX -n 2>/dev/null | grep -q "Chain RUBIX"; then
    echo -e "${GREEN}✓ RUBIX iptables chain exists${NC}"
    RULE_COUNT=$(iptables -L RUBIX -n 2>/dev/null | grep -c "DROP")
    echo -e "  Active DROP rules: $RULE_COUNT"
    print_result 0 "iptables chain configured"
else
    echo -e "${RED}✗ RUBIX iptables chain not found${NC}"
    print_result 1 "iptables chain missing"
fi

# ============================================================================
# SECTION 4: PACKET CAPTURE
# ============================================================================
print_section "4. PACKET CAPTURE PERFORMANCE"

INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
echo -e "Interface: ${GREEN}$INTERFACE${NC}"

RX_BEFORE=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo "0")
echo "Testing capture for 3 seconds..."
sleep 3
RX_AFTER=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo "0")
RX_DIFF=$((RX_AFTER - RX_BEFORE))

echo -e "  Packets captured: $RX_DIFF"

if [ $RX_DIFF -gt 0 ]; then
    print_result 0 "Packet capture active"
else
    print_result 1 "No packets captured"
fi

# ============================================================================
# SECTION 5: BLOCKING TEST
# ============================================================================
print_section "5. BLOCKING FUNCTIONALITY"

TEST_IP="8.8.8.8"
echo -e "Testing blocking for: ${YELLOW}$TEST_IP${NC}"

if iptables -L RUBIX -n 2>/dev/null | grep -q "$TEST_IP"; then
    if ping -c 1 -W 1 $TEST_IP > /dev/null 2>&1; then
        echo -e "${RED}✗ Block NOT working${NC}"
        print_result 1 "Blocking failed"
    else
        echo -e "${GREEN}✓ Block working correctly${NC}"
        print_result 0 "Blocking functional"
    fi
else
    echo -e "${YELLOW}⚠ Test IP not in block list${NC}"
    print_result 1 "Test IP not blocked"
fi

# ============================================================================
# SECTION 6: PACKET LOSS
# ============================================================================
print_section "6. PACKET LOSS ANALYSIS"

RX_DROPS=$(cat /sys/class/net/$INTERFACE/statistics/rx_dropped 2>/dev/null || echo "0")
echo -e "  RX Dropped packets: $RX_DROPS"

if [ "$RX_DROPS" -eq 0 ]; then
    print_result 0 "No packet loss"
else
    print_result 1 "Packet loss detected"
fi

# ============================================================================
# SECTION 7: SECURITY AUDIT
# ============================================================================
print_section "7. SECURITY AUDIT"

echo -n "  Root privileges: "
if [ "$EUID" -eq 0 ]; then
    echo -e "${GREEN}✓${NC}"
    print_result 0 "Running as root"
else
    echo -e "${RED}✗${NC}"
    print_result 1 "Not running as root"
fi

echo -n "  Config permissions: "
CONFIG_PERMS=$(stat -c "%a" configs/rules.yaml 2>/dev/null || echo "0")
if [ "$CONFIG_PERMS" = "644" ] || [ "$CONFIG_PERMS" = "600" ]; then
    echo -e "${GREEN}✓ (${CONFIG_PERMS})${NC}"
    print_result 0 "Config secure"
else
    echo -e "${YELLOW}⚠ (${CONFIG_PERMS})${NC}"
    print_result 1 "Config insecure"
fi

echo -n "  Log file: "
if [ -f /var/log/rubix/rubix.log ]; then
    echo -e "${GREEN}✓ exists${NC}"
    print_result 0 "Log file present"
else
    echo -e "${RED}✗ missing${NC}"
    print_result 1 "Log missing"
fi

# ============================================================================
# SECTION 8: LOG ANALYSIS
# ============================================================================
print_section "8. LOG ANALYSIS"

if [ -f /var/log/rubix/rubix.log ]; then
    LOG_SIZE=$(du -h /var/log/rubix/rubix.log 2>/dev/null | cut -f1)
    ERROR_COUNT=$(grep -c "ERROR" /var/log/rubix/rubix.log 2>/dev/null || echo "0")
    echo -e "  Size: $LOG_SIZE"
    echo -e "  Errors: $ERROR_COUNT"
    
    if [ "$ERROR_COUNT" -eq 0 ]; then
        print_result 0 "No errors in logs"
    else
        print_result 1 "$ERROR_COUNT errors found"
    fi
fi

# ============================================================================
# SECTION 9: RESOURCE USAGE
# ============================================================================
print_section "9. RESOURCE USAGE"

CORES=$(nproc)
THREADS=$(cat /proc/$RUBIX_PID/status 2>/dev/null | grep Threads | awk '{print $2}')
echo -e "  CPU Cores: $CORES"
echo -e "  Threads: $THREADS"

if [ -n "$THREADS" ] && [ $THREADS -gt 0 ]; then
    print_result 0 "Threads allocated ($THREADS)"
fi

# ============================================================================
# SECTION 10: FINAL SUMMARY
# ============================================================================
print_section "FINAL SUMMARY"

echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│                    TEST RESULTS                                 │${NC}"
echo -e "${CYAN}├─────────────────────────────────────────────────────────────────┤${NC}"
echo -e "${CYAN}│${NC}                                                               ${NC}"
echo -e "${CYAN}│${NC}  ${GREEN}✓ PASSED:${NC} $PASSED_TESTS                                           ${NC}"
echo -e "${CYAN}│${NC}  ${RED}✗ FAILED:${NC} $FAILED_TESTS                                           ${NC}"
echo -e "${CYAN}│${NC}  📊 TOTAL: ${NC} $TOTAL_TESTS                                            ${NC}"
echo -e "${CYAN}│${NC}                                                               ${NC}"
echo -e "${CYAN}└─────────────────────────────────────────────────────────────────┘${NC}"

if [ $TOTAL_TESTS -gt 0 ]; then
    PERCENTAGE=$((PASSED_TESTS * 100 / TOTAL_TESTS))
    
    echo ""
    if [ $PERCENTAGE -ge 90 ]; then
        echo -e "${GREEN}╔═════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  🎉 EXCELLENT! RUBIX IS PRODUCTION READY (${PERCENTAGE}% PASS RATE)      ║${NC}"
        echo -e "${GREEN}╚═════════════════════════════════════════════════════════════════╝${NC}"
    elif [ $PERCENTAGE -ge 70 ]; then
        echo -e "${YELLOW}╔═════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║  ✓ GOOD! Minor improvements needed (${PERCENTAGE}% PASS RATE)         ║${NC}"
        echo -e "${YELLOW}╚═════════════════════════════════════════════════════════════════╝${NC}"
    else
        echo -e "${RED}╔═════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║  ⚠ NEEDS ATTENTION! Review failed tests (${PERCENTAGE}% PASS RATE)      ║${NC}"
        echo -e "${RED}╚═════════════════════════════════════════════════════════════════╝${NC}"
    fi
fi

echo ""
echo -e "${CYAN}Test completed at: $(date)${NC}"
echo ""

exit 0
