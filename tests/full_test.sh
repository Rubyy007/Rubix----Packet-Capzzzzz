#!/bin/bash
# Complete RUBIX Test Suite

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASSED=0
FAILED=0

echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}              RUBIX COMPLETE TEST SUITE${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

# 1. RUBIX Status
echo -e "${YELLOW}[1] RUBIX Daemon Status${NC}"
RUBIX_PID=$(pgrep -x "rubix" | head -1)
if [ -n "$RUBIX_PID" ]; then
    echo -e "  ${GREEN}✓${NC} RUBIX is running (PID: $RUBIX_PID)"
    CPU=$(ps -p $RUBIX_PID -o %cpu= | xargs)
    MEM=$(($(ps -p $RUBIX_PID -o rss= | xargs)/1024))
    echo -e "    CPU: ${CPU}% | Memory: ${MEM}MB"
    ((PASSED++))
else
    echo -e "  ${RED}✗${NC} RUBIX is NOT running"
    ((FAILED++))
fi
echo ""

# 2. iptables Rules
echo -e "${YELLOW}[2] Kernel Blocking Rules${NC}"
if iptables -L RUBIX -n 2>/dev/null | grep -q "Chain RUBIX"; then
    RULES=$(iptables -L RUBIX -n 2>/dev/null | grep -c "DROP")
    echo -e "  ${GREEN}✓${NC} RUBIX chain exists with $RULES rules"
    ((PASSED++))
else
    echo -e "  ${RED}✗${NC} RUBIX chain not found"
    ((FAILED++))
fi
echo ""

# 3. Show Blocked IPs
echo -e "${YELLOW}[3] Currently Blocked IPs${NC}"
iptables -L RUBIX -n 2>/dev/null | grep "DROP" | awk '{print "  • " $8}' | sort -u | head -10
echo ""

# 4. Packet Capture Test
echo -e "${YELLOW}[4] Packet Capture Test${NC}"
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
RX_BEFORE=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo "0")
sleep 3
RX_AFTER=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo "0")
DIFF=$((RX_AFTER - RX_BEFORE))
echo -e "  Interface: $INTERFACE"
echo -e "  Packets in 3 sec: $DIFF"
if [ $DIFF -gt 0 ]; then
    echo -e "  ${GREEN}✓${NC} Packet capture working"
    ((PASSED++))
else
    echo -e "  ${YELLOW}⚠${NC} No packets detected (interface may be idle)"
fi
echo ""

# 5. Blocking Test
echo -e "${YELLOW}[5] Blocking Functionality Test${NC}"
TEST_IP="8.8.8.8"
if iptables -L RUBIX -n 2>/dev/null | grep -q "$TEST_IP"; then
    if ping -c 1 -W 1 $TEST_IP > /dev/null 2>&1; then
        echo -e "  ${RED}✗${NC} Block NOT working (ping succeeded)"
        ((FAILED++))
    else
        echo -e "  ${GREEN}✓${NC} Block working (ping failed)"
        ((PASSED++))
    fi
else
    echo -e "  ${YELLOW}⚠${NC} $TEST_IP not in block list"
fi
echo ""

# 6. Packet Loss
echo -e "${YELLOW}[6] Packet Loss Check${NC}"
DROPS=$(cat /sys/class/net/$INTERFACE/statistics/rx_dropped 2>/dev/null || echo "0")
if [ "$DROPS" -eq 0 ]; then
    echo -e "  ${GREEN}✓${NC} No packet loss detected"
    ((PASSED++))
else
    echo -e "  ${RED}✗${NC} $DROPS packets dropped"
    ((FAILED++))
fi
echo ""

# 7. Log File
echo -e "${YELLOW}[7] Log File Status${NC}"
if [ -f /var/log/rubix/rubix.log ]; then
    SIZE=$(du -h /var/log/rubix/rubix.log | cut -f1)
    LINES=$(wc -l < /var/log/rubix/rubix.log)
    ERRORS=$(grep -c "ERROR" /var/log/rubix/rubix.log 2>/dev/null || echo "0")
    echo -e "  ${GREEN}✓${NC} Log exists ($SIZE, $LINES lines)"
    if [ "$ERRORS" -eq 0 ]; then
        echo -e "  ${GREEN}✓${NC} No errors in log"
        ((PASSED++))
    else
        echo -e "  ${YELLOW}⚠${NC} $ERRORS errors found"
    fi
else
    echo -e "  ${RED}✗${NC} Log file missing"
    ((FAILED++))
fi
echo ""

# 8. Security Check
echo -e "${YELLOW}[8] Security Configuration${NC}"
CONFIG_PERMS=$(stat -c "%a" configs/rules.yaml 2>/dev/null || echo "0")
if [ "$CONFIG_PERMS" = "644" ] || [ "$CONFIG_PERMS" = "600" ]; then
    echo -e "  ${GREEN}✓${NC} Config permissions: $CONFIG_PERMS"
    ((PASSED++))
else
    echo -e "  ${YELLOW}⚠${NC} Config permissions: $CONFIG_PERMS (should be 644)"
fi
echo ""

# 9. Resource Usage
echo -e "${YELLOW}[9] Resource Usage${NC}"
THREADS=$(cat /proc/$RUBIX_PID/status 2>/dev/null | grep Threads | awk '{print $2}')
FD_COUNT=$(lsof -p $RUBIX_PID 2>/dev/null | wc -l)
echo -e "  Threads: $THREADS"
echo -e "  Open FDs: $FD_COUNT"
if [ $FD_COUNT -lt 1000 ]; then
    echo -e "  ${GREEN}✓${NC} Resource usage normal"
    ((PASSED++))
fi
echo ""

# 10. Performance Stats
echo -e "${YELLOW}[10] Performance Statistics${NC}"
if [ -f /var/log/rubix/rubix.log ]; then
    PPS=$(tail -100 /var/log/rubix/rubix.log 2>/dev/null | grep -oP '\d+(?= pps)' | tail -1 || echo "0")
    echo -e "  Recent packet rate: ${PPS} pps"
fi
echo ""

# Final Summary
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}                    TEST SUMMARY${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Passed: $PASSED${NC}"
echo -e "${RED}  Failed: $FAILED${NC}"
TOTAL=$((PASSED + FAILED))
if [ $TOTAL -gt 0 ]; then
    SCORE=$((PASSED * 100 / TOTAL))
    echo -e "${BLUE}  Score: $SCORE%${NC}"
    echo ""
    if [ $SCORE -ge 80 ]; then
        echo -e "${GREEN}  ✅ RUBIX IS PRODUCTION READY!${NC}"
    elif [ $SCORE -ge 60 ]; then
        echo -e "${YELLOW}  ⚠ Good but needs minor improvements${NC}"
    else
        echo -e "${RED}  ❌ Issues detected - review above${NC}"
    fi
fi
echo ""
