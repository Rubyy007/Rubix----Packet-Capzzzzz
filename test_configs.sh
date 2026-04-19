#!/bin/bash
echo "╔══════════════════════════════════════════════════════════╗"
echo "║           RUBIX CONFIGURATION TEST                       ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Test 1: Check config files exist
echo "📁 CONFIG FILES:"
for file in rubix.common.yaml rubix.linux.yaml rubix.windows.yaml rules.yaml; do
    if [ -f "configs/$file" ]; then
        echo "  ✅ configs/$file exists"
    else
        echo "  ❌ configs/$file MISSING"
    fi
done

# Test 2: Count rules
echo -e "\n📋 RULES SUMMARY:"
RULE_COUNT=$(grep -c "^- id:" configs/rules.yaml 2>/dev/null || echo "0")
echo "  Total rules: $RULE_COUNT"

# Test 3: Show blocked IPs
echo -e "\n🚫 BLOCKED IPS:"
grep -A 2 "dst_ips:" configs/rules.yaml | grep -E "^\\s*-" | head -5 | sed 's/^/  /'

# Test 4: Show current mode
echo -e "\n⚙️  RUBIX MODE:"
MODE=$(grep "mode:" configs/rubix.common.yaml | head -1 | awk '{print $2}')
echo "  Mode: $MODE"

# Test 5: Show capture interface
echo -e "\n🌐 NETWORK INTERFACE:"
INTERFACE=$(grep "capture_interface:" configs/rubix.common.yaml | head -1 | awk '{print $2}')
echo "  Interface: $INTERFACE"

# Test 6: Validate YAML syntax
echo -e "\n🔍 YAML SYNTAX CHECK:"
if command -v python3 &> /dev/null; then
    python3 -c "import yaml; yaml.safe_load(open('configs/rules.yaml'))" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "  ✅ rules.yaml syntax is valid"
    else
        echo "  ❌ rules.yaml has syntax errors"
    fi
else
    echo "  ⚠️  Python not installed (can't validate YAML)"
fi

echo -e "\n✅ Configuration test complete!"
