#!/bin/bash

echo "Testing RUBIX Rules Configuration"
echo "================================="

# Test YAML syntax
if python3 -c "import yaml; yaml.safe_load(open('configs/rules.yaml'))" 2>/dev/null; then
    echo "✓ YAML syntax valid"
else
    echo "✗ Invalid YAML syntax"
    exit 1
fi

# Test rule structure
echo -n "Testing rule structure... "
if grep -q "block-malware-c2" configs/rules.yaml && \
   grep -q "block-ransomware-ports" configs/rules.yaml && \
   grep -q "allow-local-network" configs/rules.yaml; then
    echo "✓ All rules present"
else
    echo "✗ Missing rules"
    exit 1
fi

# Test CIDR notation
echo -n "Testing CIDR notation... "
if grep -q "192.168.0.0/16" configs/rules.yaml && \
   grep -q "10.0.0.0/8" configs/rules.yaml; then
    echo "✓ CIDR notation valid"
else
    echo "✗ Invalid CIDR notation"
    exit 1
fi

echo "All tests passed!"
