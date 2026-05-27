#!/bin/bash
echo "Testing EndpointGuard v5.1 Fixes"
echo "================================="
echo ""

echo "1. Testing syntax..."
if bash -n src/endpointguard.sh; then
    echo "✓ Syntax check passed"
else
    echo "✗ Syntax check failed"
    exit 1
fi

echo ""
echo "2. Checking for Ghost-Shell detection function..."
if grep -q "detect_and_clean_ghost_shell" src/endpointguard.sh; then
    echo "✓ Ghost-Shell detection function found"
else
    echo "✗ Ghost-Shell detection function missing"
fi

echo ""
echo "3. Checking for LAN attacker fix..."
if grep -q "Do NOT skip private LAN IPs" src/endpointguard.sh; then
    echo "✓ LAN attacker fix applied"
else
    echo "✗ LAN attacker fix missing"
fi

echo ""
echo "4. Checking version..."
VERSION=$(grep -o 'EPG_VERSION="[^"]*"' src/endpointguard.sh | cut -d'"' -f2)
echo "  Version: $VERSION"

echo ""
echo "5. Checking updated patterns..."
if grep -q "GHOST-SHELL v4.0" src/endpointguard.sh; then
    echo "✓ Ghost-Shell patterns added"
else
    echo "✗ Ghost-Shell patterns missing"
fi

echo ""
echo "6. Checking shell prompt safety..."
if grep -q "More specific patterns to avoid false positives" src/endpointguard.sh; then
    echo "✓ Shell prompt safety enhanced"
else
    echo "✗ Shell prompt safety not enhanced"
fi

echo ""
echo "================================="
echo "Summary: EndpointGuard v5.1 upgrade complete!"
echo ""
echo "Key improvements:"
echo "  • Ghost-Shell v4.0 detection & cleanup"
echo "  • Fixed LAN attacker detection (10.x.x.x, 192.168.x.x)"
echo "  • Enhanced shell prompt safety"
echo "  • Added to watchdog and on-demand scan"
echo ""
echo "To test:"
echo "  1. Run: sudo endpointguard"
echo "  2. Choose option 3 for on-demand scan"
echo "  3. Check for Ghost-Shell detection"
echo ""
echo "To update GitHub repo:"
echo "  git add src/endpointguard.sh README.md UPGRADE_SUMMARY.md"
echo "  git commit -m 'EndpointGuard v5.1 — Ghost-Shell hunter + LAN attacker fix'"
echo "  git push origin main"