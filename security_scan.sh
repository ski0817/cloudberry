#!/bin/bash
# Security Vulnerability Scanner for Apache Cloudberry
# This script performs basic security checks on the codebase

echo "🔍 Apache Cloudberry Security Scanner"
echo "====================================="

# Color codes for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Function to print colored output
print_issue() {
    local severity=$1
    local message=$2
    local file=$3
    local line=$4
    
    case $severity in
        "HIGH")
            echo -e "${RED}🔴 HIGH: $message${NC}"
            ;;
        "MEDIUM")
            echo -e "${YELLOW}🟡 MEDIUM: $message${NC}"
            ;;
        "LOW")
            echo -e "${GREEN}🟢 LOW: $message${NC}"
            ;;
    esac
    
    if [ ! -z "$file" ] && [ ! -z "$line" ]; then
        echo "   📂 File: $file:$line"
    elif [ ! -z "$file" ]; then
        echo "   📂 File: $file"
    fi
    echo
}

# Check 1: SQL Injection patterns
echo "1. Checking for SQL injection vulnerabilities..."
sql_injection_files=$(find . -name "*.py" -exec grep -l "sql.*%" {} \; 2>/dev/null | head -10)
if [ ! -z "$sql_injection_files" ]; then
    print_issue "HIGH" "Potential SQL injection patterns found" "$sql_injection_files"
else
    echo "   ✅ No obvious SQL injection patterns found"
fi

# Check 2: Hardcoded secrets
echo "2. Checking for hardcoded secrets..."
secret_patterns=$(grep -rn "password.*=.*['\"][^'\"]*['\"]" --include="*.py" --include="*.c" --include="*.h" . 2>/dev/null | grep -v "test" | head -5)
if [ ! -z "$secret_patterns" ]; then
    print_issue "HIGH" "Potential hardcoded secrets found"
    echo "$secret_patterns"
    echo
else
    echo "   ✅ No obvious hardcoded secrets found"
fi

# Check 3: Unsafe C functions
echo "3. Checking for unsafe C functions..."
unsafe_c_functions=$(find . -name "*.c" -exec grep -Hn "strcpy\|strcat\|sprintf\|gets" {} \; 2>/dev/null | head -10)
if [ ! -z "$unsafe_c_functions" ]; then
    print_issue "MEDIUM" "Unsafe C functions found"
    echo "$unsafe_c_functions"
    echo
else
    echo "   ✅ No unsafe C functions found"
fi

# Check 4: Shell command injection
echo "4. Checking for shell command injection..."
shell_injection=$(find . -name "*.py" -exec grep -Hn "os\.system\|subprocess.*shell=True" {} \; 2>/dev/null | head -10)
if [ ! -z "$shell_injection" ]; then
    print_issue "HIGH" "Potential shell command injection found"
    echo "$shell_injection"
    echo
else
    echo "   ✅ No shell command injection patterns found"
fi

# Check 5: Insecure permissions
echo "5. Checking for insecure permission patterns..."
insecure_perms=$(find . -name "*.py" -o -name "*.sh" | xargs grep -Hn "chmod.*77[07]" 2>/dev/null | head -5)
if [ ! -z "$insecure_perms" ]; then
    print_issue "MEDIUM" "Insecure file permissions found"
    echo "$insecure_perms"
    echo
else
    echo "   ✅ No insecure permission patterns found"
fi

# Check 6: Deprecated Python functions
echo "6. Checking for deprecated Python functions..."
deprecated_funcs=$(find . -name "*.py" -exec grep -Hn "exec\|eval\|input(" {} \; 2>/dev/null | head -10)
if [ ! -z "$deprecated_funcs" ]; then
    print_issue "LOW" "Potentially dangerous Python functions found"
    echo "$deprecated_funcs"
    echo
else
    echo "   ✅ No dangerous Python functions found"
fi

# Check 7: Configuration file security
echo "7. Checking configuration files for security issues..."
config_issues=$(find . -name "*.conf" -o -name "*.config" -o -name "*.ini" | xargs grep -Hn "password\|secret\|key" 2>/dev/null | head -5)
if [ ! -z "$config_issues" ]; then
    print_issue "MEDIUM" "Potential secrets in configuration files"
    echo "$config_issues"
    echo
else
    echo "   ✅ No obvious secrets in configuration files"
fi

# Check 8: Network security patterns
echo "8. Checking for network security issues..."
network_issues=$(find . -name "*.c" -o -name "*.py" | xargs grep -Hn "bind.*0\.0\.0\.0\|listen.*0\.0\.0\.0" 2>/dev/null | head -5)
if [ ! -z "$network_issues" ]; then
    print_issue "LOW" "Potential network binding to all interfaces"
    echo "$network_issues"
    echo
else
    echo "   ✅ No obvious network security issues found"
fi

# Summary
echo "🏁 Security Scan Complete"
echo "========================"
echo "📋 Review the issues above and refer to SECURITY_ANALYSIS.md for detailed analysis"
echo "🔧 Use SECURITY_FIX_EXAMPLE.py for implementation guidance"
echo "📖 See SECURITY_ISSUES.md for tracking and prioritization"