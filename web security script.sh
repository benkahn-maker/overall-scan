#!/bin/bash
# ==============================
# Security Audit Script
# By: Ben Kahn Cybersecurity Projects
# ==============================

#  Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No color

#  Output file
OUTPUT_FILE="security_audit.txt"
TARGET="https://google.com"

# 🧹 Clear file before scanning
echo -e "${BLUE}Security Audit Report - $(date)${NC}" | tee "$OUTPUT_FILE"
echo -e "${BLUE}Target: $TARGET${NC}" | tee -a "$OUTPUT_FILE"
echo "========================================" | tee -a "$OUTPUT_FILE"

# Function to check status and print results
check_status() {
    local message=$1
    local status=$2
    echo -e "$message: $status" | tee -a "$OUTPUT_FILE"
}

# 1 HTTPS Connection Check
echo -e "${YELLOW}[+] Checking HTTPS connection...${NC}"
http_status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET")
if [[ "$http_status" == "200" ]]; then
    check_status " HTTPS Check" "${GREEN}Secure${NC}"
else
    check_status " HTTPS Check" "${RED}Insecure${NC}"
fi

# 2️ Security Headers Check
echo -e "${YELLOW}[+] Checking Security Headers...${NC}"
headers=$(curl -s -I "$TARGET")
declare -A security_headers=(
    ["Content-Security-Policy"]="CSP Missing"
    ["X-Frame-Options"]="X-Frame Missing"
    ["X-XSS-Protection"]="X-XSS Missing"
    ["Strict-Transport-Security"]="HSTS Missing"
)

for header in "${!security_headers[@]}"; do
    if echo "$headers" | grep -q "$header"; then
        check_status " $header Check" "${GREEN}Present${NC}"
    else
        check_status " $header Check" "${RED}Missing${NC}"
    fi
done

# 3️ Sensitive Files Exposure Check
echo -e "${YELLOW}[+] Checking for exposed sensitive files...${NC}"
sensitive_files=(".git/config" ".env" "wp-config.php")
for file in "${sensitive_files[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$file")
    if [[ "$response" == "200" ]]; then
        check_status " Sensitive File: $file" "${RED}Exposed${NC}"
    else
        check_status " Sensitive File: $file" "${GREEN}Secure${NC}"
    fi
done

# 4 Open CORS Check
echo -e "${YELLOW}[+] Checking CORS policy...${NC}"
cors_test=$(curl -s -I -H "Origin: evil.com" -X OPTIONS "$TARGET" | grep -i "Access-Control-Allow-Origin: *")
if [[ -n "$cors_test" ]]; then
    check_status " CORS Policy" "${RED}Too Open${NC}"
else
    check_status " CORS Policy" "${GREEN}Restricted${NC}"
fi

# 5️ Server Information Exposure Check
echo -e "${YELLOW}[+] Checking for server information exposure...${NC}"
server_info=$(echo "$headers" | grep -i "Server")
if [[ -n "$server_info" ]]; then
    check_status " Server Info Exposure" "${RED}Exposed: $server_info${NC}"
else
    check_status " Server Info Exposure" "${GREEN}Hidden${NC}"
fi

# 6️ Rate Limiting Check
echo -e "${YELLOW}[+] Checking rate limiting...${NC}"
rate_limit=$(seq 1 5 | xargs -I{} curl -s -o /dev/null -w "%{http_code}\n" "$TARGET")
if echo "$rate_limit" | grep -q "429"; then
    check_status " Rate Limiting" "${GREEN}Enforced${NC}"
else
    check_status " Rate Limiting" "${RED}Not Enforced${NC}"
fi

# 7️ Subdomain Takeover Check
echo -e "${YELLOW}[+] Checking for subdomain takeover vulnerabilities...${NC}"
subdomain="shop.$TARGET"
dns_check=$(host "$subdomain" | grep "has no address")
if [[ -n "$dns_check" ]]; then
    check_status " Subdomain Takeover" "${RED}Vulnerable${NC}"
else
    check_status " Subdomain Takeover" "${GREEN}Secure${NC}"
fi

#  Summary Statistics
echo "========================================" | tee -a "$OUTPUT_FILE"
echo -e "${BLUE}Audit Completed. Results saved to $OUTPUT_FILE${NC}"
