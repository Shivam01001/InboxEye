import dns.resolver
import requests
from datetime import datetime
import dns.exception

class ThreatIntel:

    def __init__(self, abuseipdb_api_key=None):
        self.abuseipdb_api_key = abuseipdb_api_key
        self.abuseipdb_url = 'https://api.abuseipdb.com/api/v2/check'
        # Configure global resolver with public fallbacks and longer timeouts
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3 # Time to wait for a single server
        self.resolver.lifetime = 8 # Total time to wait for the entire resolution
        # Add public DNS servers as fallbacks in case the system DNS is slow/failing
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']

    def check_dns_records(self, domain):
        """Fetch SPF, DKIM, and DMARC records for the sender's domain."""
        results = {
            'SPF': 'NOT FOUND',
            'DKIM': 'NOT CHECKED', # Requires selector which is usually parsed from auth-results
            'DMARC': 'NOT FOUND'
        }
        
        if not domain:
            return results

        # Check SPF
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                if 'v=spf1' in rdata.to_text():
                    results['SPF'] = 'FOUND'
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        except Exception as e:
            print(f"Generic DNS error checking SPF for {domain}: {e}")

        # Check DMARC
        try:
            answers = self.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for rdata in answers:
                if 'v=DMARC1' in rdata.to_text():
                    results['DMARC'] = 'FOUND'
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        except Exception as e:
            print(f"Generic DNS error checking DMARC for {domain}: {e}")
            
        return results

    def check_ip_reputation(self, ip_address):
        """Query AbuseIPDB for a given IP address."""
        if not self.abuseipdb_api_key:
            # Fallback if no API key is provided
            return {'abuseConfidenceScore': 0, 'totalReports': 0, 'countryCode': ''}

        querystring = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90'
        }

        headers = {
            'Accept': 'application/json',
            'Key': self.abuseipdb_api_key
        }

        try:
            response = requests.request(method='GET', url=self.abuseipdb_url, headers=headers, params=querystring, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('data', {})
        except Exception as e:
            print(f"Error querying AbuseIPDB for {ip_address}: {e}")
            
        return {'abuseConfidenceScore': 0, 'totalReports': 0}

    def check_dnsbl(self, ip_address):
        """Check IP against common DNS-based Blackhole Lists (DNSBL)."""
        bls = ["zen.spamhaus.org", "b.barracudacentral.org", "bl.spamcop.net"]
        listed_in = []
        try:
            reversed_ip = '.'.join(reversed(ip_address.split('.')))
        except Exception:
            return listed_in
            
        for bl in bls:
            try:
                query = f"{reversed_ip}.{bl}"
                answers = self.resolver.resolve(query, 'A')
                if answers:
                    listed_in.append(bl)
            except Exception:
                continue
        return listed_in

    def analyze_content_heuristics(self, body_content):
        """Analyze email body for common phishing keywords and urgency."""
        if not body_content:
            return 0, []
        
        score = 0
        reasons = []
        body_lower = body_content.lower()
        
        phishing_keywords = [
            "password", "urgent", "update your account", "verify your account",
            "invoice attached", "suspended", "banking", "login", "click here",
            "unauthorized access", "action required", "immediate action"
        ]
        
        matched_flags = [word for word in phishing_keywords if word in body_lower]
        if matched_flags:
            pts = min(len(matched_flags) * 10, 30)
            score += pts
            reasons.append(f"Phishing keywords found: {', '.join(matched_flags)} (Risk +{pts})")
            
        link_count = body_lower.count("http://") + body_lower.count("https://")
        if link_count > 3:
            score += 15
            reasons.append(f"Multiple links detected in body ({link_count}) (Risk +15)")
            
        return score, reasons

    def calculate_risk(self, dmarc_status, spf_status, ip_reputation_data, spoofing_detected, dnsbl_results=None, content_score=0, content_reasons=None):
        """
        Build a logic tree:
        - If DMARC == fail/not found -> Add 25 points.
        - If SPF == fail/not found -> Add 20 points.
        - If IP in Blacklist -> Add 50 points (using Abuse Confidence Score as proxy)
        - If IP in DNSBL -> Add 40 points
        - If spoofing detected -> Add 30 points
        - Adds points for malicious body patterns
        """
        score = 0
        reasons = []

        if dmarc_status != 'FOUND':
            score += 25
            reasons.append("DMARC missing or failed (Risk +25)")
            
        if spf_status != 'FOUND':
            score += 20
            reasons.append("SPF missing or failed (Risk +20)")
            
        abuse_score = ip_reputation_data.get('abuseConfidenceScore', 0)
        reports = ip_reputation_data.get('totalReports', 0)
        
        if abuse_score > 30 or reports > 10:
            score += 50
            reasons.append(f"Originating IP has {reports} reports of Phishing/Abuse (Risk +50)")
            
        if dnsbl_results:
            score += 40
            reasons.append(f"Originating IP found in DNS Blacklists: {(', '.join(dnsbl_results))} (Risk +40)")
            
        if spoofing_detected:
            score += 30
            reasons.append("Display Name Spoofing Detected (Risk +30)")
            
        if content_score > 0:
            score += content_score
            if content_reasons:
                reasons.extend(content_reasons)
            
        # Cap score at 100
        score = min(score, 100)
        risk_level = "LOW RISK"
        if score > 40:
            risk_level = "MEDIUM RISK"
        if score >= 75:
            risk_level = "HIGH RISK"
            
        return score, risk_level, reasons
