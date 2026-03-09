import email
import re
from email.utils import parseaddr

class HeaderParser:
    def __init__(self, raw_headers):
        self.raw_headers = raw_headers
        self.msg = email.message_from_string(raw_headers)

    def extract_display_name(self):
        """Extracts and separates the display name and email address."""
        from_header = self.msg.get('From', '')
        name, address = parseaddr(from_header)
        return name, address

    def detect_spoofing(self):
        """Checks for rudimentary display name spoofing."""
        name, address = self.extract_display_name()
        if not address:
            return False, "No address found"

        name_lower = name.lower()
        domain = address.split('@')[-1].lower() if '@' in address else ""
        
        # Example naive check: if known entity name is used but domain is generic
        # A real implementation would check a list of known brand names.
        suspicious_brands = ['bank of america', 'paypal', 'apple', 'microsoft', 'google']
        generic_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com']
        
        for brand in suspicious_brands:
            if brand in name_lower and domain in generic_domains:
                return True, f"Display name '{name}' paired with generic domain '{domain}'"
        
        return False, "No spoofing detected"

    def trace_hops(self):
        """Extracts every routing header and reverses the list to form a chronological path."""
        # Find IPv4 addresses using naive regex
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        # Basic IPv6 extract
        ipv6_pattern = re.compile(r'(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:)*:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*')

        hops = []
        # email headers are typically appended at the top by each hop, so top = newest, bottom = oldest.
        # We iterate in reverse to get the chronological path (oldest hop -> newest hop)
        for header, value in reversed(self.msg.items()):
            header_lower = header.lower()
            if header_lower in ['received', 'x-received', 'x-originating-ip', 'x-forwarded-for', 'x-real-ip', 'x-sender-ip']:
                matches = ip_pattern.findall(value) + ipv6_pattern.findall(value)
                for ip in matches:
                    if not ip: continue
                    # Capture all traffic including internal nodes
                    if not hops or hops[-1] != ip:
                         hops.append(ip)
                         
        return hops

    def get_auth_results(self):
        """Extract Authentication-Results header."""
        # Simple extraction - often multi-line
        auth_results = self.msg.get_all('Authentication-Results')
        return auth_results if auth_results else []

    def extract_body(self):
        """Extracts the text body of the email for phishing analysis."""
        body = ""
        # Also strip simple HTML tags to analyze text in HTML emails
        html_tag_re = re.compile(r'<[^>]+>')
        
        if self.msg.is_multipart():
            for part in self.msg.walk():
                content_type = str(part.get_content_type())
                content_disposition = str(part.get("Content-Disposition"))
                if content_type in ["text/plain", "text/html"] and "attachment" not in content_disposition:
                    try:
                        text = part.get_payload(decode=True).decode(errors='ignore')
                    except Exception:
                        text = str(part.get_payload())
                    if content_type == "text/html":
                        text = html_tag_re.sub(' ', text)
                    body += text + " "
        else:
            try:
                body = self.msg.get_payload(decode=True).decode(errors='ignore')
            except Exception:
                body = str(self.msg.get_payload())
            if "text/html" in str(self.msg.get('Content-Type', '')):
                body = html_tag_re.sub(' ', body)
                
        return body
