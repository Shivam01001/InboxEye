import os
from datetime import datetime

class LogManager:
    def __init__(self, log_dir='./log'):
        self.log_dir = log_dir
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

    def sanitize_filename(self, filename):
        """Sanitizes the email string so it can be used as a filename."""
        valid_chars = "-_.() abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        sanitized = ''.join(c for c in filename if c in valid_chars)
        return sanitized if sanitized else "unknown"

    def generate_report(self, user_name, user_email, threat_score, threat_level, threat_reasons, dmarc_status, spf_status, dkim_status, path_trace):
        """Generates the forensic report string."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report = []
        report.append("--- INBOXEYE FORENSIC REPORT ---")
        report.append(f"Timestamp: {now}")
        report.append(f"User: {user_name} <{user_email}>")
        report.append("")
        
        report.append("[AUTHENTICATION]")
        report.append(f"SPF: {spf_status} | DKIM: {dkim_status} | DMARC: {dmarc_status}")
        report.append("")
        
        report.append("[PATH TRACE]")
        for i, hop in enumerate(path_trace):
            ip = hop.get('ip', 'Unknown')
            city = hop.get('city', 'Unknown')
            country = hop.get('country', 'Unknown')
            isp = hop.get('isp', 'Unknown')
            report.append(f"Hop {i+1}: {ip} ({city}, {country}) - ISP: {isp}")
            
        report.append("")
        report.append("[RISK ASSESSMENT]")
        report.append(f"Score: {threat_score}/100 ({threat_level})")
        for reason in threat_reasons:
            report.append(f"Reason: {reason}")
            
        return "\n".join(report)

    def log_report(self, user_email, report_text):
        """Saves results to ./log/email_name/email_name.txt."""
        safe_name = self.sanitize_filename(user_email)
        if not safe_name:
            safe_name = "unknown_sender"
            
        user_dir = os.path.join(self.log_dir, safe_name)
        if not os.path.exists(user_dir):
            os.makedirs(user_dir)
            
        file_path = os.path.join(user_dir, f"{safe_name}.txt")
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(report_text)
            return user_dir, file_path
        except Exception as e:
            print(f"Error writing log file: {e}")
            return None, None
