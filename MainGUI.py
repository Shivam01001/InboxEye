import tkinter as tk
from tkinter import ttk, messagebox
import webbrowser
import os
import threading
from PIL import Image, ImageTk

# Import custom modules
from HeaderParser import HeaderParser
from GeoTracer import GeoTracer
from ThreatIntel import ThreatIntel
from Logger import LogManager

class MainGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("InboxEye - Forensic Email Analyzer")
        self.root.geometry("1000x900") # Increased height for logo
        
        # Set Window Icon
        try:
            logo_path = os.path.join(os.getcwd(), 'assets', 'logo.png')
            if os.path.exists(logo_path):
                self.icon_img = tk.PhotoImage(file=logo_path)
                self.root.iconphoto(False, self.icon_img)
        except Exception as e:
            print(f"Could not load icon: {e}")

        
        # Modules
        self.tracer = GeoTracer()
        self.intel = ThreatIntel() # Can optionally provide API key here
        self.logger = LogManager(log_dir=os.path.join(os.getcwd(), 'log'))

        self.setup_ui()

    def setup_ui(self):
        # Apply themes
        style = ttk.Style()
        style.theme_use('clam')
        
        # Main layout: Frames
        self.logo_frame = ttk.Frame(self.root, padding=5)
        self.logo_frame.pack(side=tk.TOP, fill=tk.X)
        
        try:
            logo_path = os.path.join(os.getcwd(), 'assets', 'logo.png')
            if os.path.exists(logo_path):
                # Load and resize logo for the header
                img = Image.open(logo_path)
                img = img.resize((200, 200), Image.LANCZOS)
                self.logo_img = ImageTk.PhotoImage(img)
                
                logo_label = ttk.Label(self.logo_frame, image=self.logo_img)
                logo_label.pack(pady=10)
        except Exception as e:
            print(f"Error loading logo in UI: {e}")

        top_frame = ttk.Frame(self.root, padding=10)
        top_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=False)
        
        middle_frame = ttk.Frame(self.root, padding=10)
        middle_frame.pack(side=tk.TOP, fill=tk.X, expand=False)
        
        bottom_frame = ttk.Frame(self.root, padding=10)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)
        
        # Split bottom frame into left and right
        self.bottom_left = ttk.LabelFrame(bottom_frame, text="Intelligence Panel", padding=10)
        self.bottom_left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.bottom_right = ttk.LabelFrame(bottom_frame, text="Map View", padding=10)
        self.bottom_right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Top: Text widget for headers
        ttk.Label(top_frame, text="Paste Raw Email (Headers + Body) Here:", font=("Helvetica", 12, "bold")).pack(anchor=tk.W)
        self.header_text = tk.Text(top_frame, height=10, width=80)
        self.header_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Middle: Analyze Button
        self.analyze_btn = ttk.Button(middle_frame, text="Analyze Header", command=self.on_analyze)
        self.analyze_btn.pack(side=tk.LEFT, pady=5)
        
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        ttk.Label(middle_frame, textvariable=self.status_var, foreground="gray").pack(side=tk.LEFT, padx=10)

        # Bottom Left: Info Labels
        self.name_var = tk.StringVar(value="Name: -")
        self.email_var = tk.StringVar(value="Email: -")
        self.risk_var = tk.StringVar(value="Risk Rating: -")
        
        ttk.Label(self.bottom_left, textvariable=self.name_var, font=("Helvetica", 11)).pack(anchor=tk.W, pady=2)
        ttk.Label(self.bottom_left, textvariable=self.email_var, font=("Helvetica", 11)).pack(anchor=tk.W, pady=2)
        ttk.Label(self.bottom_left, textvariable=self.risk_var, font=("Helvetica", 11, "bold")).pack(anchor=tk.W, pady=2)
        
        # Treeview for hops
        ttk.Label(self.bottom_left, text="Path Trace:", font=("Helvetica", 10, "bold")).pack(anchor=tk.W, pady=(10, 0))
        self.hops_tree = ttk.Treeview(self.bottom_left, columns=('IP', 'Location', 'ISP'), show='headings', height=6)
        self.hops_tree.heading('IP', text='IP Address')
        self.hops_tree.heading('Location', text='Location')
        self.hops_tree.heading('ISP', text='ISP')
        
        self.hops_tree.column('IP', width=100)
        self.hops_tree.column('Location', width=120)
        self.hops_tree.column('ISP', width=120)
        self.hops_tree.pack(fill=tk.BOTH, expand=True, pady=5)

        # Authentication Results Text
        self.auth_text = tk.Text(self.bottom_left, height=6, state=tk.DISABLED)
        self.auth_text.pack(fill=tk.BOTH, expand=False, pady=5)

        # Bottom Right: Map View (Button instead of HtmlFrame because tkinterweb doesn't load JS)
        ttk.Label(self.bottom_right, text="Interactive Maps require a web browser", font=("Helvetica", 10)).pack(pady=30)
        self.map_btn = ttk.Button(self.bottom_right, text="Open Map in Browser", command=self.open_map, state=tk.DISABLED)
        self.map_btn.pack(pady=10)
        self.current_map_file = None

    def on_analyze(self):
        # Disable button to prevent spamming
        self.analyze_btn.config(state=tk.DISABLED)
        self.status_var.set("Analyzing... please wait")
        
        # Run analysis in an thread to keep UI responsive
        raw_text = self.header_text.get(1.0, tk.END).strip()
        if not raw_text:
            messagebox.showwarning("Warning", "Please paste an email header first.")
            self.analyze_btn.config(state=tk.NORMAL)
            self.status_var.set("Ready")
            return
            
        threading.Thread(target=self.run_analysis, args=(raw_text,), daemon=True).start()

    def run_analysis(self, raw_text):
        try:
            # 1. Parse Headers
            parser = HeaderParser(raw_text)
            name, email_address = parser.extract_display_name()
            spoofed, spoof_reason = parser.detect_spoofing()
            hops = parser.trace_hops()
            
            # 2. Get Threat Intel
            domain = email_address.split('@')[-1] if '@' in email_address else ""
            dns_results = self.intel.check_dns_records(domain)
            
            # 3. Trace Hops Geolocation
            traced_path = self.tracer.trace_ips(hops)
            
            # Add final destination
            destination = self.tracer.get_current_location()
            if destination:
                # Only add if it's not the exact same IP as the last hop
                if not traced_path or traced_path[-1]['ip'] != destination['ip']:
                    traced_path.append(destination)
            
            # Gather IP threat intelligence for the first originating IP (usually the sender or their direct relay)
            originating_ip = hops[0] if hops else None
            ip_threat_data = {}
            dnsbl_hits = []
            if originating_ip:
                ip_threat_data = self.intel.check_ip_reputation(originating_ip)
                dnsbl_hits = self.intel.check_dnsbl(originating_ip)
                
            # Content Phishing Analysis
            body_content = parser.extract_body()
            content_score, content_reasons = self.intel.analyze_content_heuristics(body_content)
            
            # Build threat dictionary for mapping
            threat_map_data = {originating_ip: ip_threat_data} if originating_ip else {}
            
            # 4. Calculate overall risk
            dmarc_status = dns_results.get('DMARC', 'NOT FOUND')
            spf_status = dns_results.get('SPF', 'NOT FOUND')
            threat_score, risk_level, reasons = self.intel.calculate_risk(dmarc_status, spf_status, ip_threat_data, spoofed, dnsbl_hits, content_score, content_reasons)
            
            # Append SPF/DKIM details to reasons if needed or just display them
            auth_string = f"[AUTHENTICATION]\nSPF: {dns_results.get('SPF')} | DKIM: {dns_results.get('DKIM')} | DMARC: {dns_results.get('DMARC')}\n"
            if spoofed:
                auth_string += f"\n[SPOOFING ALERT]: {spoof_reason}"

            # 5. Log the results first to create the directory
            report_text = self.logger.generate_report(
                user_name=name,
                user_email=email_address,
                threat_score=threat_score,
                threat_level=risk_level,
                threat_reasons=reasons,
                dmarc_status=dns_results.get('DMARC'),
                spf_status=dns_results.get('SPF'),
                dkim_status=dns_results.get('DKIM'),
                path_trace=traced_path
            )
            user_dir, log_file_path = self.logger.log_report(email_address, report_text)

            # 6. Build Map inside the new user directory
            map_file = self.tracer.generate_map(traced_path, threat_data=threat_map_data, save_dir=user_dir)
            
            # Update GUI from main thread
            self.root.after(0, self.update_gui, name, email_address, risk_level, threat_score, auth_string, traced_path, map_file, log_file_path)

        except Exception as e:
            self.root.after(0, self.show_error, str(e))

    def update_gui(self, name, email_address, risk_level, threat_score, auth_string, traced_path, map_file, log_file_path):
        # Update Info Panel
        self.name_var.set(f"Name: {name if name else 'Unknown'}")
        self.email_var.set(f"Email: {email_address if email_address else 'Unknown'}")
        
        risk_color = "red" if threat_score >= 75 else "orange" if threat_score > 40 else "green"
        self.risk_var.set(f"Risk Rating: {threat_score}/100 ({risk_level})")
        
        # We can't change label color directly in ttk easily, so we fallback to label text color update via style if needed
        # For simplicity, we just keep the text
        
        # Update Hops Tree
        for item in self.hops_tree.get_children():
            self.hops_tree.delete(item)
            
        for hop in traced_path:
            self.hops_tree.insert('', tk.END, values=(
                hop.get('ip', 'N/A'),
                f"{hop.get('city', '')}, {hop.get('country', '')}",
                hop.get('isp', 'N/A')
            ))
            
        # Update Auth Text
        self.auth_text.config(state=tk.NORMAL)
        self.auth_text.delete(1.0, tk.END)
        self.auth_text.insert(tk.END, auth_string)
        self.auth_text.config(state=tk.DISABLED)

        # Update Map
        self.current_map_file = map_file
        self.map_btn.config(state=tk.NORMAL)

        # Status
        msg = f"Analysis Complete. Log saved to log/ folder." if log_file_path else "Analysis Complete."
        self.status_var.set(msg)
        self.analyze_btn.config(state=tk.NORMAL)

    def show_error(self, message):
        messagebox.showerror("Error", f"An error occurred during analysis:\n{message}")
        self.status_var.set("Error during analysis")
        self.analyze_btn.config(state=tk.NORMAL)

    def open_map(self):
        if self.current_map_file and os.path.exists(self.current_map_file):
            import webbrowser
            webbrowser.open(f"file:///{self.current_map_file.replace(chr(92), '/')}")

if __name__ == "__main__":
    root = tk.Tk()
    app = MainGUI(root)
    root.mainloop()
