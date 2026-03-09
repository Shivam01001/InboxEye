<p align="center">
  <img src="assets/logo.png" width="400" alt="InboxEye Logo">
</p>

# InboxEye - Forensic Email Analyzer

## Short Summary
**InboxEye** is a comprehensive, open-source Python tool designed to perform deep forensic analysis on email headers and bodies. It automatically extracts sender identities, traces precise geographic routing across public and internal networks, verifies DNS-based authentication protocols (SPF, DKIM, DMARC), and actively scans the email body for known phishing dialects and metadata. InboxEye generates holistic risk intelligence through integration with DNS Blackhole Lists (DNSBL), compiling the evidence into detailed local intelligence reports and an interactive geographic route map.

---

## Key Features
- **Geographic Path Tracing:** Extrapolates detailed chronological server bounces (including proxy and X-Received headers) and visualizes the full IP routing path on an interactive Folium map.
- **Phishing Heuristics Analyzer:** Scans raw HTML/Plaintext payloads for social engineering verbiage and high-density malicious links.
- **Domain Authentication Auditing:** Verifies DMARC and SPF DNS enforcement policies, automatically flagging missing protections.
- **Global Blackhole Listing (DNSBL):** Performs active reputation checks against major spam blacklists (e.g., Spamhaus, Barracuda) directly from the originating server IP.
- **Isolated Forensics Sandbox:** Sorts log files and interactive HTML maps dynamically into a distinct folder sorted by the detected attacker's email address.

## Use Cases
- **Incident Responders:** Instantly determine the true origin of a suspected phishing campaign.
- **Security Analysts:** Analyze malware delivery chains and intermediate hop locations.
- **System Administrators:** Audit incoming organizational mail to verify bypasses against SPF/DMARC filters.
---

## Installation & Setup

### Automated Setup (Recommended)
Open your terminal and run the following commands to install and set up **InboxEye**:

#### On Windows
```powershell
# 1. Clone the repository
git clone https://github.com/Shivam01001/InboxEye.git

# 2. Navigate into the folder
cd InboxEye

# 3. Run the automated setup
.\setup.bat

# 4. Start the application
.\run.bat
```

#### On Linux / Kali / Ubuntu
```bash
# 1. Clone the repository
git clone https://github.com/Shivam01001/InboxEye.git

# 2. Navigate into the folder
cd InboxEye

# 3. Make the scripts executable
chmod +x setup.sh run.sh

# 4. Run the automated setup
./setup.sh

# 5. Start the application
./run.sh
```

### Manual Installation (Advanced)
If you prefer to install dependencies manually into your own environment, you can use the provided `requirements.txt`:
```bash
pip install -r requirements.txt
```

---

## Running the Application

### On Windows
- **Recommended Method:** Double-click on `run.bat` in the folder.
- **Via CLI:** Open a terminal in the folder and type `.\run.bat`

### On Linux / Kali / Ubuntu
- **Recommended Method:** Execute the shell script in your terminal:
  ```bash
  ./run.sh
  ```

---

## Usage Guide
1. Obtain the **Original Raw Email** source (Headers + the Body content). In Gmail, you can get this via "Show Original", or in Outlook via "Message Details / Source".
2. Paste the entire block into the top window of the InboxEye application.
3. Click **Analyze Header**.
4. The application will parse the email, evaluate the threat, and automatically generate a dedicated folder inside `log/` named after the sender.
5. You can click **Open Map in Browser** to view the geographic plotting of the threat!
