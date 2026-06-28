 About The Project
Cipher Hub is a modern, browser-based cybersecurity application designed to bring powerful security tools directly to your fingertips — no installation, no backend, no data uploads. Everything runs 100% inside your browser for maximum privacy.

Built as part of the IBM SkillsBuild Skill-Based Training Program 2026, Cipher Hub provides 7 interactive cybersecurity modules that help everyday users understand, analyze, and strengthen their digital security posture.

All security operations are processed 100% client-side — your data never leaves your device.

Features
1. Password Hub
Strength Analyzer — Tests passwords against Google's official password guidelines
Shannon Entropy Calculator — Computes real cryptographic entropy (E = L × log₂R) to quantify password complexity
Secure Password Generator — Cryptographically secure generation using crypto.getRandomValues() with customizable length (6–64 chars), uppercase, lowercase, numbers, and symbols
Real-time feedback — Rule checklist updates live as you type
2. URL Scanner
Detects phishing URL patterns using brand keyword heuristics
Checks for HTTP vs HTTPS (SSL verification)
Flags IP-based hostnames, excessive subdomain stacking, and high-risk TLDs (.xyz, .top, .ru, etc.)
Computes a Vulnerability Risk Score (0–100) with detailed threat indicators
3. SMS Phishing Scanner (Smishing Detector)
Identifies urgency triggers ("Act Now!", "Account Suspended")
Detects financial bait language (prizes, lottery, refunds)
Flags credential harvesting requests (OTP, PIN, CVV)
Scans for embedded malicious URLs within message text
4. File Threat Analyzer
Computes real SHA-256 cryptographic hash using the Web Crypto API
Reads binary magic number headers to verify true file type vs extension
Detects double-extension spoofing (e.g., document.pdf.exe)
Checks against simulated threat signature databases
5. QR Code Security Scanner
Two scan modes:
Upload Photo — Drag-and-drop or upload a QR image for instant decode
Live Webcam — Real-time camera stream scanning via WebRTC + jsQR
Analyzes decoded payloads for malicious URLs, script injections, SQL commands, and QRLjacking risks
6. WiFi Security Auditor
Simulates a live wireless network scanner mapping hotspots in range
Audits encryption standards: WEP, WPA/WPA2-TKIP, WPA2-CCMP (AES), WPA3-SAE, Open
Flags WPS PIN vulnerabilities (Reaver / Pixie Dust exploits)
Detects default manufacturer SSIDs and Evil Twin attack risks
7. System Log Threat Analyzer
Parses Apache Access Logs, Auth Logs, and Syslog format entries
Detects attack signatures:
SQL Injection (UNION SELECT, OR 1=1)
Cross-Site Scripting (XSS) (<script>, onerror=)
Directory Traversal (../../etc/passwd)
Brute Force Attacks (sequential 401 failures)
Visualizes results with interactive Chart.js dashboards (severity pie chart + attack vector bar chart)
Tech Stack
Technology	Purpose
HTML5	Application structure and semantic layout
CSS3 (Vanilla)	Responsive light-theme design system
JavaScript (ES6+)	Security logic, routing, and tool engines
Web Crypto API	Cryptographically secure password generation & SHA-256 hashing
WebRTC API	Live webcam stream access for QR scanning
jsQR	Client-side QR code decoding from images and video frames
Chart.js	Interactive security dashboard charts and visualizations
Lucide Icons	Modern icon library for clean UI elements
Google Fonts (Outfit)	Premium typography
Getting Started
No installation or dependencies needed! Just serve the files locally:

Option 1: Python (Recommended)
bash

# Clone the repository
git clone https://github.com/yourusername/cipher-hub.git
# Navigate to the project directory
cd cipher-hub
# Start local server
python -m http.server 8000
Then open : http://localhost:8000 in your browser.

Option 2: VS Code Live Server
Install the Live Server extension in VS Code
Open the project folder
Right-click index.html → "Open with Live Server"
Option 3: Open Directly
Simply double-click index.html to open in your browser (some features like webcam require a server).

Project Structure

cipher-hub/
│
├── index.html          # Main application shell with all tool sections
├── styles.css          # Premium light-theme CSS design system
├── app.js              # SPA routing, navigation sync, review mailer
└── tools.js            # All 7 cybersecurity tool implementations
Project Context
Detail	Info
Developer	Umat Harnishaba
College	SIR BPTI BHAVNAGAR
Organization	IBM SkillsBuild Skill-Based Training Program 2026
Guideliner	Ayush Kumar (CSRBOX)
Contact	
umatharnisha@gmail.com
Privacy Guarantee
Cipher Hub is built with a zero-trust, offline-first philosophy:

No backend server or API calls
No analytics or tracking scripts
No user data stored, logged, or transmitted
All computations (hashing, scanning, decoding) happen in-browser
License
Distributed under the MIT License. See LICENSE for more information.

Acknowledgements
jsQR — QR code decoding library
Chart.js — Beautiful charting library
Lucide Icons — Icon library
Google Fonts — Outfit typeface
IBM SkillsBuild — Training program framework
Made with : by Umat Harnishaba under the IBM SkillsBuild Program 2026
Guidance by Ayush Kumar (CSRBOX)

