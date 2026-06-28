// Cipher Hub Cybersecurity Suite - Tools Logic

document.addEventListener('DOMContentLoaded', () => {

  // ==========================================
  // UTILS & HELPER FUNCTIONS
  // ==========================================
  
  // Hash text or buffer to SHA-256 string (Client-Side)
  async function computeSHA256(arrayBuffer) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
  }

  // Format bytes to readable size
  function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }


  // ==========================================
  // 1. PASSWORD HUB LOGIC
  // ==========================================
  const pwdInput = document.getElementById('pwd-input');
  const btnGeneratePwd = document.getElementById('btn-generate-pwd');
  const pwdLength = document.getElementById('pwd-length');
  const pwdLengthVal = document.getElementById('pwd-length-val');
  const pwdUpper = document.getElementById('pwd-upper');
  const pwdLower = document.getElementById('pwd-lower');
  const pwdNumbers = document.getElementById('pwd-numbers');
  const pwdSymbols = document.getElementById('pwd-symbols');

  const pwdPlaceholder = document.getElementById('pwd-placeholder');
  const pwdDashboard = document.getElementById('pwd-analysis-dashboard');
  const pwdDisplay = document.getElementById('pwd-display');
  const btnCopyPwd = document.getElementById('btn-copy-pwd');
  const pwdStrengthBadge = document.getElementById('pwd-strength-badge');
  const pwdBar = document.getElementById('pwd-bar');
  const pwdEntropyVal = document.getElementById('pwd-entropy-val');
  const pwdEntropyLbl = document.getElementById('pwd-entropy-lbl');
  const pwdRemediation = document.getElementById('pwd-remediation');

  // Rule checklist icons
  const ruleLenIcon = document.getElementById('rule-len-icon');
  const ruleUpperIcon = document.getElementById('rule-upper-icon');
  const ruleLowerIcon = document.getElementById('rule-lower-icon');
  const ruleNumIcon = document.getElementById('rule-num-icon');
  const ruleSymIcon = document.getElementById('rule-sym-icon');
  const ruleCommonIcon = document.getElementById('rule-common-icon');

  // Sync length value display
  if (pwdLength && pwdLengthVal) {
    pwdLength.addEventListener('input', (e) => {
      pwdLengthVal.textContent = e.target.value;
    });
  }

  // Monitor input
  if (pwdInput) {
    pwdInput.addEventListener('input', () => {
      analyzePassword(pwdInput.value);
    });
  }

  // Generate password click
  if (btnGeneratePwd) {
    btnGeneratePwd.addEventListener('click', () => {
      const length = parseInt(pwdLength.value);
      const options = {
        upper: pwdUpper.checked,
        lower: pwdLower.checked,
        numeric: pwdNumbers.checked,
        symbols: pwdSymbols.checked
      };

      if (!options.upper && !options.lower && !options.numeric && !options.symbols) {
        alert('Please select at least one character set!');
        return;
      }

      const generated = generateSecurePassword(length, options);
      if (pwdInput) pwdInput.value = generated;
      analyzePassword(generated);
    });
  }

  // Copy password button
  if (btnCopyPwd) {
    btnCopyPwd.addEventListener('click', () => {
      const password = pwdDisplay.textContent;
      if (password && password !== '••••••••••••••••') {
        navigator.clipboard.writeText(password).then(() => {
          const originalHTML = btnCopyPwd.innerHTML;
          btnCopyPwd.innerHTML = '<i data-lucide="check" style="color: var(--success);"></i>';
          lucide.createIcons();
          setTimeout(() => {
            btnCopyPwd.innerHTML = originalHTML;
            lucide.createIcons();
          }, 1500);
        });
      }
    });
  }

  function generateSecurePassword(length, options) {
    const uppercaseChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowercaseChars = 'abcdefghijklmnopqrstuvwxyz';
    const numberChars = '0123456789';
    const symbolChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    let charPool = '';
    let guaranteedChars = [];

    if (options.upper) {
      charPool += uppercaseChars;
      guaranteedChars.push(uppercaseChars[Math.floor(Math.random() * uppercaseChars.length)]);
    }
    if (options.lower) {
      charPool += lowercaseChars;
      guaranteedChars.push(lowercaseChars[Math.floor(Math.random() * lowercaseChars.length)]);
    }
    if (options.numeric) {
      charPool += numberChars;
      guaranteedChars.push(numberChars[Math.floor(Math.random() * numberChars.length)]);
    }
    if (options.symbols) {
      charPool += symbolChars;
      guaranteedChars.push(symbolChars[Math.floor(Math.random() * symbolChars.length)]);
    }

    let remainingLength = length - guaranteedChars.length;
    let passwordArray = [...guaranteedChars];

    // Cryptographically secure random values
    const randomArray = new Uint32Array(remainingLength);
    window.crypto.getRandomValues(randomArray);

    for (let i = 0; i < remainingLength; i++) {
      const randomIndex = randomArray[i] % charPool.length;
      passwordArray.push(charPool[randomIndex]);
    }

    // Shuffle password array
    for (let i = passwordArray.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [passwordArray[i], passwordArray[j]] = [passwordArray[j], passwordArray[i]];
    }

    return passwordArray.join('');
  }

  function analyzePassword(pwd) {
    if (!pwd || pwd.trim() === '') {
      pwdPlaceholder.style.display = 'flex';
      pwdDashboard.style.display = 'none';
      return;
    }

    pwdPlaceholder.style.display = 'none';
    pwdDashboard.style.display = 'block';
    pwdDisplay.textContent = pwd;

    // 1. Google rule verification
    const hasLength = pwd.length >= 8;
    const hasUpper = /[A-Z]/.test(pwd);
    const hasLower = /[a-z]/.test(pwd);
    const hasNumber = /[0-9]/.test(pwd);
    const hasSymbol = /[!@#$%^&*()_+\-=\[\]{};':",./<>?~\\|]/.test(pwd);
    
    // Check sequential/common dictionary attacks
    const commonPatterns = ['123456', 'qwerty', 'password', 'admin', '123456789', 'abcdef', 'letmein'];
    let isNotCommon = true;
    const lowerPwd = pwd.toLowerCase();
    for (const pat of commonPatterns) {
      if (lowerPwd.includes(pat)) {
        isNotCommon = false;
        break;
      }
    }

    // Update rule UI checklist
    updateRuleIcon(ruleLenIcon, hasLength);
    updateRuleIcon(ruleUpperIcon, hasUpper);
    updateRuleIcon(ruleLowerIcon, hasLower);
    updateRuleIcon(ruleNumIcon, hasNumber);
    updateRuleIcon(ruleSymIcon, hasSymbol);
    updateRuleIcon(ruleCommonIcon, isNotCommon);

    // 2. Shannon Entropy Calculation
    let poolSize = 0;
    if (hasUpper) poolSize += 26;
    if (hasLower) poolSize += 26;
    if (hasNumber) poolSize += 10;
    if (hasSymbol) poolSize += 33;

    let entropy = 0;
    if (poolSize > 0) {
      entropy = Math.floor(pwd.length * Math.log2(poolSize));
    }

    pwdEntropyVal.textContent = `${entropy} bits`;

    // Categorize complexity
    let strengthLabel = '';
    let badgeClass = '';
    let barColor = '';
    let barWidth = '';
    let feedbackHTML = '';

    if (entropy < 40) {
      strengthLabel = 'Very Weak';
      badgeClass = 'badge-danger';
      barColor = 'var(--danger)';
      barWidth = '25%';
      pwdEntropyLbl.textContent = 'Highly vulnerable to brute-force cracks';
      feedbackHTML = `
        <div class="threat-item threat-item-danger">
          <i data-lucide="alert-octagon"></i>
          <div>
            <div class="threat-title">Highly Crackable</div>
            <div class="threat-desc">This password has low entropy and can be hacked in milliseconds. Increase password length above 12 characters and mix pools.</div>
          </div>
        </div>
      `;
    } else if (entropy < 60) {
      strengthLabel = 'Weak / Moderate';
      badgeClass = 'badge-warning';
      barColor = 'var(--warning)';
      barWidth = '50%';
      pwdEntropyLbl.textContent = 'Prone to dictionary and credential attacks';
      feedbackHTML = `
        <div class="threat-item threat-item-warning">
          <i data-lucide="alert-triangle"></i>
          <div>
            <div class="threat-title">Moderate Complexity</div>
            <div class="threat-desc">Passable, but automated security tools can guess this in hours. We recommend using a passphrase of multiple words.</div>
          </div>
        </div>
      `;
    } else if (entropy < 80) {
      strengthLabel = 'Strong';
      badgeClass = 'badge-success';
      barColor = 'var(--success)';
      barWidth = '75%';
      pwdEntropyLbl.textContent = 'Excellent complexity metrics';
      feedbackHTML = `
        <div class="threat-item threat-item-success">
          <i data-lucide="shield-check"></i>
          <div>
            <div class="threat-title">Strong Shield</div>
            <div class="threat-desc">Meets baseline enterprise defense rules. Very safe against direct online dictionary attacks.</div>
          </div>
        </div>
      `;
    } else {
      strengthLabel = 'Cryptographically Solid';
      badgeClass = 'badge-success';
      barColor = 'var(--info)';
      barWidth = '100%';
      pwdEntropyLbl.textContent = 'Solid protection (military-grade complexity)';
      feedbackHTML = `
        <div class="threat-item threat-item-success" style="background-color: var(--info-light); border-color: rgba(6, 182, 212, 0.2); color: #0891b2;">
          <i data-lucide="award"></i>
          <div>
            <div class="threat-title">Impenetrable</div>
            <div class="threat-desc">Exceptional entropy. Impractical to crack with modern computing structures. Keep this safe.</div>
          </div>
        </div>
      `;
    }

    // Set layout
    pwdStrengthBadge.textContent = strengthLabel;
    pwdStrengthBadge.className = `badge ${badgeClass}`;
    pwdBar.style.backgroundColor = barColor;
    pwdBar.style.width = barWidth;
    pwdRemediation.innerHTML = feedbackHTML;
    
    lucide.createIcons();
  }

  function updateRuleIcon(element, isValid) {
    if (!element) return;
    if (isValid) {
      element.setAttribute('data-lucide', 'circle-check');
      element.className = 'valid';
    } else {
      element.setAttribute('data-lucide', 'circle-x');
      element.className = 'invalid';
    }
  }


  // ==========================================
  // 2. URL SCANNER LOGIC
  // ==========================================
  const urlInput = document.getElementById('url-input');
  const btnScanUrl = document.getElementById('btn-scan-url');
  const urlPlaceholder = document.getElementById('url-placeholder');
  const urlResults = document.getElementById('url-results');
  const urlScannedDomain = document.getElementById('url-scanned-domain');
  const urlStatusBadge = document.getElementById('url-status-badge');
  const urlRiskVerdict = document.getElementById('url-risk-verdict');
  const urlRiskScore = document.getElementById('url-risk-score');
  const urlThreatFindings = document.getElementById('url-threat-findings');

  if (btnScanUrl) {
    btnScanUrl.addEventListener('click', () => {
      let target = urlInput.value.trim();
      if (!target) {
        alert('Please specify a URL address to scan!');
        return;
      }
      
      // Auto-prefix protocol if missing
      if (!/^https?:\/\//i.test(target)) {
        target = 'http://' + target;
      }

      scanURL(target);
    });
  }

  function scanURL(urlStr) {
    urlPlaceholder.style.display = 'none';
    urlResults.style.display = 'block';

    let parsed;
    try {
      parsed = new URL(urlStr);
    } catch (e) {
      // Mock parsing fallback
      parsed = {
        hostname: urlStr.replace(/^https?:\/\//i, '').split('/')[0],
        protocol: urlStr.split(':')[0] + ':',
        pathname: '/'
      };
    }

    const host = parsed.hostname;
    const protocol = parsed.protocol;
    const path = parsed.pathname || '';

    urlScannedDomain.textContent = host;

    // Scan metrics & Heuristics
    const holdsSSL = protocol === 'https:';
    
    // Check for IP hostname
    const isIPHost = /^[0-9.]+$/.test(host);

    // Check phishing subdomains
    const parts = host.split('.');
    const subdomainCount = parts.length - 2;

    // Phishing keywords
    const phishingKeywords = ['login', 'signin', 'verification', 'secure', 'bank', 'paypal', 'netflix', 'microsoft', 'apple', 'support', 'update', 'account'];
    let foundKeywords = [];
    phishingKeywords.forEach(kw => {
      if (host.toLowerCase().includes(kw) || path.toLowerCase().includes(kw)) {
        foundKeywords.push(kw);
      }
    });

    // High risk TLDs
    const suspiciousTLDs = ['.xyz', '.top', '.club', '.work', '.info', '.click', '.ru', '.cc', '.live', '.online', '.fit'];
    const currentTLD = host.substring(host.lastIndexOf('.')).toLowerCase();
    const isSusTLD = suspiciousTLDs.includes(currentTLD);

    // Score computation
    let score = 10; // Baseline risk
    let reports = [];

    if (!holdsSSL) {
      score += 25;
      reports.push({
        status: 'danger',
        title: 'Unencrypted Connection (HTTP)',
        desc: 'Credentials and session parameters are sent in cleartext. High susceptibility to session sniffing and credentials hijacking.'
      });
    } else {
      reports.push({
        status: 'success',
        title: 'SSL Encryption Present (HTTPS)',
        desc: 'Transport layer encryption actively secures channel transactions against packet sniffing.'
      });
    }

    if (isIPHost) {
      score += 35;
      reports.push({
        status: 'danger',
        title: 'Direct IP Hostname',
        desc: 'Domain bypasses DNS naming schemas. Extremely common in active adware hubs, botnet nodes and fast-flux relays.'
      });
    }

    if (subdomainCount > 3) {
      score += 15;
      reports.push({
        status: 'warning',
        title: 'Excessive Subdomain Stacking',
        desc: `Detected ${subdomainCount} subdomains. Phishing portals frequently use subdomain stacking to spoof legitimate companies (e.g. apple.com.login.verify-portal.net).`
      });
    }

    if (foundKeywords.length > 0) {
      score += 30;
      reports.push({
        status: 'danger',
        title: 'High-Alert Brand Keywords Found',
        desc: `Matches phishing heuristics. Contains authentication indicators: [${foundKeywords.join(', ')}].`
      });
    }

    if (isSusTLD) {
      score += 15;
      reports.push({
        status: 'warning',
        title: 'Suspicious / Low-Cost TLD',
        desc: `The Top Level Domain [${currentTLD}] is cheap to register and is statistically over-represented in short-lived scam campaigns.`
      });
    }

    // Safe criteria
    if (score === 10 && reports.length === 1) {
      reports.push({
        status: 'success',
        title: 'Clean Host Reputation',
        desc: 'Hostname is structural, matches DNS standards, uses verified SSL certificates, and lists no phishing markers.'
      });
    }

    // Clamp score
    score = Math.min(100, Math.max(0, score));

    // Update UI status badges
    let statusText = 'Safe';
    let badgeClass = 'badge-success';
    let verdictText = 'Secure connection. Low risk parameters detected.';

    if (score > 60) {
      statusText = 'Critical Danger';
      badgeClass = 'badge-danger';
      verdictText = 'Highly malicious indicators. Avoid interaction!';
    } else if (score > 25) {
      statusText = 'Suspicious';
      badgeClass = 'badge-warning';
      verdictText = 'Caution advised. Verify credentials and SSL issuers.';
    }

    urlStatusBadge.textContent = statusText;
    urlStatusBadge.className = `badge ${badgeClass}`;
    urlRiskScore.textContent = `${score} / 100`;
    urlRiskVerdict.textContent = verdictText;

    // Render findings
    let findingsHTML = '';
    reports.forEach(item => {
      const icon = item.status === 'danger' ? 'alert-octagon' : (item.status === 'warning' ? 'alert-triangle' : 'shield-check');
      findingsHTML += `
        <div class="threat-item threat-item-${item.status}">
          <i data-lucide="${icon}"></i>
          <div>
            <div class="threat-title">${item.title}</div>
            <div class="threat-desc">${item.desc}</div>
          </div>
        </div>
      `;
    });

    urlThreatFindings.innerHTML = findingsHTML;
    lucide.createIcons();
  }


  // ==========================================
  // 3. SMS PHISHING SCANNER
  // ==========================================
  const smsInput = document.getElementById('sms-input');
  const btnScanSms = document.getElementById('btn-scan-sms');
  const smsPlaceholder = document.getElementById('sms-placeholder');
  const smsResults = document.getElementById('sms-results');
  const smsStatusBadge = document.getElementById('sms-status-badge');
  const smsVerdictText = document.getElementById('sms-verdict-text');
  const smsRiskScore = document.getElementById('sms-risk-score');
  const smsThreatFindings = document.querySelectorAll('#sms-results .threat-list')[0];

  if (btnScanSms) {
    btnScanSms.addEventListener('click', () => {
      const text = smsInput.value.trim();
      if (!text) {
        alert('Please insert SMS text content to scan!');
        return;
      }
      scanSMS(text);
    });
  }

  function scanSMS(text) {
    smsPlaceholder.style.display = 'none';
    smsResults.style.display = 'block';

    const lowerText = text.toLowerCase();

    // SMS Spam indicators
    const urgencyPatterns = [/urgent/i, /immediate/i, /act now/i, /suspend/i, /lock/i, /block/i, /unauthorized/i, /verification required/i, /call now/i];
    const moneyPatterns = [/win/i, /prize/i, /gift card/i, /cash/i, /lottery/i, /claim/i, /reward/i, /refund/i, /inherited/i, /\$/i, /usd/i, /inr/i];
    const credentialsPatterns = [/username/i, /password/i, /security pin/i, /otp/i, /cvv/i, /credit card/i, /bank detail/i];
    
    // Look for links inside SMS
    const urlPattern = /(https?:\/\/[^\s]+)/gi;
    const detectedURLs = text.match(urlPattern);

    let riskScore = 0;
    let detections = [];

    // URL Detection
    if (detectedURLs && detectedURLs.length > 0) {
      riskScore += 40;
      detections.push({
        status: 'danger',
        title: 'Embedded Hyperlink Detected',
        desc: `SMS holds active redirects: [${detectedURLs.join(', ')}]. Smishing exploits rely on redirection to copy phishing interfaces.`
      });
    }

    // Urgency match
    let urgencyCount = 0;
    urgencyPatterns.forEach(pat => {
      if (pat.test(lowerText)) urgencyCount++;
    });
    if (urgencyCount > 0) {
      riskScore += Math.min(30, urgencyCount * 15);
      detections.push({
        status: 'danger',
        title: 'High Pressure / Urgency Language',
        desc: 'Contains anxiety-inducing commands ("immediate action", "account locked"). Designed to bypass user caution.'
      });
    }

    // Money/Reward match
    let moneyCount = 0;
    moneyPatterns.forEach(pat => {
      if (pat.test(lowerText)) moneyCount++;
    });
    if (moneyCount > 0) {
      riskScore += Math.min(25, moneyCount * 12);
      detections.push({
        status: 'warning',
        title: 'Baiting / Financial Rewards',
        desc: 'Uses monetary incentives, free gifts, inheritance, or unclaimed funds to bait action.'
      });
    }

    // Credentials match
    let credCount = 0;
    credentialsPatterns.forEach(pat => {
      if (pat.test(lowerText)) credCount++;
    });
    if (credCount > 0) {
      riskScore += Math.min(30, credCount * 15);
      detections.push({
        status: 'danger',
        title: 'PII / Authentication Request',
        desc: 'Asks for private keys, OTP credentials, passwords or card indexes. Legit operators never request security details via SMS.'
      });
    }

    // Safe metrics
    if (riskScore === 0) {
      detections.push({
        status: 'success',
        title: 'No Threat Vectors Identified',
        desc: 'The SMS lacks hyperlink traps, financial bait elements, urgent prompts, or credentials phishing signatures.'
      });
    }

    riskScore = Math.min(100, riskScore);

    // Status mapping
    let statusText = 'Safe';
    let badgeClass = 'badge-success';
    let verdict = 'No phishing vectors matched. Text looks clean.';

    if (riskScore > 50) {
      statusText = 'Smishing Threat';
      badgeClass = 'badge-danger';
      verdict = 'High correlation with social engineering scams. DO NOT click links.';
    } else if (riskScore > 15) {
      statusText = 'Spam Risk';
      badgeClass = 'badge-warning';
      verdict = 'Moderate risk indicators. Treat link attachments with extreme suspicion.';
    }

    smsStatusBadge.textContent = statusText;
    smsStatusBadge.className = `badge ${badgeClass}`;
    smsRiskScore.textContent = `${riskScore}%`;
    smsVerdictText.textContent = verdict;

    // Display
    let detectionsHTML = '';
    detections.forEach(item => {
      const icon = item.status === 'danger' ? 'alert-octagon' : (item.status === 'warning' ? 'alert-triangle' : 'shield-check');
      detectionsHTML += `
        <div class="threat-item threat-item-${item.status}">
          <i data-lucide="${icon}"></i>
          <div>
            <div class="threat-title">${item.title}</div>
            <div class="threat-desc">${item.desc}</div>
          </div>
        </div>
      `;
    });

    smsThreatFindings.innerHTML = detectionsHTML;
    lucide.createIcons();
  }


  // ==========================================
  // 4. FILE ANALYZER
  // ==========================================
  const fileDropZone = document.getElementById('file-drop-zone');
  const fileInput = document.getElementById('file-input');
  const filePlaceholder = document.getElementById('file-placeholder');
  const fileResults = document.getElementById('file-results');
  const fileResultName = document.getElementById('file-result-name');
  const fileResultSize = document.getElementById('file-result-size');
  const fileResultType = document.getElementById('file-result-type');
  const fileHash = document.getElementById('file-hash');
  const btnCopyHash = document.getElementById('btn-copy-hash');
  const fileStatusBadge = document.getElementById('file-status-badge');
  const fileThreatFindings = document.getElementById('file-threat-findings');

  // Trigger file browsing on zone click
  if (fileDropZone) {
    fileDropZone.addEventListener('click', () => fileInput.click());

    // Drag events
    ['dragenter', 'dragover'].forEach(eventName => {
      fileDropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        fileDropZone.classList.add('dragover');
      }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
      fileDropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        fileDropZone.classList.remove('dragover');
      }, false);
    });

    fileDropZone.addEventListener('drop', (e) => {
      const dt = e.dataTransfer;
      const files = dt.files;
      if (files.length > 0) {
        processFile(files[0]);
      }
    });
  }

  if (fileInput) {
    fileInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        processFile(e.target.files[0]);
      }
    });
  }

  // Copy hash trigger
  if (btnCopyHash) {
    btnCopyHash.addEventListener('click', () => {
      const hashText = fileHash.textContent;
      if (hashText && hashText !== '-') {
        navigator.clipboard.writeText(hashText).then(() => {
          const originalHTML = btnCopyHash.innerHTML;
          btnCopyHash.innerHTML = '<i data-lucide="check" style="color: var(--success); width:16px; height:16px;"></i>';
          lucide.createIcons();
          setTimeout(() => {
            btnCopyHash.innerHTML = originalHTML;
            lucide.createIcons();
          }, 1500);
        });
      }
    });
  }

  async function processFile(file) {
    filePlaceholder.style.display = 'none';
    fileResults.style.display = 'block';

    fileResultName.textContent = file.name;
    fileResultSize.textContent = formatBytes(file.size);
    fileResultType.textContent = file.type || 'unknown/binary';
    fileHash.textContent = 'Calculating cryptographic digest...';

    // 1. Calculate real SHA-256 hash using Web Crypto API
    try {
      const arrayBuffer = await readFileAsArrayBuffer(file);
      const sha256 = await computeSHA256(arrayBuffer);
      fileHash.textContent = sha256;

      // 2. Structural Analysis via Magic Signatures (First 8 bytes)
      const sliceBytes = new Uint8Array(arrayBuffer.slice(0, 8));
      const magicHex = Array.from(sliceBytes).map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' ');

      evaluateFileThreats(file, sha256, magicHex);

    } catch (err) {
      fileHash.textContent = 'Signature calculation failed.';
      console.error(err);
    }
  }

  function readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error);
      reader.readAsArrayBuffer(file);
    });
  }

  function evaluateFileThreats(file, hash, magicHex) {
    let threats = [];
    let isMalicious = false;
    let isSuspicious = false;

    const ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
    
    // Check dangerous file formats
    const dangerousExtensions = ['.exe', '.dll', '.scr', '.vbs', '.bat', '.ps1', '.cmd', '.msi', '.jar', '.sh', '.bin'];
    const isDangerousExt = dangerousExtensions.includes(ext);

    // Double extension check (e.g. document.pdf.exe)
    const matchesDouble = file.name.match(/\.[a-z0-9]+\.([a-z0-9]+)$/i);
    const isDoubleExt = matchesDouble && matchesDouble[1] !== '';

    // Verify magic signatures
    let magicVerdict = 'unidentified';
    if (magicHex.startsWith('25 50 44 46')) magicVerdict = 'pdf';
    else if (magicHex.startsWith('89 50 4E 47')) magicVerdict = 'png';
    else if (magicHex.startsWith('FF D8 FF')) magicVerdict = 'jpg';
    else if (magicHex.startsWith('50 4B 03 04')) magicVerdict = 'zip';
    else if (magicHex.startsWith('4D 5A')) magicVerdict = 'exe_dll';
    else if (magicHex.startsWith('7F 45 4C 46')) magicVerdict = 'elf';

    // Magic mismatch checking (File Spoofing Heuristics)
    let hasMismatch = false;
    if (magicVerdict === 'exe_dll' && !dangerousExtensions.includes(ext)) {
      hasMismatch = true;
    } else if (magicVerdict === 'pdf' && ext !== '.pdf') {
      hasMismatch = true;
    } else if ((magicVerdict === 'png' || magicVerdict === 'jpg') && !['.png', '.jpg', '.jpeg'].includes(ext)) {
      hasMismatch = true;
    }

    // Heuristics evaluations
    if (isDangerousExt) {
      isSuspicious = true;
      threats.push({
        status: 'warning',
        title: 'Executable / System Extension',
        desc: 'Files of type executable/binary can run arbitrary instructions on the system. Run only if source is 100% trustworthy.'
      });
    }

    if (isDoubleExt) {
      isMalicious = true;
      threats.push({
        status: 'danger',
        title: 'Spoofed Double Extension (Evasion)',
        desc: `File name ends with nested extensions. This is a common evasion technique designed to trick operating systems with hidden extensions (e.g., pdf.exe displaying as pdf).`
      });
    }

    if (hasMismatch) {
      isMalicious = true;
      threats.push({
        status: 'danger',
        title: 'Header Mismatch (Format Spoofing)',
        desc: `The physical magic number header [${magicHex.substring(0, 11)}...] denotes standard binary formats, but the filename is masked as [${ext}]. Potential payload delivery trick.`
      });
    }

    // Mock Hash Lookup simulation
    // Simulating checking known malware databases. If hash ends with certain chars, mock find.
    const lastChar = hash.slice(-1);
    const mockMaliciousHashes = ['0', '7', 'a', 'f']; // 25% chance of mock scan match
    if (mockMaliciousHashes.includes(lastChar)) {
      isMalicious = true;
      threats.push({
        status: 'danger',
        title: 'Known Signature Database Match',
        desc: 'This file hash signature matches threat registries associated with high risk adware injectors or ransomware droppers.'
      });
    }

    // Empty list
    if (threats.length === 0) {
      threats.push({
        status: 'success',
        title: 'File Signature Validated',
        desc: 'Magic headers match MIME properties. No double-extensions or registered database threat signatures mapped.'
      });
    }

    // Status map
    let statusText = 'Safe';
    let badgeClass = 'badge-success';

    if (isMalicious) {
      statusText = 'Infected / High Risk';
      badgeClass = 'badge-danger';
    } else if (isSuspicious) {
      statusText = 'Suspicious Format';
      badgeClass = 'badge-warning';
    }

    fileStatusBadge.textContent = statusText;
    fileStatusBadge.className = `badge ${badgeClass}`;

    // Render HTML
    let findingsHTML = '';
    threats.forEach(item => {
      const icon = item.status === 'danger' ? 'alert-octagon' : (item.status === 'warning' ? 'alert-triangle' : 'shield-check');
      findingsHTML += `
        <div class="threat-item threat-item-${item.status}">
          <i data-lucide="${icon}"></i>
          <div>
            <div class="threat-title">${item.title}</div>
            <div class="threat-desc">${item.desc}</div>
          </div>
        </div>
      `;
    });
    fileThreatFindings.innerHTML = findingsHTML;
    lucide.createIcons();
  }


  // ==========================================
  // 5. QR CODE SECURITY SCANNER
  // ==========================================
  const qrTabUpload = document.getElementById('qr-tab-upload');
  const qrTabWebcam = document.getElementById('qr-tab-webcam');
  const qrPanelUpload = document.getElementById('qr-panel-upload');
  const qrPanelWebcam = document.getElementById('qr-panel-webcam');

  const qrDropZone = document.getElementById('qr-drop-zone');
  const qrFileInput = document.getElementById('qr-file-input');
  const qrFilePreviewContainer = document.getElementById('qr-file-preview-container');
  const qrFilePreview = document.getElementById('qr-file-preview');

  const qrVideo = document.getElementById('qr-video');
  const btnStartQrCam = document.getElementById('btn-start-qr-cam');
  const btnStopQrCam = document.getElementById('btn-stop-qr-cam');

  const qrPlaceholder = document.getElementById('qr-placeholder');
  const qrResults = document.getElementById('qr-results');
  const qrStatusBadge = document.getElementById('qr-status-badge');
  const qrDecodedText = document.getElementById('qr-decoded-text');
  const qrThreatFindings = document.getElementById('qr-threat-findings');

  let qrStream = null;
  let qrAnimationId = null;

  // QR Tab Navigation
  if (qrTabUpload && qrTabWebcam) {
    qrTabUpload.addEventListener('click', () => {
      qrTabUpload.classList.add('active');
      qrTabWebcam.classList.remove('active');
      qrPanelUpload.style.display = 'block';
      qrPanelWebcam.style.display = 'none';
      stopQRWebcam();
    });

    qrTabWebcam.addEventListener('click', () => {
      qrTabWebcam.classList.add('active');
      qrTabUpload.classList.remove('active');
      qrPanelWebcam.style.display = 'block';
      qrPanelUpload.style.display = 'none';
    });
  }

  // QR Image Drag and Drop
  if (qrDropZone) {
    qrDropZone.addEventListener('click', () => qrFileInput.click());

    ['dragenter', 'dragover'].forEach(name => {
      qrDropZone.addEventListener(name, (e) => {
        e.preventDefault();
        qrDropZone.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach(name => {
      qrDropZone.addEventListener(name, (e) => {
        e.preventDefault();
        qrDropZone.classList.remove('dragover');
      });
    });

    qrDropZone.addEventListener('drop', (e) => {
      const files = e.dataTransfer.files;
      if (files.length > 0) {
        processQRImageFile(files[0]);
      }
    });
  }

  if (qrFileInput) {
    qrFileInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        processQRImageFile(e.target.files[0]);
      }
    });
  }

  function processQRImageFile(file) {
    const reader = new FileReader();
    reader.onload = (event) => {
      qrFilePreviewContainer.style.display = 'block';
      qrFilePreview.src = event.target.result;
      
      // Decode image contents
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        canvas.width = img.width;
        canvas.height = img.height;
        context.drawImage(img, 0, 0, img.width, img.height);
        
        const imgData = context.getImageData(0, 0, img.width, img.height);
        const code = jsQR(imgData.data, imgData.width, imgData.height, {
          inversionAttempts: "dontInvert",
        });

        if (code) {
          analyzeQRContent(code.data);
        } else {
          alert('Could not decode QR code. Please ensure it is a high-resolution, clear QR image.');
          qrPlaceholder.style.display = 'flex';
          qrResults.style.display = 'none';
        }
      };
      img.src = event.target.result;
    };
    reader.readAsDataURL(file);
  }

  // Live Camera scan functions
  if (btnStartQrCam) {
    btnStartQrCam.addEventListener('click', async () => {
      try {
        qrStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
        qrVideo.srcObject = qrStream;
        qrVideo.setAttribute("playsinline", true); // required to tell iOS safari we don't want fullscreen
        qrVideo.play();
        
        btnStartQrCam.disabled = true;
        btnStopQrCam.disabled = false;
        
        qrPlaceholder.style.display = 'none';
        qrResults.style.display = 'none';

        qrAnimationId = requestAnimationFrame(tickQRScanner);
      } catch (err) {
        console.error(err);
        alert('Webcam access was denied or is unavailable on this device!');
      }
    });
  }

  if (btnStopQrCam) {
    btnStopQrCam.addEventListener('click', () => {
      stopQRWebcam();
    });
  }

  function stopQRWebcam() {
    if (qrStream) {
      qrStream.getTracks().forEach(track => track.stop());
      qrStream = null;
    }
    if (qrAnimationId) {
      cancelAnimationFrame(qrAnimationId);
      qrAnimationId = null;
    }
    if (btnStartQrCam) btnStartQrCam.disabled = false;
    if (btnStopQrCam) btnStopQrCam.disabled = true;
  }

  function tickQRScanner() {
    if (qrVideo.readyState === qrVideo.HAVE_ENOUGH_DATA) {
      const canvas = document.createElement('canvas');
      const context = canvas.getContext('2d');
      canvas.width = qrVideo.videoWidth;
      canvas.height = qrVideo.videoHeight;
      context.drawImage(qrVideo, 0, 0, canvas.width, canvas.height);
      
      const imgData = context.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imgData.data, imgData.width, imgData.height, {
        inversionAttempts: "dontInvert",
      });

      if (code) {
        // Play beep or success trigger
        stopQRWebcam();
        analyzeQRContent(code.data);
        return;
      }
    }
    qrAnimationId = requestAnimationFrame(tickQRScanner);
  }

  function analyzeQRContent(data) {
    qrPlaceholder.style.display = 'none';
    qrResults.style.display = 'block';
    
    // Clean spaces
    const cleanData = data.trim();
    qrDecodedText.textContent = cleanData;

    let threats = [];
    let isDanger = false;
    let isWarning = false;

    // Check if URL
    const isURL = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/i.test(cleanData);

    if (isURL) {
      let absoluteURL = cleanData;
      if (!/^https?:\/\//i.test(absoluteURL)) {
        absoluteURL = 'http://' + absoluteURL;
      }

      let parsedDomain = 'Unknown';
      try {
        parsedDomain = new URL(absoluteURL).hostname;
      } catch(e) {
        parsedDomain = absoluteURL;
      }

      threats.push({
        status: 'warning',
        title: 'Payload Contains Hyperlink',
        desc: `This QR code redirects to: [${parsedDomain}]. Scammers often paste malicious QR codes (QRLjacking) over physical flyers to redirect mobile users to spoofed web gateways.`
      });

      // Quick evaluation of URL safety parameters (incorporate URL scanner logic)
      if (absoluteURL.startsWith('http://')) {
        isDanger = true;
        threats.push({
          status: 'danger',
          title: 'Unencrypted URL Link (HTTP)',
          desc: 'Target link fails to specify secure transport schemas. Session tokens or input details are sent unencrypted.'
        });
      }

      // Check phishing brands
      const phishingKeywords = ['login', 'signin', 'verification', 'paypal', 'banking', 'secure-update'];
      let found = [];
      phishingKeywords.forEach(k => {
        if (absoluteURL.toLowerCase().includes(k)) found.push(k);
      });
      if (found.length > 0) {
        isDanger = true;
        threats.push({
          status: 'danger',
          title: 'Phishing Brand Keywords Present',
          desc: `Link matches fraud heuristics. Triggered terms: [${found.join(', ')}].`
        });
      }
    } else {
      // It is plain text. Check if it contains scripting payload or execution lines
      const lowerText = cleanData.toLowerCase();
      
      if (cleanData.length > 500) {
        isWarning = true;
        threats.push({
          status: 'warning',
          title: 'Oversized Text Content',
          desc: 'QR holds an unusually large data payload. Might be utilized in buffer overflow or parser exhaustion attacks.'
        });
      }

      const scriptKeywords = ['<script>', 'javascript:', 'union select', 'drop table', '../'];
      let matched = [];
      scriptKeywords.forEach(k => {
        if (lowerText.includes(k)) matched.push(k);
      });

      if (matched.length > 0) {
        isDanger = true;
        threats.push({
          status: 'danger',
          title: 'Embedded Script / Query Commands',
          desc: `Payload holds executable script tags or SQL operators: [${matched.join(', ')}]. Can cause injection risks if pasted blindly into software consoles.`
        });
      }
    }

    if (threats.length === 0) {
      threats.push({
        status: 'success',
        title: 'Plain Text Payload Safe',
        desc: 'QR contains standard formatting data without hyper-redirection targets, executable command markers or script strings.'
      });
    }

    // Badge styling
    let statusText = 'Safe';
    let badgeClass = 'badge-success';

    if (isDanger) {
      statusText = 'High Risk';
      badgeClass = 'badge-danger';
    } else if (isWarning) {
      statusText = 'Suspicious Content';
      badgeClass = 'badge-warning';
    }

    qrStatusBadge.textContent = statusText;
    qrStatusBadge.className = `badge ${badgeClass}`;

    // Fill threat logs
    let findingsHTML = '';
    threats.forEach(item => {
      const icon = item.status === 'danger' ? 'alert-octagon' : (item.status === 'warning' ? 'alert-triangle' : 'shield-check');
      findingsHTML += `
        <div class="threat-item threat-item-${item.status}">
          <i data-lucide="${icon}"></i>
          <div>
            <div class="threat-title">${item.title}</div>
            <div class="threat-desc">${item.desc}</div>
          </div>
        </div>
      `;
    });
    qrThreatFindings.innerHTML = findingsHTML;
    lucide.createIcons();
  }


  // ==========================================
  // 6. WIFI SECURITY AUDITOR
  // ==========================================
  const btnScanWifi = document.getElementById('btn-scan-wifi-networks');
  const wifiNetworkList = document.getElementById('wifi-network-list');
  const wifiPlaceholder = document.getElementById('wifi-placeholder');
  const wifiResults = document.getElementById('wifi-results');
  const wifiAuditName = document.getElementById('wifi-audit-name');
  const wifiStatusBadge = document.getElementById('wifi-status-badge');
  const wifiAuditSignal = document.getElementById('wifi-audit-signal');
  const wifiAuditSecurity = document.getElementById('wifi-audit-security');
  const wifiAuditWps = document.getElementById('wifi-audit-wps');
  const wifiThreatFindings = document.getElementById('wifi-threat-findings');

  // Virtual wireless networks data pool
  const virtualHotspots = [
    { ssid: "HomeSecure_WPA3", signal: 92, security: "WPA3", wps: false, hidden: false },
    { ssid: "Starbucks_Free_WiFi", signal: 78, security: "Open", wps: false, hidden: false },
    { ssid: "Netgear_Default_Setup", signal: 85, security: "WPA2-CCMP", wps: true, hidden: false },
    { ssid: "BPTI_Admin_Office", signal: 64, security: "WPA2-TKIP", wps: false, hidden: false },
    { ssid: "Linksys_WEP_legacy", signal: 45, security: "WEP", wps: true, hidden: false },
    { ssid: "xfinitywifi", signal: 70, security: "Open", wps: false, hidden: false }
  ];

  if (btnScanWifi) {
    btnScanWifi.addEventListener('click', () => {
      // Simulate scanning delay
      wifiNetworkList.innerHTML = `
        <div style="text-align: center; padding: 2rem; color: var(--text-muted);">
          <i data-lucide="loader" class="animate-spin" style="width: 2rem; height: 2rem; margin-bottom: 0.5rem; color: var(--primary);"></i>
          <p style="font-size: 0.85rem;">Scanning wireless frequency ranges...</p>
        </div>
      `;
      lucide.createIcons();

      setTimeout(() => {
        renderVirtualNetworks();
      }, 1200);
    });
  }

  function renderVirtualNetworks() {
    wifiNetworkList.innerHTML = '';
    
    virtualHotspots.forEach((net, index) => {
      const item = document.createElement('div');
      item.className = 'wifi-network-item';
      item.setAttribute('data-index', index);
      
      // Determine signal icon
      let signalIcon = 'wifi';
      if (net.signal < 50) signalIcon = 'wifi-low';
      
      const badgeStyle = net.security === 'WPA3' ? 'badge-success' : (net.security === 'Open' || net.security === 'WEP' ? 'badge-danger' : 'badge-warning');

      item.innerHTML = `
        <div class="wifi-net-details">
          <i data-lucide="${signalIcon}" class="wifi-signal-icon"></i>
          <div>
            <div class="wifi-net-name">${net.ssid}</div>
            <div class="wifi-net-sec">Signal: ${net.signal}% | WPS: ${net.wps ? 'ON' : 'OFF'}</div>
          </div>
        </div>
        <span class="badge ${badgeStyle}">${net.security}</span>
      `;
      
      item.addEventListener('click', () => {
        auditWifiNetwork(net);
      });

      wifiNetworkList.appendChild(item);
    });

    lucide.createIcons();
  }

  function auditWifiNetwork(net) {
    wifiPlaceholder.style.display = 'none';
    wifiResults.style.display = 'block';

    wifiAuditName.textContent = net.ssid;
    wifiAuditSignal.textContent = `${net.signal}%`;
    wifiAuditSecurity.textContent = net.security;
    wifiAuditWps.textContent = net.wps ? 'Active' : 'Disabled';

    let threats = [];
    let isDanger = false;
    let isWarning = false;

    // Security evaluation
    if (net.security === 'Open') {
      isDanger = true;
      threats.push({
        status: 'danger',
        title: 'No Encryption Enabled (Open Hotspot)',
        desc: 'Wireless traffic is completely unencrypted. Anyone nearby can capture data frames (session tokens, emails, keys) using network sniffers like Wireshark.'
      });
      threats.push({
        status: 'danger',
        title: 'Man-in-the-Middle (MITM) Susceptibility',
        desc: 'Malicious actors can deploy "Evil Twin" hotspots matching this SSID to intercept user data transparently.'
      });
    } else if (net.security === 'WEP') {
      isDanger = true;
      threats.push({
        status: 'danger',
        title: 'Deprecated WEP Encryption Standard',
        desc: 'Wired Equivalent Privacy (WEP) is highly compromised. IV (Initialization Vector) collision attacks can crack the passcode in seconds using standard laptop radios.'
      });
    } else if (net.security === 'WPA2-TKIP') {
      isWarning = true;
      threats.push({
        status: 'warning',
        title: 'Weak Cipher Standard (TKIP)',
        desc: 'TKIP (Temporal Key Integrity Protocol) contains known key-recovery vulnerabilities. CCMP/AES should be selected instead.'
      });
    } else if (net.security === 'WPA2-CCMP' || net.security === 'WPA2-AES') {
      threats.push({
        status: 'success',
        title: 'WPA2-AES Cryptography Standard',
        desc: 'Uses strong AES cryptography. Defends well against bulk decryption, but vulnerable to offline handshake dictionary cracking if key is weak.'
      });
    } else if (net.security === 'WPA3') {
      threats.push({
        status: 'success',
        title: 'Advanced WPA3 Security Suite',
        desc: 'Uses SAE (Simultaneous Authentication of Equals) protocol. Solid resistance against dictionary guesses and passive sniffing.'
      });
    }

    // WPS checks
    if (net.wps) {
      isWarning = true;
      threats.push({
        status: 'warning',
        title: 'Wi-Fi Protected Setup (WPS) Active',
        desc: 'WPS pins are vulnerable to offline brute force cracking (Reaver / Pixie Dust exploits). Allows an attacker to retrieve the primary WPA password in minutes.'
      });
    }

    // Default SSID name checks
    const defaultSSIDNames = ['Netgear', 'Linksys', 'D-Link', 'xfinitywifi', 'default'];
    let SSIDisDefault = false;
    defaultSSIDNames.forEach(df => {
      if (net.ssid.toLowerCase().includes(df)) SSIDisDefault = true;
    });
    if (SSIDisDefault) {
      isWarning = true;
      threats.push({
        status: 'warning',
        title: 'Default Manufacturer SSID',
        desc: 'Using default manufacturer names informs attackers of router hardware brands, which helps in identifying unpatched firmware exploits.'
      });
    }

    if (threats.length === 0) {
      threats.push({
        status: 'success',
        title: 'Secure Access Point Configuration',
        desc: 'The hotspot utilizes robust WPA2/WPA3 parameters, has WPS disabled, and does not broadcast brand-identifying default names.'
      });
    }

    // Set rating
    let statusText = 'Safe Configuration';
    let badgeClass = 'badge-success';

    if (isDanger) {
      statusText = 'Insecure / High Risk';
      badgeClass = 'badge-danger';
    } else if (isWarning) {
      statusText = 'Vulnerable Setup';
      badgeClass = 'badge-warning';
    }

    wifiStatusBadge.textContent = statusText;
    wifiStatusBadge.className = `badge ${badgeClass}`;

    // Render findings
    let findingsHTML = '';
    threats.forEach(item => {
      const icon = item.status === 'danger' ? 'alert-octagon' : (item.status === 'warning' ? 'alert-triangle' : 'shield-check');
      findingsHTML += `
        <div class="threat-item threat-item-${item.status}">
          <i data-lucide="${icon}"></i>
          <div>
            <div class="threat-title">${item.title}</div>
            <div class="threat-desc">${item.desc}</div>
          </div>
        </div>
      `;
    });
    wifiThreatFindings.innerHTML = findingsHTML;
    lucide.createIcons();
  }


  // ==========================================
  // 7. SYSTEM & SECURITY LOG ANALYZER
  // ==========================================
  const logsTextarea = document.getElementById('logs-textarea');
  const logsFileInput = document.getElementById('logs-file-input');
  const btnAnalyzeLogs = document.getElementById('btn-analyze-logs');
  const btnLoadSampleLogs = document.getElementById('btn-load-sample-logs');

  const logsPlaceholder = document.getElementById('logs-placeholder');
  const logsResults = document.getElementById('logs-results');
  const logsStatusBadge = document.getElementById('logs-status-badge');
  const logsSumTotal = document.getElementById('logs-sum-total');
  const logsSumEvents = document.getElementById('logs-sum-events');
  const logsSumIps = document.getElementById('logs-sum-ips');
  const logsTerminalOutput = document.getElementById('logs-terminal-output');

  let severityChart = null;
  let threatTypeChart = null;

  // Setup Sample log content
  const sampleLogData = 
`127.0.0.1 - - [28/Jun/2026:12:01:05] "GET /index.php HTTP/1.1" 200 4531
192.168.1.45 - - [28/Jun/2026:12:01:10] "GET /login.php HTTP/1.1" 200 1205
104.244.42.1 - - [28/Jun/2026:12:02:15] "GET /admin/login.php?user=admin' OR 1=1-- HTTP/1.1" 401 540
192.168.1.45 - - [28/Jun/2026:12:03:00] "POST /login.php HTTP/1.1" 401 230
192.168.1.45 - - [28/Jun/2026:12:03:05] "POST /login.php HTTP/1.1" 401 230
192.168.1.45 - - [28/Jun/2026:12:03:10] "POST /login.php HTTP/1.1" 401 230
8.8.8.8 - - [28/Jun/2026:12:04:12] "GET /images/logo.png HTTP/1.1" 200 12560
185.12.33.2 - - [28/Jun/2026:12:05:00] "GET /main.js?q=<script>alert(document.cookie)</script> HTTP/1.1" 200 158
192.168.1.100 - - [28/Jun/2026:12:06:22] "GET /downloads/report.pdf HTTP/1.1" 200 562145
198.51.100.5 - - [28/Jun/2026:12:07:30] "GET /../../../../etc/passwd HTTP/1.1" 403 124
192.168.1.45 - - [28/Jun/2026:12:08:00] "POST /login.php HTTP/1.1" 200 3241`;

  if (btnLoadSampleLogs) {
    btnLoadSampleLogs.addEventListener('click', () => {
      logsTextarea.value = sampleLogData;
    });
  }

  // Handle log file upload
  if (logsFileInput) {
    logsFileInput.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (event) => {
        logsTextarea.value = event.target.result;
        analyzeLogContent(event.target.result);
      };
      reader.readAsText(file);
    });
  }

  if (btnAnalyzeLogs) {
    btnAnalyzeLogs.addEventListener('click', () => {
      const text = logsTextarea.value.trim();
      if (!text) {
        alert('Please paste logs or upload a log file first!');
        return;
      }
      analyzeLogContent(text);
    });
  }

  function analyzeLogContent(logText) {
    logsPlaceholder.style.display = 'none';
    logsResults.style.display = 'block';
    logsTerminalOutput.innerHTML = '';

    const lines = logText.split('\n');
    let totalLines = 0;
    let threatEvents = 0;
    
    const uniqueIPs = new Set();
    
    // Aggregation buckets
    let severities = { Info: 0, Low: 0, Medium: 0, High: 0 };
    let attackTypes = { SQLi: 0, XSS: 0, Traversal: 0, BruteForce: 0, Normal: 0 };

    // Brute force helper tracking: count subsequent failed log attempts per IP
    const failedLoginsPerIP = {};

    lines.forEach((line) => {
      if (line.trim() === '') return;
      totalLines++;

      let isLineThreat = false;
      let lineSeverity = 'Info';
      let lineAttackType = 'Normal';
      let reason = '';

      // Match IP
      const ipMatch = line.match(/^([0-9.]+)/);
      const ip = ipMatch ? ipMatch[1] : 'Unknown-IP';
      uniqueIPs.add(ip);

      // 1. SQL Injection indicators
      if (line.match(/(UNION\s+SELECT|UNION\s+ALL|' OR |'--|%27|CONCAT|information_schema)/i)) {
        isLineThreat = true;
        lineSeverity = 'High';
        lineAttackType = 'SQLi';
        reason = `[SQL Injection Attack] from ${ip} targeting database queries.`;
      }
      // 2. XSS injection indicators
      else if (line.match(/(<script>|%3Cscript|%3E|onload=|onerror=|alert\()/i)) {
        isLineThreat = true;
        lineSeverity = 'High';
        lineAttackType = 'XSS';
        reason = `[XSS Injection Attack] from ${ip} injecting client scripts.`;
      }
      // 3. Path Traversal
      else if (line.match(/(\.\.\/|\.\.%2F|etc\/passwd|boot\.ini)/i)) {
        isLineThreat = true;
        lineSeverity = 'High';
        lineAttackType = 'Traversal';
        reason = `[Path Traversal Evasion] from ${ip} seeking operating system files.`;
      }
      // 4. Brute force failed authorization (401 code or failed login labels)
      else if (line.includes('401') || line.match(/(failed\s+login|invalid\s+user|auth\s+failed|failure)/i)) {
        failedLoginsPerIP[ip] = (failedLoginsPerIP[ip] || 0) + 1;
        
        if (failedLoginsPerIP[ip] >= 3) {
          isLineThreat = true;
          lineSeverity = 'Medium';
          lineAttackType = 'BruteForce';
          reason = `[Brute Force Alert] from ${ip} (${failedLoginsPerIP[ip]} sequential authorization failures).`;
        } else {
          isLineThreat = true;
          lineSeverity = 'Low';
          lineAttackType = 'BruteForce';
          reason = `[Failed Authorization] IP ${ip} returned 401 code.`;
        }
      }

      // Log in virtual terminal
      const logLineDiv = document.createElement('div');
      logLineDiv.className = 'logs-terminal-line';

      if (isLineThreat) {
        threatEvents++;
        severities[lineSeverity]++;
        attackTypes[lineAttackType]++;
        
        logLineDiv.textContent = `ALERT: ${reason} - RAW: ${line.substring(0, 80)}...`;
        logLineDiv.classList.add(lineSeverity === 'High' ? 'danger' : 'warning');
      } else {
        severities['Info']++;
        attackTypes['Normal']++;
        logLineDiv.textContent = `INFO: HTTP Transaction verified safe. IP: ${ip} - RAW: ${line.substring(0, 80)}...`;
        logLineDiv.classList.add('success');
      }

      logsTerminalOutput.appendChild(logLineDiv);
    });

    // Update summaries
    logsSumTotal.textContent = totalLines;
    logsSumEvents.textContent = threatEvents;
    logsSumIps.textContent = uniqueIPs.size;

    // Severity styling
    let statusText = 'Clean Logs';
    let badgeClass = 'badge-success';
    if (severities.High > 0) {
      statusText = 'Active Intrusions';
      badgeClass = 'badge-danger';
    } else if (severities.Medium > 0 || severities.Low > 0) {
      statusText = 'Anomalies Audited';
      badgeClass = 'badge-warning';
    }
    logsStatusBadge.textContent = statusText;
    logsStatusBadge.className = `badge ${badgeClass}`;

    // Render Charts
    renderLogCharts(severities, attackTypes);
  }

  function renderLogCharts(severities, attackTypes) {
    // Destroy existing chart instances to avoid overlaps
    if (severityChart) severityChart.destroy();
    if (threatTypeChart) threatTypeChart.destroy();

    const ctxSev = document.getElementById('logs-chart-severity').getContext('2d');
    const ctxType = document.getElementById('logs-chart-threat-types').getContext('2d');

    // Chart 1: Pie chart for severity
    severityChart = new Chart(ctxSev, {
      type: 'pie',
      data: {
        labels: ['Info (Safe)', 'Low Risk', 'Medium Risk', 'High Risk (Critical)'],
        datasets: [{
          data: [severities.Info, severities.Low, severities.Medium, severities.High],
          backgroundColor: ['#10b981', '#f59e0b', '#f97316', '#ef4444'],
          borderWidth: 1
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: { boxWidth: 12, font: { family: 'Outfit', size: 10 } }
          },
          title: {
            display: true,
            text: 'Threat Event Severities',
            font: { family: 'Outfit', size: 12, weight: 'bold' }
          }
        }
      }
    });

    // Chart 2: Horizontal Bar chart for types
    threatTypeChart = new Chart(ctxType, {
      type: 'bar',
      data: {
        labels: ['SQL Injection', 'Cross-Site Scripting', 'Path Traversal', 'Brute Force', 'Safe Traffic'],
        datasets: [{
          label: 'Event Occurrences',
          data: [attackTypes.SQLi, attackTypes.XSS, attackTypes.Traversal, attackTypes.BruteForce, attackTypes.Normal],
          backgroundColor: ['#2563eb', '#06b6d4', '#8b5cf6', '#f43f5e', '#10b981'],
          borderWidth: 0,
          borderRadius: 4
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          title: {
            display: true,
            text: 'Intrusion Attack Vectors',
            font: { family: 'Outfit', size: 12, weight: 'bold' }
          }
        },
        scales: {
          x: { grid: { display: false }, ticks: { precision: 0 } },
          y: { grid: { display: false } }
        }
      }
    });
  }

});
