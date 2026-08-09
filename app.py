#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
==========================================
VIRAT DEVELOPER - NUMBER INFORMATION
Python Flask Server for Termux
============================================
"""

from flask import Flask, render_template_string, request, jsonify
import requests
import re
import os
import json

app = Flask(__name__)

# ============================================
# API CONFIGURATION
# ============================================
API_URL = "https://exploitsindia.site/osint/api.php"
API_KEY = "anish-exploits"

# ============================================
# HTML TEMPLATE (Complete Website)
# ============================================
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>VIRAT  DEVELOPER - TERMINAL ACCESS</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <!-- Using a hacker-style monospace font -->
    <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet">
    <style>
        /* ===== HACKER THEME & RESET ===== */
        :root {
            --term-green: #00ff41;
            --term-dark: #0d0208;
            --term-black: #000000;
            --term-glow: 0 0 10px rgba(0, 255, 65, 0.5);
            --term-red: #ff003c;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            -webkit-user-select: none;
            -moz-user-select: none;
            -ms-user-select: none;
            user-select: none;
        }

        input, textarea {
            -webkit-user-select: text;
            -moz-user-select: text;
            -ms-user-select: text;
            user-select: text;
        }

        body {
            font-family: 'Share Tech Mono', monospace;
            background-color: var(--term-black);
            color: var(--term-green);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            overflow-x: hidden;
            text-transform: uppercase;
        }

        /* Scanline CRT Effect */
        body::after {
            content: " ";
            display: block;
            position: fixed;
            top: 0;
            left: 0;
            bottom: 0;
            right: 0;
            background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.06), rgba(0, 255, 0, 0.02), rgba(0, 0, 255, 0.06));
            z-index: 2;
            background-size: 100% 2px, 3px 100%;
            pointer-events: none;
        }

        /* Custom Scrollbar */
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: var(--term-black); border-left: 1px solid var(--term-green); }
        ::-webkit-scrollbar-thumb { background: var(--term-green); }

        /* ===== DISCLAIMER (SYSTEM WARNING) ===== */
        .disclaimer-overlay {
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.95);
            z-index: 9999;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .disclaimer-overlay.hidden { opacity: 0; visibility: hidden; transition: all 0.5s; }
        .disclaimer-overlay.hide-permanent { display: none !important; }

        .disclaimer-box {
            background: var(--term-black);
            border: 2px solid var(--term-red);
            padding: 40px;
            max-width: 500px;
            width: 90%;
            text-align: center;
            box-shadow: 0 0 30px rgba(255, 0, 60, 0.3);
            position: relative;
        }

        .disclaimer-box h2 {
            color: var(--term-red);
            font-size: 24px;
            margin-bottom: 20px;
            text-shadow: 0 0 10px var(--term-red);
            animation: blink 1s infinite;
        }

        @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }

        .disclaimer-box .content {
            color: #fff;
            font-size: 14px;
            line-height: 1.8;
            margin-bottom: 30px;
        }

        .disclaimer-box .btn-accept {
            background: transparent;
            border: 2px solid var(--term-red);
            color: var(--term-red);
            padding: 12px 30px;
            font-family: 'Share Tech Mono', monospace;
            font-size: 16px;
            cursor: pointer;
            transition: 0.3s;
            text-transform: uppercase;
        }

        .disclaimer-box .btn-accept:hover {
            background: var(--term-red);
            color: var(--term-black);
            box-shadow: 0 0 15px var(--term-red);
        }

        /* ===== TOP HEADER (TERMINAL BAR) ===== */
        .top-header {
            width: 100%;
            background: #001100;
            border-bottom: 1px solid var(--term-green);
            padding: 8px 0;
            position: sticky;
            top: 0;
            z-index: 999;
        }

        .top-header .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 12px;
            letter-spacing: 2px;
        }

        /* ===== MAIN HEADER ===== */
        .main-header {
            width: 100%;
            padding: 30px 0 10px;
            text-align: center;
        }

        .main-header .title-section h1 {
            font-size: 40px;
            font-weight: normal;
            letter-spacing: 4px;
            text-shadow: var(--term-glow);
            margin-bottom: 5px;
        }

        .main-header .sub-title {
            color: #888;
            font-size: 14px;
            letter-spacing: 5px;
        }

        /* ===== TERMINAL CONTAINER ===== */
        .main-container {
            max-width: 650px;
            width: 100%;
            padding: 20px;
            margin: 20px 0;
        }

        .card {
            background: rgba(0, 15, 0, 0.8);
            border: 1px solid var(--term-green);
            box-shadow: var(--term-glow);
            position: relative;
        }

        /* Terminal Window Controls (Fake) */
        .card::before {
            content: "[ ROOT_TERMINAL ] - /usr/bin/intel_gather";
            display: block;
            background: var(--term-green);
            color: var(--term-black);
            padding: 5px 15px;
            font-size: 12px;
            font-weight: bold;
            letter-spacing: 1px;
        }

        .card-body { padding: 30px; }

        /* ===== FORM ===== */
        .form-group { margin-bottom: 25px; }

        .form-label {
            display: block;
            font-size: 14px;
            margin-bottom: 10px;
        }

        .input-group {
            display: flex;
            align-items: center;
            background: var(--term-black);
            border: 1px solid var(--term-green);
            position: relative;
        }

        .input-group::before {
            content: ">";
            color: var(--term-green);
            padding-left: 15px;
            font-size: 18px;
            animation: blink 1s infinite;
        }

        .input-group input {
            flex: 1;
            padding: 15px;
            background: transparent;
            border: none;
            color: var(--term-green);
            font-size: 18px;
            font-family: 'Share Tech Mono', monospace;
            outline: none;
            letter-spacing: 3px;
        }

        .input-group input::placeholder {
            color: rgba(0, 255, 65, 0.3);
        }

        /* ===== STATUS ===== */
        .status-bar {
            font-size: 12px;
            margin-bottom: 15px;
            color: #888;
        }
        .status-bar span { color: var(--term-green); }

        /* ===== HACKER BUTTON ===== */
        .btn-search {
            width: 100%;
            padding: 15px;
            background: transparent;
            border: 1px solid var(--term-green);
            color: var(--term-green);
            font-size: 18px;
            font-family: 'Share Tech Mono', monospace;
            cursor: pointer;
            letter-spacing: 3px;
            transition: 0.2s;
            text-transform: uppercase;
            position: relative;
            overflow: hidden;
        }

        .btn-search:hover:not(:disabled) {
            background: var(--term-green);
            color: var(--term-black);
            box-shadow: var(--term-glow);
        }

        .btn-search:disabled {
            border-color: #555;
            color: #555;
            cursor: not-allowed;
        }

        /* ===== RESULTS SECTION (TERMINAL OUTPUT) ===== */
        .result-box {
            margin-top: 30px;
            border: 1px dashed var(--term-green);
            background: #000;
            display: none;
            padding: 1px;
        }

        .result-box.show { display: block; }

        .result-header {
            background: rgba(0, 255, 65, 0.1);
            padding: 10px;
            border-bottom: 1px dashed var(--term-green);
            display: flex;
            justify-content: space-between;
            font-size: 12px;
        }

        .result-item {
            display: flex;
            padding: 12px 15px;
            border-bottom: 1px solid rgba(0, 255, 65, 0.2);
        }
        
        .result-item:last-child { border-bottom: none; }

        .result-item .label {
            color: #888;
            width: 35%;
        }

        .result-item .label::before { content: "[+] "; color: var(--term-green); }

        .result-item .value {
            color: #fff;
            width: 65%;
            text-shadow: 0 0 5px rgba(255,255,255,0.5);
        }
        .result-item .value.highlight { color: var(--term-green); font-weight: bold; }

        /* ===== SOCIAL & FOOTER ===== */
        .social-section {
            margin-top: 30px;
            text-align: center;
            border: 1px solid rgba(0, 255, 65, 0.3);
            padding: 15px;
        }

        .social-buttons {
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-top: 10px;
        }

        .social-btn {
            color: var(--term-green);
            text-decoration: none;
            font-size: 12px;
            border: 1px solid var(--term-green);
            padding: 5px 15px;
            transition: 0.3s;
        }

        .social-btn:hover {
            background: var(--term-green);
            color: var(--term-black);
        }

        .footer-section {
            margin-top: auto;
            width: 100%;
            text-align: center;
            padding: 20px;
            border-top: 1px solid var(--term-green);
            font-size: 12px;
            color: #555;
            background: #000;
        }

        /* ===== ERROR & JSON ===== */
        .error-text { color: var(--term-red); font-size: 12px; display: none; padding-bottom: 10px; text-shadow: 0 0 5px var(--term-red); }
        .error-text.show { display: block; }

        .json-toggle {
            margin-top: 20px;
            padding: 10px;
            background: transparent;
            border: 1px dashed #555;
            color: #888;
            width: 100%;
            cursor: pointer;
            font-family: 'Share Tech Mono', monospace;
        }
        .json-toggle:hover { border-color: var(--term-green); color: var(--term-green); }

        .json-box {
            margin-top: 10px;
            background: #000;
            padding: 15px;
            font-size: 11px;
            color: #00ff41;
            display: none;
            border: 1px solid var(--term-green);
            max-height: 200px;
            overflow: auto;
        }
        .json-box.show { display: block; }
    </style>
</head>

<body>

    <!-- SYSTEM WARNING -->
    <div class="disclaimer-overlay" id="disclaimerOverlay">
        <div class="disclaimer-box">
            <h2>Wellcome</h2>
            <div class="content">
                UNAUTHORIZED ACCESS DETECTED.<br>
                THIS TOOL IS CONFIGURED FOR <strong>EDUCATIONAL & OSINT</strong> PURPOSES ONLY.<br><br>
                DEVELOPER BY VIRAT RAJPUT 
            </div>
            <button class="btn-accept" onclick="acceptDisclaimer()">[ INITIATE CONNECTION ]</button>
        </div>
    </div>

    <!-- TERMINAL BAR -->
    <div class="top-header">
        <div class="container">
            <div><i class="fas fa-terminal"></i> VIRAT_DEVELOPER // SECURE_NODE</div>
            <div>STATUS: <span style="color:#00ff41;">CONNECTED</span></div>
        </div>
    </div>

    <!-- MAIN TITLE -->
    <div class="main-header">
        <div class="title-section">
            <h1>VIRAT<span style="color:#fff;">_DEV</span></h1>
            <div class="sub-title">== INTEL GATHERING SUBSYSTEM ==</div>
        </div>
    </div>

    <!-- TERMINAL WINDOW -->
    <div class="main-container">
        <div class="card">
            <div class="card-body">
                <form id="trackForm">
                    <div class="form-group">
                        <label class="form-label">ENTER TARGET NUMBER [10 DIGITS]:</label>
                        <div class="input-group">
                            <input type="tel" id="phoneInput" placeholder="TARGET_NUMBER" maxlength="10" inputmode="numeric">
                        </div>
                    </div>

                    <div class="status-bar">
                        SYS_MSG: <span id="statusText">AWAITING INPUT...</span>
                    </div>

                    <div class="error-text" id="errorText">ERR: FATAL EXCEPTION</div>

                    <button type="submit" class="btn-search" id="trackBtn">
                        <i class="fas fa-satellite-dish"></i> EXECUTE TRACE
                    </button>
                </form>

                <!-- OUTPUT BOX -->
                <div class="result-box" id="resultBox">
                    <div class="result-header">
                        <div><i class="fas fa-database"></i> DUMP_SUCCESS</div>
                        <div>RECORDS: <span id="recordCount">0</span></div>
                    </div>
                    <div id="resultContent"></div>
                </div>

                <!-- SOCIAL LINKS -->
                <div class="social-section">
                    <div style="font-size:12px; color:#888; margin-bottom:10px;">// SECURE COMMS CHANNELS //</div>
                    <div class="social-buttons">
                        <a href="https://t.me/Viratdeveloper988" target="_blank" class="social-btn"><i class="fab fa-telegram-plane"></i> TELE_NET</a>
                        <a href="https://wa.me/917310927827" target="_blank" class="social-btn">  <i class="fab fa-whatsapp"></i> WHATSAPP</a>
                    </div>
                </div>

                <button class="json-toggle" onclick="toggleJson()">[ VIEW_RAW_JSON_DUMP ]</button>
                <div class="json-box" id="jsonBox"></div>
            </div>
        </div>
    </div>

    <!-- FOOTER -->
    <div class="footer-section">
        (C) 2025 VIRAT DEVELOPER - END OF TRANSMISSION
        ALL RIGHT REVERSED// SOFTWARE DEVELOPER// CYBER EXPERT 
    </div>

    <script>
        // Matrix/Terminal Disclaimer Logic
        (function () {
            if (sessionStorage.getItem('disclaimerShown') === 'true') {
                document.getElementById('disclaimerOverlay').classList.add('hide-permanent');
            }
        })();

        function acceptDisclaimer() {
            sessionStorage.setItem('disclaimerShown', 'true');
            document.getElementById('disclaimerOverlay').classList.add('hidden');
            setTimeout(function () {
                document.getElementById('disclaimerOverlay').classList.add('hide-permanent');
            }, 500);
        }

        function toggleJson() {
            const box = document.getElementById('jsonBox');
            box.classList.toggle('show');
        }

        async function callAPI(number) {
            try {
                // Flask proxy placeholder
                const response = await fetch('/api/lookup', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ number: number })
                });
                if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                return await response.json();
            } catch (error) {
                return { status: 'error', message: error.message };
            }
        }

        function displayResults(number, data) {
            const resultBox = document.getElementById('resultBox');
            const resultContent = document.getElementById('resultContent');
            const recordCount = document.getElementById('recordCount');
            
            document.getElementById('jsonBox').textContent = JSON.stringify(data, null, 2);

            if (data.status === 'error' || !data.result || data.result.length === 0) {
                resultBox.classList.remove('show');
                document.getElementById('errorText').textContent = 'ERR_CODE_404: ' + (data.message || 'TARGET NOT FOUND IN DATABASE.');
                document.getElementById('errorText').classList.add('show');
                return;
            }

            const info = data.result[0];
            recordCount.textContent = data.result.length;

            let html = `
                <div class="result-item"><span class="label">MSISDN</span><span class="value highlight">${info.num || '+91 ' + number}</span></div>
                <div class="result-item"><span class="label">SUBJECT_NAME</span><span class="value">${info.name || 'NULL'}</span></div>
                <div class="result-item"><span class="label">UIDAI_HASH</span><span class="value">${info.aadhar || 'NULL'}</span></div>
                <div class="result-item"><span class="label">LOCATION_LST</span><span class="value">${info.address || 'NULL'}</span></div>
                <div class="result-item"><span class="label">CARRIER_NET</span><span class="value">${info.circle || 'NULL'}</span></div>
            `;
            
            resultContent.innerHTML = html;
            resultBox.classList.add('show');
            document.getElementById('errorText').classList.remove('show');
        }

        async function searchNumber() {
            const input = document.getElementById('phoneInput');
            const number = input.value.trim();
            const trackBtn = document.getElementById('trackBtn');
            const errorText = document.getElementById('errorText');
            const statusText = document.getElementById('statusText');

            if (!/^[0-9]{10}$/.test(number)) {
                errorText.textContent = 'SYS_WARN: INVALID MSISDN FORMAT.';
                errorText.classList.add('show');
                return;
            }
            errorText.classList.remove('show');
            trackBtn.disabled = true;
            trackBtn.innerHTML = 'ESTABLISHING CONNECTION...';
            statusText.textContent = 'BYPASSING SECURITY PROTOCOLS...';

            // Fake delay for hacker effect
            setTimeout(async () => {
                const data = await callAPI(number);
                displayResults(number, data);
                trackBtn.disabled = false;
                trackBtn.innerHTML = '<i class="fas fa-satellite-dish"></i> EXECUTE TRACE';
                statusText.textContent = 'TRACE COMPLETED.';
            }, 800);
        }

        document.getElementById('trackForm').addEventListener('submit', e => { e.preventDefault(); searchNumber(); });
        document.getElementById('phoneInput').addEventListener('input', function () { this.value = this.value.replace(/[^0-9]/g, ''); });

        // Security / Anti-skid
        document.addEventListener('contextmenu', e => e.preventDefault());
        document.addEventListener('keydown', e => { if (e.ctrlKey || e.key === 'F12') e.preventDefault(); });
    </script>
</body>
</html>
'''

# ============================================
# FLASK ROUTE: HOME PAGE
# ============================================
@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

# ============================================
# FLASK ROUTE: API LOOKUP (PROXY)
# ============================================
@app.route('/api/lookup', methods=['POST'])
def lookup():
    try:
        data = request.get_json()
        number = data.get('number', '').strip()
        
        if not number:
            return jsonify({"status": "error", "message": "Phone number required"})
        
        # Clean number
        clean_number = re.sub(r'[\+\s\-]', '', number)
        
        # Build API URL
        params = {
            'key': API_KEY,
            'type': 'number',
            'num': clean_number
        }
        
        # Call API
        response = requests.get(API_URL, params=params, timeout=30)
        response.raise_for_status()
        
        api_data = response.json()
        
        # Check if API returned error
        if api_data.get('status') == 'error':
            return jsonify(api_data)
        
        # Format response
        return jsonify({
            "status": "success",
            "result": api_data.get('result', [])
        })
        
    except requests.exceptions.Timeout:
        return jsonify({"status": "error", "message": "API timeout"})
    except requests.exceptions.RequestException as e:
        return jsonify({"status": "error", "message": f"API error: {str(e)}"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"})

# ============================================
# MAIN: RUN SERVER
# ============================================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print("\n" + "="*50)
    print("🛡️   KRISH DEVELOPER - NUMBER INFORMATION")
    print("="*50)
    print(f"✅ Server running on: http://127.0.0.1:{port}")
    print(f"📱 Open in browser: http://127.0.0.1:{port}")
    print("="*50 + "\n")
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
