// ============================================================
// ENHANCED SERVER.JS - Bug Fixes + New Features
// ============================================================
import dotenv from "dotenv"
dotenv.config()
import { WebSocketServer } from "ws"
import http from "http"
import express from "express"
import cors from "cors"
import crypto from "crypto"
import path from "path"
import fs from "fs"
import nodemailer from "nodemailer"
const app = express()
app.use(cors())
app.use(express.json({ limit: '50mb' })) // Increased limit for large scan data

const scans = {}
const activeSessions = {}
const scanHistory = [] // NEW: Track all scans
// ============================================================
// ENHANCED REST APIs
// ============================================================
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS
  }
})
app.post("/api/onboarding-email", async (req, res) => {
  const { company, email } = req.body
  if (!company || !email) {
    return res.status(400).json({ error: "Missing fields" })
  }

  try {
    await transporter.sendMail({
      from: `"AGENTIC X" <${process.env.GMAIL_USER}>`,
      to:email,
      cc: process.env.GMAIL_USER,
      subject: "New AGENTIC X Demo Request",
      html:`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
          }

          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', sans-serif;
            background: #ffff;
            padding: 20px;
          }

          .container {
            max-width: 600px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.08);
          }

          /* Liquid gradient header with animation */
          .header {
            position: relative;
            height: 280px;
            background: linear-gradient(135deg, #000000 0%, #1a1a1a 50%, #000000 100%);
            overflow: hidden;
            display: flex;
            align-items: center;
            justify-content: center;
          }

          .liquid-blob {
            position: absolute;
            border-radius: 40% 60% 70% 30% / 40% 50% 60% 50%;
            background: #eeeeee;
            animation: liquidFlow 8s ease-in-out infinite;
          }

          .blob-1 {
            width: 300px;
            height: 300px;
            top: -100px;
            right: -50px;
            animation-delay: 0s;
          }

          .blob-2 {
            width: 250px;
            height: 250px;
            bottom: -80px;
            left: -50px;
            animation-delay: 2s;
          }

          .blob-3 {
            width: 200px;
            height: 200px;
            top: 50%;
            left: 20%;
            animation-delay: 4s;
          }

          @keyframes liquidFlow {
            0%, 100% {
              border-radius: 40% 60% 70% 30% / 40% 50% 60% 50%;
              transform: translate(0, 0);
            }
            50% {
              border-radius: 30% 70% 70% 30% / 30% 30% 70% 70%;
              transform: translate(30px, -20px);
            }
          }

          .header-content {
            position: relative;
            z-index: 10;
            text-align: center;
            color: white;
          }

  

          @keyframes iconPulse {
            0%, 100% {
              transform: scale(1);
              opacity: 1;
            }
            50% {
              transform: scale(1.1);
              opacity: 0.8;
            }
          }

          .header-title {
            font-size: 32px;
            font-weight: 700;
            letter-spacing: -0.5px;
            margin-bottom: 8px;
          }

          .header-subtitle {
            font-size: 14px;
            color: rgba(255, 255, 255, 0.7);
            font-weight: 500;
          }

          /* Content section with enhanced spacing */
          .content {
            padding: 48px 32px;
          }

          .greeting {
            font-size: 20px;
            font-weight: 600;
            color: #000;
            margin-bottom: 24px;
            line-height: 1.4;
          }

          .info-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin: 32px 0;
          }

          .info-item {
            background: linear-gradient(135deg, #f9f9f9 0%, #ffffff 100%);
            padding: 20px;
            border-radius: 12px;
            border: 1px solid #f0f0f0;
            transition: all 0.3s ease;
            animation: slideUp 0.6s ease-out;
          }

          .info-item:nth-child(1) {
            animation-delay: 0.1s;
          }

          .info-item:nth-child(2) {
            animation-delay: 0.2s;
          }

          @keyframes slideUp {
            from {
              opacity: 0;
              transform: translateY(20px);
            }
            to {
              opacity: 1;
              transform: translateY(0);
            }
          }

          .info-item:hover {
            border-color: #000;
            background: #fff;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
          }

          .info-label {
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
            margin-bottom: 8px;
          }

          .info-value {
            font-size: 16px;
            color: #000;
            font-weight: 600;
            word-break: break-all;
          }

          /* Enhanced features section */
          .features {
            margin: 32px 0;
            padding: 24px;
            background: #f9f9f9;
            border-radius: 12px;
            border: 1px solid #f0f0f0;
          }

          .features-title {
            font-size: 14px;
            font-weight: 600;
            color: #000;
            margin-bottom: 16px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
          }

          .feature-list {
            list-style: none;
          }

          .feature-list li {
            font-size: 14px;
            color: #333;
            margin-bottom: 12px;
            padding-left: 24px;
            position: relative;
            line-height: 1.5;
            animation: featureSlide 0.5s ease-out;
          }

          .feature-list li:nth-child(1) {
            animation-delay: 0.3s;
          }

          .feature-list li:nth-child(2) {
            animation-delay: 0.4s;
          }

          .feature-list li:nth-child(3) {
            animation-delay: 0.5s;
          }

          @keyframes featureSlide {
            from {
              opacity: 0;
              transform: translateX(-10px);
            }
            to {
              opacity: 1;
              transform: translateX(0);
            }
          }

          .feature-list li:before {
            content: "→";
            position: absolute;
            left: 0;
            color: #000;
            font-weight: 600;
          }

          /* Call-to-action button with hover animation */
          .cta-section {
            margin-top: 32px;
            text-align: center;
          }

          .cta-button {
            display: inline-block;
            background: #000;
            color: white;
            padding: 14px 40px;
            border-radius: 50px;
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
            letter-spacing: 0.5px;
            transition: all 0.3s ease;
            cursor: pointer;
            border: 2px solid #000;
            animation: buttonFadeIn 0.6s ease-out 0.4s backwards;
          }

          @keyframes buttonFadeIn {
            from {
              opacity: 0;
              transform: scale(0.95);
            }
            to {
              opacity: 1;
              transform: scale(1);
            }
          }

          .cta-button:hover {
            background: white;
            color: #000;
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.15);
          }

          .cta-button:active {
            transform: translateY(0);
          }

          .secondary-button {
            display: inline-block;
            background: transparent;
            color: #000;
            padding: 14px 40px;
            border-radius: 50px;
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
            letter-spacing: 0.5px;
            border: 2px solid #000;
            margin-left: 12px;
            transition: all 0.3s ease;
            animation: buttonFadeIn 0.6s ease-out 0.5s backwards;
          }

          .secondary-button:hover {
            background: #000;
            color: white;
            transform: translateY(-2px);
          }

          /* Footer with metadata */
          .footer {
            background: #f5f5f5;
            padding: 24px 32px;
            border-top: 1px solid #f0f0f0;
            text-align: center;
          }

          .footer-text {
            font-size: 12px;
            color: #999;
            line-height: 1.6;
            margin-bottom: 12px;
          }

          .metadata {
            font-size: 11px;
            color: #bbb;
            padding-top: 12px;
            border-top: 1px solid #f0f0f0;
          }

          .divider {
            height: 1px;
            background: #f0f0f0;
            margin: 24px 0;
          }

          /* Responsive design */
          @media (max-width: 600px) {
            .container {
              border-radius: 8px;
            }

            .header {
              height: 220px;
            }

            .header-title {
              font-size: 24px;
            }

            .content {
              padding: 32px 24px;
            }

            .info-grid {
              grid-template-columns: 1fr;
            }

            .secondary-button {
              display: block;
              margin-left: 0;
              margin-top: 12px;
            }

            .greeting {
              font-size: 18px;
            }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <!-- Header with liquid animation -->
          <div class="header">
            <div class="liquid-blob blob-1"></div>
            <div class="liquid-blob blob-2"></div>
            <div class="liquid-blob blob-3"></div>
            <div class="header-content">
              <h1 class="header-title">AGENTIC X</h1>
              <p class="header-subtitle">AI ONBOARDING AGENT</p>
            </div>
          </div>

          <!-- Content -->
          <div class="content">
            <p class="greeting">Thank you for your demo request!</p>

            <p style="font-size: 14px; color: #666; line-height: 1.6; margin-bottom: 24px;">
              We've received your onboarding request and our team is excited to show you how AI onboarding agent  can transform your security operations.
            </p>

            <!-- Info Grid -->
            <div class="info-grid">
              <div class="info-item">
                <div class="info-label">Company</div>
                <div class="info-value">${company}</div>
              </div>
              <div class="info-item">
                <div class="info-label">Contact Email</div>
                <div class="info-value">${email}</div>
              </div>
            </div>

            <!-- Features Section -->
            <div class="features">
              <div class="features-title">What's Next</div>
              <ul class="feature-list">
                <li>AI oboarding agent will assist you</li>
                <li>Personalized demo tailored to your security needs</li>
                <li>Direct access to our security experts for Q&A</li>
              </ul>
            </div>

            <div class="divider"></div>

            <!-- CTA Section -->
            <div class="cta-section">
              <a href="https://example.com/demo" class="secondary-button">Schedule Demo</a>
              <a href="https://example.com/docs" class="secondary-button">View Documentation</a>
            </div>
          </div>

          <!-- Footer -->
          <div class="footer">
            <p class="footer-text">
              AI ONBOARDING - Advanced Security Operations Platform<br>
              Protecting your infrastructure with intelligent automation
            </p>
            <div class="metadata">
              Request ID: ${Date.now()}<br>
              © 2025 AGENTIC X . All rights reserved.
            </div>
          </div>
        </div>
      </body>
      </html>
    `
    })

    res.json({ success: true })
  } catch (err) {
    console.error("SMTP error:", err)
    res.status(500).json({ error: "Email failed" })
  }
})

app.post("/api/create-session", (req, res) => {
  const scan_id = crypto.randomUUID()
  const ip = req.ip
  scans[scan_id] = { 
    status: "WAITING",
    created_at: new Date().toISOString(),
    ip_address: ip
  }
  activeSessions[ip] = scan_id
  console.log(`✓ New session created: ${scan_id} for ${ip}`)
  res.json({ scan_id })
})

app.get("/api/active-session", (req, res) => {
  const scan_id = activeSessions[req.ip]
  if (!scan_id) return res.status(404).json({ error: "No active scan" })
  res.json({ scan_id })
})

app.get("/api/active-session-status", (req, res) => {
  const scan_id = activeSessions[req.ip]
  if (!scan_id) return res.json({ status: "WAITING" })
  res.json(scans[scan_id])
})

// NEW: Get scan history
app.get("/api/scan-history", (req, res) => {
  const limit = parseInt(req.query.limit) || 10
  res.json({
    scans: scanHistory.slice(-limit).reverse(),
    total: scanHistory.length
  })
})

// NEW: Get specific scan details
app.get("/api/scan/:scan_id", (req, res) => {
  const { scan_id } = req.params
  const scan = scans[scan_id]
  if (!scan) return res.status(404).json({ error: "Scan not found" })
  res.json(scan)
})

// ENHANCED: Improved scoring algorithm
app.post("/api/scan-result", (req, res) => {
  const { system, security, scan_id, agent_version } = req.body

  let score = 100
  const findings = []
  const recommendations = []
  const critical_issues = []

  // Security checks with detailed scoring
  if (security.firewall !== "ON") { 
    findings.push("Firewall disabled")
    recommendations.push("Enable Windows Firewall immediately")
    critical_issues.push("FIREWALL_DISABLED")
    score -= 15 
  }

  if (security.defender !== "ENABLED") { 
    findings.push("Windows Defender real-time protection disabled")
    recommendations.push("Enable Windows Defender real-time protection")
    critical_issues.push("DEFENDER_DISABLED")
    score -= 15 
  }

  if (security.rdp === "YES") { 
    findings.push("RDP enabled (brute-force risk)")
    recommendations.push("Disable RDP or use strong authentication with VPN")
    score -= 15 
  }

  if (security.smb_v1 === "ENABLED") { 
    findings.push("SMBv1 enabled (WannaCry vulnerability)")
    recommendations.push("Disable SMBv1 immediately - known security risk")
    critical_issues.push("SMBV1_ENABLED")
    score -= 20 
  }

  if (security.failed_logins > 5) { 
    findings.push(`${security.failed_logins} failed login attempts detected`)
    recommendations.push("Review security logs for potential brute-force attacks")
    score -= 10 
  }

  // NEW: UAC check
  if (security.uac_status === "DISABLED") {
    findings.push(" User Account Control (UAC) disabled")
    recommendations.push("Enable UAC for better security")
    score -= 10
  }

  // NEW: Auto-updates check
  if (security.auto_updates === "DISABLED") {
    findings.push("Windows auto-updates disabled")
    recommendations.push("Enable automatic Windows updates")
    score -= 10
  }

  // NEW: Check for open ports
  if (security.open_ports && security.open_ports.length > 20) {
    findings.push(` ${security.open_ports.length} open ports detected`)
    recommendations.push("Review and close unnecessary open ports")
    score -= 5
  }

  // ClamAV results
  if (security.clamav?.status === "INFECTED") {
    findings.push(`🦠 ClamAV: ${security.clamav.infected_count} infected files detected`)
    recommendations.push("Quarantine and remove infected files immediately")
    critical_issues.push("MALWARE_DETECTED")
    score -= Math.min(30, security.clamav.infected_count * 5)
  }

  // NEW: Nmap results
  if (security.nmap?.status === "COMPLETED" && security.nmap.ports_count > 10) {
    findings.push(`Nmap detected ${security.nmap.ports_count} open ports`)
    score -= 5
  }

  // NEW: System health checks
  if (system.cpu_usage > 90) {
    findings.push(" High CPU usage detected")
    recommendations.push("Investigate high CPU usage - possible malware activity")
    score -= 5
  }

  if (system.ram_usage > 90) {
    findings.push(" High memory usage detected")
    recommendations.push("Check memory-intensive processes")
    score -= 5
  }

  if (system.disk_usage > 90) {
    findings.push(" Low disk space")
    recommendations.push("Free up disk space - less than 10% remaining")
    score -= 5
  }

  if (score < 0) score = 0

  // Determine risk level
  let risk_level = "LOW"
  if (score < 40) risk_level = "CRITICAL"
  else if (score < 60) risk_level = "HIGH"
  else if (score < 75) risk_level = "MEDIUM"

  const report = {
    scan_id,
    score,
    severity: score < 40 ? "HIGH" : score < 70 ? "MEDIUM" : "LOW",
    risk_level,
    system,
    security,
    findings,
    recommendations,
    critical_issues,
    agent_version,
    scan_completed_at: new Date().toISOString(),
    soc_response: [
      "✓ Continuous log ingestion and analysis",
      "✓ AI-based anomaly detection",
      "✓ Automated threat containment",
      "✓ 24x7 SOC analyst review",
      "✓ Incident response playbooks",
      "✓ Compliance reporting"
    ]
  }

  scans[scan_id] = {
    status: "PROCESSED",
    report
  }

  // Add to history
  scanHistory.push({
    scan_id,
    score,
    risk_level,
    timestamp: new Date().toISOString(),
    hostname: system.hostname
  })

  console.log(`✓ Scan ${scan_id} processed - Score: ${score}/100, Risk: ${risk_level}`)
  res.json({ success: true, score, risk_level })
})

// Download agent
app.get("/download/agent.exe", (req, res) => {
  const exePath = path.join(process.cwd(), "agent.exe")
  if (!fs.existsSync(exePath)) {
    console.log(" agent.exe not found")
    return res.status(404).json({ error: "Agent file not found" })
  }
  console.log("✓ Downloading agent.exe")
  res.download(exePath, "SOC_Scanner.exe")
})

// ClamAV report
app.get("/api/clamav-report/:scan_id", (req, res) => {
  const { scan_id } = req.params
  const scan = scans[scan_id]

  if (!scan || !scan.report?.security?.clamav?.report) {
    return res.status(404).send("ClamAV report not available")
  }

  res.type("text/plain").send(scan.report.security.clamav.report)
})

// NEW: Export scan report as JSON
app.get("/api/export/:scan_id", (req, res) => {
  const { scan_id } = req.params
  const scan = scans[scan_id]
  
  if (!scan || !scan.report) {
    return res.status(404).json({ error: "Scan not found" })
  }

  res.setHeader('Content-Type', 'application/json')
  res.setHeader('Content-Disposition', `attachment; filename="scan_${scan_id}.json"`)
  res.json(scan.report)
})

// NEW: Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    uptime: process.uptime(),
    active_scans: Object.keys(scans).length,
    timestamp: new Date().toISOString()
  })
})

// ============================================================
// ENHANCED WEBSOCKET
// ============================================================

const server = http.createServer(app)
const wss = new WebSocketServer({ server })

const sockets = new Map()

wss.on("connection", (ws) => {
  console.log("🔌 New WebSocket connection")
  
  ws.on("message", (msg) => {
    let data
    try { 
      data = JSON.parse(msg.toString()) 
    } catch (e) {
      console.log(" Invalid WebSocket message")
      return 
    }

    const { type, scan_id, message } = data
    if (!scan_id) {
      console.log(" WebSocket message missing scan_id")
      return
    }

    if (!sockets.has(scan_id)) {
      sockets.set(scan_id, { agent: null, ui: new Set() })
    }

    const entry = sockets.get(scan_id)

    if (type === "REGISTER_AGENT") {
      entry.agent = ws
      ws.role = "agent"
      ws.scan_id = scan_id

      // ✅ MARK SCAN AS RUNNING
      if (scans[scan_id]) {
        scans[scan_id].status = "RUNNING"
        scans[scan_id].started_at = new Date().toISOString()
      }

      console.log(`✓ Agent registered → scan ${scan_id} is RUNNING`)
      return
    }

    if (type === "PROGRESS") {
      console.log(` Progress [${scan_id}]: ${message}`)
      
      // Broadcast to all UI clients
      for (const ui of entry.ui) {
        if (ui.readyState === ui.OPEN) {
          ui.send(JSON.stringify({
            type: "PROGRESS",
            message,
            timestamp: new Date().toISOString()
          }))
        }
      }
    }
  })

  ws.on("close", () => {
    const { scan_id, role } = ws
    if (!scan_id || !sockets.has(scan_id)) return

    const entry = sockets.get(scan_id)
    if (role === "agent") {
      entry.agent = null
      console.log(`✓ Agent disconnected for scan ${scan_id}`)
    }
    if (role === "ui") {
      entry.ui.delete(ws)
      console.log(`✓ UI disconnected for scan ${scan_id}`)
    }

    // Clean up if no connections remain
    if (!entry.agent && entry.ui.size === 0) {
      sockets.delete(scan_id)
      console.log(`✓ Cleaned up scan ${scan_id}`)
    }
  })

  ws.on("error", (error) => {
    console.error(" WebSocket error:", error.message)
  })
})

// ============================================================
// SERVER STARTUP
// ============================================================

const PORT = process.env.PORT || 3000

server.listen(PORT, () => {
  console.log("╔═══════════════════════════════════════╗")
  console.log("║ Agentic X Security System - Enhanced  ║")
  console.log("╚═══════════════════════════════════════╝")
  console.log(` Backend Server: http://localhost:${PORT}`)
  console.log(` WebSocket Server: ws://localhost:${PORT}`)
  console.log(`Ready to process security scans`)
  console.log("")
})

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 Shutting down gracefully...')
  server.close(() => {
    console.log('✓ Server closed')
    process.exit(0)
  })
})

// ============================================================
// KEY IMPROVEMENTS & NEW FEATURES
// ============================================================

/*
BUG FIXES:
1. ✓ Added JSON body size limit (50mb) for large scan data
2. ✓ Better error handling for missing agent.exe
3. ✓ WebSocket error handling
4. ✓ Proper cleanup of disconnected sockets
5. ✓ Added missing error responses

NEW FEATURES:
1. ✓ Scan history tracking (/api/scan-history)
2. ✓ Individual scan lookup (/api/scan/:scan_id)
3. ✓ Enhanced scoring algorithm with detailed checks
4. ✓ Risk level classification (CRITICAL/HIGH/MEDIUM/LOW)
5. ✓ Recommendations for each finding
6. ✓ Critical issues tracking
7. ✓ System health checks (CPU, RAM, disk)
8. ✓ Export scan report as JSON (/api/export/:scan_id)
9. ✓ Health check endpoint (/api/health)
10. ✓ Better logging with emojis
11. ✓ Timestamps for all operations
12. ✓ Graceful shutdown handling
13. ✓ Active scan counting
14. ✓ WebSocket message timestamps

SECURITY ENHANCEMENTS:
1. ✓ More comprehensive security scoring
2. ✓ UAC status checking
3. ✓ Auto-update status checking
4. ✓ Open ports analysis
5. ✓ System resource monitoring
6. ✓ Critical issue flagging
*/