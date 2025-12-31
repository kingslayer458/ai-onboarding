// ============================================================
// ENHANCED SERVER.JS - Bug Fixes + New Features
// ============================================================

import { WebSocketServer } from "ws"
import http from "http"
import express from "express"
import cors from "cors"
import crypto from "crypto"
import path from "path"
import fs from "fs"

const app = express()
app.use(cors())
app.use(express.json({ limit: '50mb' })) // Increased limit for large scan data

const scans = {}
const activeSessions = {}
const scanHistory = [] // NEW: Track all scans

// ============================================================
// ENHANCED REST APIs
// ============================================================

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
  console.log("║   SOC Security System - Enhanced      ║")
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