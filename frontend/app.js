async function start() {
  const r = await fetch("http://localhost:3000/api/create-session", {
    method: "POST"
  })

  if (!r.ok) {
    alert("Failed to create scan session")
    return
  }

  const data = await r.json()
  console.log("Session created:", data)

  document.getElementById("chat").innerHTML = `
    <a href="http://localhost:3000/download/agent.exe">
      Download Security Scanner
    </a>
    <p>Run the scanner after download.</p>
  `

  const interval = setInterval(async () => {
    const r = await fetch("http://localhost:3000/api/active-session-status")
    const s = await r.json()

    if (s.status === "RUNNING") {
      clearInterval(interval)
      location.href = "wait.html"
    }
  }, 2000)
}
