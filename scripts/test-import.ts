// Petit script de test manuel de POST /api/cves/import (top-level await -> module).
export {}
const res = await fetch("http://localhost:3000/api/cves/import", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ cveId: "CVE-1999-0001" })
})
const data = await res.json()
console.log(JSON.stringify(data, null, 2))