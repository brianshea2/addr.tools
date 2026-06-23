export default {
  content: r => {
    const out = {
      request: r.variables.request,
      headers: r.rawHeadersIn.map(v => `${v[0]}: ${v[1]}`),
    }
    r.headersOut["Content-Type"] = "application/json"
    r.return(200, JSON.stringify(out, null, 2) + "\n")
  },
}
