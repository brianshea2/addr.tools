export default {
  content: r => {
    const out = {
      request: r.variables.request,
      headers: Object.fromEntries(r.rawHeadersIn),
    }
    r.headersOut["Content-Type"] = "application/json"
    r.return(200, JSON.stringify(out, null, 2) + "\n")
  },
}
