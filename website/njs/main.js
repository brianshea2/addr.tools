const get_self_ip_host = r =>
  r.remoteAddress.replace(/[.:]/g, "-").replace(/^-/, "0-").replace(/-$/, "-0") + ".ip.addr.tools"

const make_client_id = () =>
  Math.floor(Math.random() * 0xffffffff).toString(16)

const myip_content = r => {
  if (r.args.format === "json") {
    r.headersOut["Content-Type"] = "application/json"
    const obj = {}
    if (r.args.key === undefined) {
      obj.ip = r.variables.remote_addr
    } else {
      obj[r.args.key] = r.variables.remote_addr
    }
    r.return(200, JSON.stringify(obj))
    return
  }
  if (r.args.format === "pfsense") {
    r.headersOut["Content-Type"] = "text/html"
    r.return(200, `<html><head><title>Current IP Check</title></head><body>Current IP Address: ${r.variables.remote_addr}</body></html>\n`)
    return
  }
  if (r.args.format === "plain") {
    r.headersOut["Content-Type"] = "text/plain"
    r.return(200, r.variables.remote_addr)
    return
  }
  if (r.args.format === undefined) {
    r.headersOut["Content-Type"] = "text/plain"
    r.return(200, r.variables.remote_addr + "\n")
    return
  }
  r.headersOut["Content-Type"] = "text/plain"
  r.return(400, "Bad format\n")
}

const header_echo_content = r => {
  r.return(200, r.variables.request + "\n" + r.rawHeadersIn.map(header => `${header[0]}: ${header[1]}\n`).join(""))
}

const header_echo = r => {
  const validHeaderName = /^[a-zA-Z0-9_-]+$/
  const validHeaderValue = /^[ -~]+$/
  const validStatusCode = /^[1-5][0-9][0-9]$/
  let statusCode = 200
  const headersOut = {}
  for (const key in r.args) {
    if (validHeaderName.test(key)) {
      const name = key.toLowerCase()
      const values = Array.isArray(r.args[key]) ? r.args[key] : [r.args[key]]
      for (let i = 0; i < values.length; i++) {
        if (name === "status-code") {
          if (validStatusCode.test(values[i])) {
            statusCode = +values[i]
          }
        } else if (validHeaderValue.test(values[i])) {
          if (headersOut[name] === undefined) {
            headersOut[name] = values[i]
          } else if (Array.isArray(headersOut[name])) {
            headersOut[name].push(values[i])
          } else {
            headersOut[name] = [headersOut[name], values[i]]
          }
        }
      }
    }
  }
  r.status = statusCode
  r.headersOut["Content-Type"] = "text/plain"
  for (const key in headersOut) {
    r.headersOut[key] = headersOut[key]
  }
}

export default {
  get_self_ip_host,
  make_client_id,
  myip_content,
  header_echo_content,
  header_echo
}
