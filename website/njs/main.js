const get_self_ip_host = r => r.remoteAddress.replace(/[.:]/g, "-").replace(/^-/, "0-").replace(/-$/, "-0") + ".ip.addr.tools"

const header_echo_content = r => {
  if (r.args["status-code"] === "204" || r.args["status-code"] === "205" || r.args["status-code"] === "304") {
    r.return(+r.args["status-code"])
    return
  }
  let content = `# IP: ${r.variables.remote_addr}.${r.variables.remote_port} > ${r.variables.server_addr}.${r.variables.server_port}\n`
  if (r.variables.ssl_protocol) {
    content += `# TLS: ${r.variables.ssl_session_reused === "r" ? "Reused" : "New"}, ${r.variables.ssl_protocol}\n`
  }
  if (r.variables.ssl_ciphers) {
    content += `# CIPHER: ${r.variables.ssl_ciphers.split(":").map(v => v === r.variables.ssl_cipher ? `[${v}]` : v).join(", ")}\n`
  }
  if (r.variables.ssl_curves) {
    content += `# CURVE: ${r.variables.ssl_curves.split(":").map(v => v === r.variables.ssl_curve ? `[${v}]` : v).join(", ")}\n`
  }
  if (r.variables.ssl_server_name) {
    content += `# SNI: ${r.variables.ssl_server_name}\n`
  }
  content += `${r.variables.request}\n`
  content += r.rawHeadersIn.map(hdr => `${hdr[0]}: ${hdr[1]}\n`).join("")
  r.return(200, content)
}

const disallowedHeaderNames = /^(Connection|Content-Length|Transfer-Encoding)$/i
const validHeaderName = /^[a-zA-Z0-9_-]+$/
const validHeaderValue = /^[ -~]+$/
const validStatusCode = /^[2-5][0-9][0-9]$/
const header_echo = r => {
  const headersOut = {}
  for (const key in r.args) {
    if (key === "status-code") {
      continue
    }
    if (disallowedHeaderNames.test(key)) {
      continue
    }
    if (!validHeaderName.test(key)) {
      continue
    }
    const name = key.toLowerCase()
    const values = Array.isArray(r.args[key]) ? r.args[key] : [r.args[key]]
    for (let i = 0; i < values.length; i++) {
      if (!validHeaderValue.test(values[i])) {
        continue
      }
      if (headersOut[name] === undefined) {
        headersOut[name] = values[i]
      } else if (Array.isArray(headersOut[name])) {
        headersOut[name].push(values[i])
      } else {
        headersOut[name] = [headersOut[name], values[i]]
      }
    }
  }
  for (const key in headersOut) {
    r.headersOut[key] = headersOut[key]
  }
  if (r.status === 200 && typeof r.args["status-code"] === "string" && validStatusCode.test(r.args["status-code"])) {
    r.status = +r.args["status-code"]
  }
}

export default {
  get_self_ip_host,
  header_echo_content,
  header_echo,
}
