const get_self_ip_host = r => r.remoteAddress.replace(/[.:]/g, "-").replace(/^-/, "0-").replace(/-$/, "-0") + ".ip.addr.tools"

const header_echo_content = r => {
  if (r.args["status-code"] === "204" || r.args["status-code"] === "205" || r.args["status-code"] === "304") {
    r.return(+r.args["status-code"])
    return
  }
  r.return(200, `${r.variables.request}\n${r.rawHeadersIn.map(hdr => `${hdr[0]}: ${hdr[1]}\n`).join("")}`)
}

const disallowedHeaderNames = /^(Connection|Content-Length|Transfer-Encoding|X-Robots-Tag)$/i
const validHeaderName = /^[a-zA-Z0-9_-]+$/
const validHeaderValue = /^[ -~]+$/
const validStatusCode = /^[2-5][0-9][0-9]$/
const header_echo = r => {
  if (r.status === 200 && typeof r.args["status-code"] === "string" && validStatusCode.test(r.args["status-code"])) {
    r.status = +r.args["status-code"]
  }
  const headersOut = {}
  for (const key in r.args) {
    if (key === "status-code" || disallowedHeaderNames.test(key) || !validHeaderName.test(key)) {
      continue
    }
    const name = key.toLowerCase()
    const values = Array.isArray(r.args[key]) ? r.args[key] : [r.args[key]]
    for (let i = 0; i < values.length; i++) {
      if (!validHeaderValue.test(values[i])) {
        continue
      }
      if (headersOut[name] === undefined) {
        headersOut[name] = [values[i]]
      } else {
        headersOut[name].push(values[i])
      }
    }
  }
  r.headersOut["X-Robots-Tag"] = "noindex"
  for (const key in headersOut) {
    r.headersOut[key] = headersOut[key]
  }
}

export default {
  get_self_ip_host,
  header_echo_content,
  header_echo,
}
