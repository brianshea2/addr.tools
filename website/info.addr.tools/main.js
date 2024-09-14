import { IPAddr, IPRange }      from 'https://www.addr.tools/js/ipaddr'
import { Client as RDAPClient } from 'https://www.addr.tools/js/rdap'
import { encode, fetchOk }      from 'https://www.addr.tools/js/util'

const rdapClient = new RDAPClient()

const domainNamePattern = '(?:[0-9a-z_](?:[0-9a-z_-]*[0-9a-z])?\\.)*[0-9a-z](?:[0-9a-z-]*[0-9a-z])?\\.[a-z][0-9a-z-]*[0-9a-z]'
const ipOrCidrPattern = `${IPAddr.v4Pattern}(?:/(?:3[0-2]|[1-2][0-9]|[0-9]))?|${IPAddr.v6Pattern}(?:/(?:12[0-8]|1[0-1][0-9]|[1-9][0-9]|[0-9]))?`
const domainNameRegex = new RegExp(`^${domainNamePattern}$`, 'i')
const infoRegex = new RegExp(`(?:(${domainNamePattern})|(^|[^0-9a-z.])(${ipOrCidrPattern})(?=[^0-9a-z.]|$))`, 'gi')

const jCardFormatter = jCard => jCard[1].reduce((out, prop) => {
  if (prop[0] !== 'version') {
    const values = prop.slice(3).flat().flatMap(val => typeof val === 'string' ? val.split('\n') : val).filter(val => val !== '')
    const params = Object.entries(prop[1])
      .map(entry => [ entry[0], [entry[1]].flat().flatMap(val => typeof val === 'string' ? val.split('\n') : val).filter(val => val !== '') ])
      .filter(entry => entry[1].length > 0)
      .map(entry => [ entry[0], entry[1].length === 1 ? entry[1][0] : entry[1] ])
    if (params.length > 0) {
      values.unshift(Object.fromEntries(params))
    }
    if (values.length > 0) {
      out[prop[0]] = values.length === 1 ? values[0] : values
    }
  }
  return out
}, {})

const jsonReplacer = (key, value) => {
  const type = value === null ? 'null' : typeof value
  if (type === 'object') {
    if (Array.isArray(value)) {
      return value.length > 0 ? value : undefined // hide empty arrays
    }
    const entries = Object.entries(value)
      .filter(([ k ]) => k !== 'rdapConformance' && k !== 'links' && k !== 'notices' && k !== 'port43')
      .map(entry => entry[0] === 'vcardArray' ? [ 'vCardObj', jCardFormatter(entry[1]) ] : entry)
      .map(([ k, v ]) => [ `<key>${encode(k)}</key>`, v ])
    return entries.length > 0 ? Object.fromEntries(entries) : undefined // hide empty objects
  }
  if (type === 'string') {
    value = encode(value)
    value = value.replace(infoRegex, (_, domain, beforeIp, ip) => domain !== undefined ? `<domain>${domain}</domain>` : `${beforeIp}<ip>${ip}</ip>`)
  }
  return `<value ${type}>${value}</value>`
}

const infoLink = (label, page) => `<a href="/${page}" onclick="history.pushState(null, '', '/${page}');window.reload();return false">${label}</a>`
const domainLinks = domain => {
  const labels = domain.split('.')
  if (labels.length <= 2) {
    return infoLink(`<span>${domain}</span>`, domain)
  }
  return infoLink(`<span>${labels.shift()}</span>.`, domain) + `<span class="sublinks">${domainLinks(labels.join('.'))}</span>`
}

const htmlify = (obj, quoteStrings) => JSON.stringify(obj, jsonReplacer, 2)
  .replace(/<domain>(.*?)<\/domain>/g, (_, domain) => `<span class="domain">${domainLinks(domain)}</span>`)
  .replace(/<ip>(.*?)<\/ip>/g, (_, ip) => `<span class="ip">${infoLink(ip, ip)}</span>`)
  .replace(/"<key>(.*?)<\/key>"/g, (_, key) => `<span class="key">"${key}"</span>`)
  .replace(/"<value (.*?)>(.*?)<\/value>"/g, (_, type, value) => {
    if (quoteStrings && type === 'string') {
      value = `"${value}"`
    }
    return `<span class="${type} value">${value}</span>`
  })

const dnsLookup = (name, type, fetchOpts) => fetchOk(`https://www.addr.tools/dns/${name}/${type}`, fetchOpts).then(r => r.json())
const dnsTypes = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 65: 'HTTPS' }
const dnsSortOrder = [ 5, 1, 28, 65, 15, 16, 12, 2, 6 ]
const drawDns = (data, div) => {
  data = data.filter(o => o.type in dnsTypes).reduce((seen, current) => {
    if (seen.every(o => o.type !== current.type || o.name !== current.name || o.data !== current.data)) {
      seen.push(current)
    }
    return seen
  }, [])
  data.sort((a, b) => dnsSortOrder.indexOf(a.type) - dnsSortOrder.indexOf(b.type))
  const nameWidth = data.map(o => o.name.length).reduce((max, current) => current > max ? current : max, 0)
  div.innerHTML = data.map(
    o => [
      ' '.repeat(5 - dnsTypes[o.type].length),
      dnsTypes[o.type],
      ' '.repeat(2),
      htmlify(o.name, false),
      ' '.repeat(2 + nameWidth - o.name.length),
      htmlify(o.data, false)
    ].join('')
  ).join('<br>')
}

let abortController
const loadInfo = async () => {
  abortController = new AbortController()
  const { signal } = abortController

  const query = (s => {
    try {
      return new IPAddr(s)
    } catch (e) {
      // fallthrough
    }
    try {
      return new IPRange(s)
    } catch (e) {
      // fallthrough
    }
    if (domainNameRegex.test(s)) {
      return s.toLowerCase()
    }
    return null
  })(window.location.pathname.slice(1))

  if (query === null) {
    document.title = 'info.addr.tools'
    document.body.innerHTML = `<div><div class="title">Error</div><div class="error">Invalid address</div></div>`
    return
  }

  const name = query.toString()
  document.title = name
  document.body.innerHTML = ''
  if (!(query instanceof IPRange)) {
    document.body.innerHTML += `<div id="dns-container">` +
      `<div class="title"><abbr title="Domain Name System">DNS</abbr> records for ${htmlify(name, false)}</div>` +
      `<div id="dns-data" class="pre">loading...</div></div>`
  }
  document.body.innerHTML += `<div id="rdap-container">` +
    `<div class="title"><abbr title="Registration Data Access Protocol">RDAP</abbr> data for ${htmlify(name, false)}</div>` +
    `<div id="rdap-data" class="pre">loading...</div></div>`

  if (!(query instanceof IPRange)) {
    const dnsDataDiv = document.getElementById('dns-data')

    let dnsData = []
    let nxdomain, servfail, soa
    const handleDnsResponse = resp => {
      if (resp.Status === 3) {
        nxdomain = true
      }
      if (resp.Status === 2) {
        servfail = true
      }
      dnsData.push(...(resp.Answer ?? []))
      dnsData.push(...(resp.Authority ?? []))
      if (dnsData.length > 0) {
        drawDns(dnsData, dnsDataDiv)
        if (soa === undefined) {
          soa = dnsData.find(({ type }) => type === 6)?.name?.replace(/\.$/, '')
        }
      }
    }

    const handleDnsError = ({ message }) => {
      dnsDataDiv.insertAdjacentHTML('afterend', `<br><div class="error">Error: ${encode(message)}</div>`)
    }

    if (query instanceof IPAddr) {
      await dnsLookup(query.reverseZone(), 'ptr', { signal }).then(handleDnsResponse).catch(handleDnsError)
    } else {
      await Promise.all([ 'a', 'aaaa', 'https', 'mx', 'txt' ].map(type =>
        dnsLookup(query, type, { signal }).then(handleDnsResponse).catch(handleDnsError)
      ))
      if (nxdomain) {
        handleDnsError(new Error('NXDOMAIN (Non-existent domain)'))
      }
    }
    if (soa === undefined) {
      await dnsLookup(query instanceof IPAddr ? query.reverseZone() : query, 'soa', { signal }).then(handleDnsResponse).catch(handleDnsError)
    }
    if (soa !== undefined && domainNameRegex.test(soa)) {
      await dnsLookup(soa, 'ns', { signal }).then(handleDnsResponse).catch(handleDnsError)
    }
    if (servfail) {
      handleDnsError(new Error('SERVFAIL (DNSSEC validation or other server failure)'))
    }
    if (dnsData.length === 0) {
      dnsDataDiv.innerHTML = `<span class="error">No records</span>`
    }
  }

  const rdapDataDiv = document.getElementById('rdap-data')

  await rdapClient[(query instanceof IPAddr) || (query instanceof IPRange) ? 'lookupIP' : 'lookupDomain'](query, { signal })
    .then(({ data }) => {
      rdapDataDiv.innerHTML = htmlify(data, true)
    })
    .catch(({ message }) => {
      rdapDataDiv.innerHTML = `<span class="error">No data (${encode(message)})</span>`
    })
}

let run = loadInfo()

window.reload = async () => {
  abortController.abort()
  await run
  run = loadInfo()
}

window.addEventListener('popstate', () => window.reload())
