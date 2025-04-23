import { IPAddr, IPRange }                                from 'https://www.addr.tools/js/ipaddr'
import { Client as RDAPClient, RDAPServiceNotFoundError } from 'https://www.addr.tools/js/rdap'
import { encode, fetchOk }                                from 'https://www.addr.tools/js/util'

const rdapClient = new RDAPClient()
const domainNamePattern = '(?:[0-9a-z_](?:[0-9a-z_-]*[0-9a-z])?\\.)*[0-9a-z](?:[0-9a-z-]*[0-9a-z])?\\.[a-z][0-9a-z-]*[0-9a-z]'
const ipOrCidrPattern = `${IPAddr.v4Pattern}(?:/(?:3[0-2]|[1-2][0-9]|[0-9]))?|${IPAddr.v6Pattern}(?:/(?:12[0-8]|1[0-1][0-9]|[1-9][0-9]|[0-9]))?`
const domainNameRegex = new RegExp(`^${domainNamePattern}$`, 'i')
const infoRegex = new RegExp(`(?:(${domainNamePattern})|(^|[^0-9a-z.])(${ipOrCidrPattern})(?=[^0-9a-z.]|$))`, 'gi')
const footer = `<footer>// <a href="https://info.addr.tools">info.addr.tools</a></footer>`

const jCardFormatter = jCard => jCard[1].reduce((out, prop) => {
  if (prop[0] !== 'version') {
    const values = prop.slice(3).flat().flatMap(val => typeof val === 'string' ? val.split(/\r?\n/) : val).filter(val => val !== '')
    const params = Object.entries(prop[1])
      .map(entry => [ entry[0], [entry[1]].flat().flatMap(val => typeof val === 'string' ? val.split(/\r?\n/) : val).filter(val => val !== '') ])
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
      .filter(([ k ]) => k !== 'links' && k !== 'notices' && k !== 'port43' && k !== 'rdapConformance' && k !== 'redacted')
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

const infoLink = (page, html) => `<a href="/${page}" onclick="history.pushState(null, '', '/${page}');window.reload();return false">${html ?? page}</a>`
const domainLinks = domain => {
  const labels = domain.split('.')
  if (labels.length <= 2) {
    return infoLink(domain, `<span>${domain}</span>`)
  }
  return infoLink(domain, `<span>${labels.shift()}</span>.`) + `<span class="sublinks">${domainLinks(labels.join('.'))}</span>`
}

const htmlify = (obj, quoteStrings) => JSON.stringify(obj, jsonReplacer, 2)
  .replace(/<domain>(.*?)<\/domain>/g, (_, domain) => `<span class="domain">${domainLinks(domain)}</span>`)
  .replace(/<ip>(.*?)<\/ip>/g, (_, ip) => `<span class="ip">${infoLink(ip)}</span>`)
  .replace(/"<key>(.*?)<\/key>"/g, '<span class="key">$1</span>')
  .replace(/"<value (.*?)>(.*?)<\/value>"/g, (_, type, value) => {
    if (quoteStrings && type === 'string') {
      value = `"${value}"`
    }
    return `<span class="${type} value">${value}</span>`
  })
  .replace(/\[\n\s*(.*?)\n\s*\]/g, '[ $1 ]')

const dnsLookup = (() => {
  const headers = { Accept: 'application/dns-json' }
  let fetcher = (name, type, signal) => fetchOk(`https://cloudflare-dns.com/dns-query?name=${name}&type=${type}`, { headers, signal }).catch(() => {
    fetcher = (name, type, signal) => fetchOk(`https://doh-proxy.addr.tools/dns-query?name=${name}&type=${type}`, { headers, signal })
    return fetcher(name, type, signal)
  })
  return (name, type, { signal }) => fetcher(name, type, signal).then(r => r.json())
})()
const dnsTypes = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 65: 'HTTPS' }
const dnsSortOrder = [ 5, 1, 28, 65, 15, 16, 12, 2, 6 ]
const drawDns = (records, div) => {
  records = records.filter(o => o.type in dnsTypes).reduce((seen, current) => {
    if (seen.every(o => o.type !== current.type || o.name !== current.name || o.data !== current.data)) {
      seen.push(current)
    }
    return seen
  }, [])
  records.sort((a, b) => dnsSortOrder.indexOf(a.type) - dnsSortOrder.indexOf(b.type))
  div.innerHTML = records.map(({ type, data }) => {
    if (type === 6) {
      const soaParts = data.split(/\s+/)
      soaParts[1] = soaParts[1].replace(/((?:\\\.|[^.])*)\./, '$1@').replace(/\\\./g, '.')
      data = soaParts.join(' ')
    }
    return `<div><span>${dnsTypes[type]}</span> ${htmlify(data, false)}</div>`
  }).join('')
}

const geoLookup = (() => {
  let fetcher = (str, signal) => fetchOk(`https://ipinfo.io/${str}`, { headers: { Accept: 'application/json' }, signal }).catch(() => {
    fetcher = (str, signal) => fetchOk(`https://ipinfo.addr.tools/${str}`, { signal })
    return fetcher(str, signal)
  })
  return (ip, { signal }) => {
    const str = `${ip.is4() ? ip : new IPAddr(ip & 0xffffffffffffffff0000000000000000n)}`
    return fetcher(str, signal).then(r => r.json()).then(({ city, region, country }) => [ city, region, country ].filter(v => v).join(', '))
  }
})()

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
    document.body.innerHTML = `<div><h2>Error</h2><div class="error">Invalid address</div></div>${footer}`
    return
  }

  const name = (query instanceof IPAddr) || (query instanceof IPRange) ? query.toString(true) : query
  document.title = name
  document.body.innerHTML = `<header><h1>${htmlify(name, false)}</h1></header>`
  if (!(query instanceof IPRange)) {
    document.body.innerHTML += `<div id="dns-container">` +
      `<h2><abbr title="Domain Name System">DNS</abbr> records</h2>` +
      `<div id="dns-data">loading...</div></div>`
  }
  document.body.innerHTML += `<div id="rdap-container">` +
    `<h2><abbr title="Registration Data Access Protocol">RDAP</abbr> data</h2>` +
    `<div id="rdap-data">loading...</div></div>`
  document.body.innerHTML += footer

  if (query instanceof IPAddr) {
    geoLookup(query, { signal }).then(geo => {
      document.body.firstElementChild.innerHTML += `<div id="geo-data">${encode(geo)}</div>`
    }).catch(() => {})
  }

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

    const handleDnsError = e => {
      dnsDataDiv.insertAdjacentHTML('afterend', `<br><div class="error">Error: ${encode(e.message)}</div>`)
    }

    if (query instanceof IPAddr) {
      await dnsLookup(query.reverseZone(), 'ptr', { signal }).then(handleDnsResponse).catch(handleDnsError)
    } else {
      await Promise.all([ 'a', 'aaaa', 'mx', 'txt' ].map(type =>
        dnsLookup(query, type, { signal }).then(handleDnsResponse).catch(handleDnsError)
      ))
      if (nxdomain) {
        dnsDataDiv.insertAdjacentHTML('afterend', `<br><div class="error">Status: NXDOMAIN (Non-eXistent domain)</div>`)
      }
    }
    if (soa === undefined) {
      await dnsLookup(query instanceof IPAddr ? query.reverseZone() : query, 'soa', { signal }).then(handleDnsResponse).catch(handleDnsError)
    }
    if (soa !== undefined && domainNameRegex.test(soa)) {
      await dnsLookup(soa, 'ns', { signal }).then(handleDnsResponse).catch(handleDnsError)
    }
    if (servfail) {
      dnsDataDiv.insertAdjacentHTML('afterend', `<br><div class="error">Status: SERVFAIL (DNS server failure or bogus DNSSEC)</div>`)
    }
    if (dnsData.length === 0) {
      dnsDataDiv.innerHTML = `<span class="error">No records</span>`
    }
  }

  const rdapDataDiv = document.getElementById('rdap-data')
  if ((query instanceof IPAddr) || (query instanceof IPRange)) {
    await rdapClient.lookupIP(query, { signal })
      .then(({ data }) => {
        rdapDataDiv.innerHTML = htmlify(data, true)
      })
      .catch(e => {
        rdapDataDiv.innerHTML = `<span class="error">No data (${encode(e.message)})</span>`
      })
  } else {
    await rdapClient.lookupDomain(query, { signal })
      .then(({ data }) => {
        rdapDataDiv.innerHTML = htmlify(data, true)
      })
      .catch(e => {
        if (e instanceof RDAPServiceNotFoundError) {
          rdapDataDiv.innerHTML = `<span class="error">No RDAP service found for this domain</span>`
          return
        }
        const labels = query.split('.')
        if (labels.length > 2) {
          labels.shift()
          rdapDataDiv.innerHTML = `<span class="error">No data. Try a parent domain: ${htmlify(labels.join('.'), false)}</span>`
          return
        }
        rdapDataDiv.innerHTML = `<span class="error">No data (${encode(e.message)})</span>`
      })
  }
}

let run = loadInfo()

window.reload = async () => {
  abortController.abort()
  await run
  run = loadInfo()
}

window.addEventListener('popstate', () => window.reload())
