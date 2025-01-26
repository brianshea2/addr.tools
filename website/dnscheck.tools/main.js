import { IPAddr, IPRange }      from 'https://www.addr.tools/js/ipaddr'
import { Client as RDAPClient } from 'https://www.addr.tools/js/rdap'
import { encode, fetchOk }      from 'https://www.addr.tools/js/util'

// handle tabs
const updateTab = tab => {
  if (tab === undefined) {
    tab = window.location.hash === '#more' ? 'more' : 'results'
  }
  history.replaceState(null, '', window.location.pathname + (tab === 'results' ? '' : `#${tab}`))
  document.querySelectorAll('.active').forEach(el => el.classList.remove('active'))
  document.getElementById(`tab-${tab}`)?.classList.add('active')
  document.getElementById(`content-${tab}`)?.classList.add('active')
  document.getElementById(`status-${tab}`)?.classList.add('active')
}
updateTab()
window.addEventListener('hashchange', () => updateTab())
document.querySelectorAll('a.tab').forEach(el => {
  const tab = el.id.slice(4) // 'tab-'
  el.addEventListener('click', e => {
    e.preventDefault()
    updateTab(tab)
  })
})

// state
const clientId       = Math.floor(Math.random() * 0xffffffff).toString(16)
const rdapClient     = new RDAPClient()
const geoLookups     = {}               // geolocation lookup promises by IP string
const ipData         = {}               // combined IP data promises
const clientIPs      = {}               // detected HTTP client source IPs
const clientSubnets  = {}               // EDNS advertised client subnets
const resolvers      = {}               // detected DNS resolvers
const dnssecTests    = [ ...Array(12) ] // DNSSEC test results
const rtts           = []               // DNS round trip times
const udpSizes       = []               // EDNS advertised UDP buffer sizes
let count            = 0                // number of DNS requests received
let ipLongestLength  = 0                // longest IP length (used for css var --ip-min-width)
let ptrLongestLength = 0                // longest PTR/NS length (used for css var --ptr-min-width)
let geoLongestLength = 0                // longest geo length (used for css var --geo-min-width)
let seenIPv6         = false            // whether any DNS requests have been seen over IPv6

// commonly used elements
const rootEl           = document.documentElement
const resultsDiv       = document.getElementById('content-results')
const connectionDiv    = document.getElementById('connection-results')
const clientSubnetsDiv = document.getElementById('ecs-results')
const resolversDiv     = document.getElementById('resolver-results')
const dnssecDiv        = document.getElementById('dnssec-results')
const rttStatusSpan    = document.getElementById('rtt-status')
const ednsStatusSpan   = document.getElementById('edns-status')
const dnssecStatusSpan = document.getElementById('dnssec-status')
const ipv6StatusSpan   = document.getElementById('ipv6-status')
const tcpStatusSpan    = document.getElementById('tcp-status')
const countSpan        = document.getElementById('count')

// generates some DNS requests from the browser to the given subdomain
const makeQuery = (subdomain, abortSignal) => fetch(`https://${subdomain}.dnscheck.tools/`, {
  signal: AbortSignal.any([ abortSignal, AbortSignal.timeout(10000) ]),
}).then(r => r.ok, () => false)

// returns promise of RDAP registrant name or other identifier for given IPAddr or IPRange
const getReg = ipOrRange => rdapClient.lookupIP(ipOrRange).then(
  r => r.registrantName?.replace(/(?:\s+|,\s*)(?:llc|l\.l\.c\.|ltd\.?|inc\.?)$/i, '') || r.data.name || r.data.handle
)

// returns cached promise of geolocation for given IPAddr or IPRange
const getGeo = ipOrRange => {
  // use first IP of range
  const ip = ipOrRange instanceof IPRange ? ipOrRange.start : ipOrRange
  // all ipv6 of the same /64 should have the same geolocation
  const str = `${ip.is4() ? ip : new IPAddr(ip & 0xffffffffffffffff0000000000000000n)}`
  if (geoLookups[str] === undefined) {
    geoLookups[str] = fetchOk(`https://ipinfo.addr.tools/${str}`).then(r => r.json())
      .then(({ city, region, country }) => [ city, region, country ].filter(v => v).join(', '))
  }
  return geoLookups[str]
}

// returns promise of PTR name or SOA NS for given IPAddr
const getPtr = ip =>
  fetchOk(`https://cloudflare-dns.com/dns-query?name=${ip.reverseZone()}&type=ptr`, { headers: { Accept: 'application/dns-json' } })
    .then(r => r.json())
    .then(({ Answer, Authority }) => ({
      ptr: Answer?.find(({ type }) => type === 12)?.data?.slice(0, -1),
      ns: Authority?.find(({ type }) => type === 6)?.data?.split(' ')[0].slice(0, -1),
    }))

// returns cached promise of combined geo, ptr, and rdap reg data for given IP or CIDR string
const getIPData = str => {
  if (ipData[str] === undefined) {
    const ipOrRange = str.includes('/') ? new IPRange(str) : new IPAddr(str)
    const gets = [
      getReg(ipOrRange).then(reg => ({ reg }), () => ({})),
      getGeo(ipOrRange).then(geo => ({ geo }), () => ({})),
    ]
    if (ipOrRange instanceof IPAddr) {
      gets.push(getPtr(ipOrRange).catch(() => ({})))
    }
    ipData[str] = Promise.all(gets).then(data => Object.assign({ str, ipOrRange }, ...data))
  }
  return ipData[str]
}

// generates HTML for an IP list item
const ipItem = ({ str, ptr, ns, geo }) => {
  let html = `<li><span><a class="no-ul" href="https://info.addr.tools/${str}" target="_blank">${str}</a></span>`
  if (ptr) {
    html += ` <span class="blue"><abbr title="PTR record (reverse DNS)">ptr</abbr>: ${encode(ptr)}</span>`
  } else if (ns) {
    html += ` <span class="violet"><abbr title="NameServer for the reverse DNS zone">ns</abbr>: ${encode(ns)}</span>`
  } else {
    html += '<span></span>'
  }
  if (geo) {
    html += ` <span class="indigo">${encode(geo)}</span>`
  } else {
    html += '<span></span>'
  }
  html += '</li>'
  return html
}

// generates HTML for an IP list given an array of IP data objects
const ipList = objs => {
  let html = ''
  const pending = objs.filter(({ pending }) => pending)
  if (pending.length) {
    html += '<div class="subtitle bold"><i>Pending</i></div>' +
      `<ul class="ip-list">${pending.map(ipItem).join('')}</ul>`
  }
  const byReg = {}
  objs.filter(({ pending }) => !pending).forEach(obj => {
    if (byReg[obj.reg || ''] === undefined) {
      byReg[obj.reg || ''] = [ obj ]
    } else {
      byReg[obj.reg || ''].push(obj)
    }
  })
  Object.keys(byReg).sort((a, b) => a.localeCompare(b)).forEach(reg => {
    html += `<div class="subtitle bold">${reg ? encode(reg) : '<i>Unknown</i>'}</div>` +
      `<ul class="ip-list">${byReg[reg].sort((a, b) => a.ipOrRange.compareTo(b.ipOrRange)).map(ipItem).join('')}</ul>`
  })
  return html
}

// updates style vars --ip-min-width, --ptr-min-width, --geo-min-width given an array of IP data objects
const updateMinWidths = objs => {
  const thisLongestIP = Math.max(...objs.map(({ str }) => str.length))
  if (thisLongestIP > ipLongestLength) {
    ipLongestLength = thisLongestIP
    rootEl.style.setProperty('--ip-min-width', `${ipLongestLength}ch`)
  }
  const thisLongestPTR = Math.max(...objs.map(({ ptr, ns }) => ptr ? ptr.length + 5 : ns ? ns.length + 4 : 0))
  if (thisLongestPTR > ptrLongestLength) {
    ptrLongestLength = thisLongestPTR
    rootEl.style.setProperty('--ptr-min-width', `${ptrLongestLength}ch`)
  }
  const thisLongestGEO = Math.max(...objs.map(({ geo }) => geo ? geo.length : 0))
  if (thisLongestGEO > geoLongestLength) {
    geoLongestLength = thisLongestGEO
    rootEl.style.setProperty('--geo-min-width', `${geoLongestLength}ch`)
  }
}

// draws the client IPs section
const drawIPs = () => {
  const objs = Object.values(clientIPs)
  connectionDiv.innerHTML = connectionDiv.firstElementChild.outerHTML + ipList(objs)
  updateMinWidths(objs)
}

// draws the EDNS Client Subnets section
const drawClientSubnets = () => {
  const objs = Object.values(clientSubnets)
  clientSubnetsDiv.classList.remove('hidden')
  clientSubnetsDiv.innerHTML = clientSubnetsDiv.firstElementChild.outerHTML + ipList(objs)
  updateMinWidths(objs)
}

// draws the DNS resolvers section
const drawResolvers = () => {
  const objs = Object.values(resolvers)
  resolversDiv.innerHTML = resolversDiv.firstElementChild.outerHTML + ipList(objs)
  updateMinWidths(objs)
}

// draws the DNSSEC test results section
const drawDNSSEC = () => {
  let title, statusTooltip, statusClass
  const dnssec = '<a class="no-ul" href="https://en.wikipedia.org/wiki/Domain_Name_System_Security_Extensions" target="_blank">' +
    '<abbr title="Domain Name System Security Extensions">DNSSEC</abbr></a>'
  if ([ 1, 2, 3, 5, 6, 7 ].some(i => dnssecTests[i])) {
    // one or more ecdsa failing domains connected
    title = `<div class="dialogue">Oh no! Your DNS responses are not authenticated with ${dnssec}:</div>`
    statusTooltip = 'DNS Security Extensions\n\nYour DNS responses are not authenticated'
    statusClass = 'red'
  } else if (dnssecTests.some(t => t === undefined)) {
    // tests are still running
    title = dnssecDiv.firstElementChild.outerHTML
  } else if ([ 0, 4, 8 ].every(i => dnssecTests[i])) {
    if ([ 9, 10, 11 ].every(i => !dnssecTests[i])) {
      // all good!
      title = `<div class="dialogue">Great! Your DNS responses are authenticated with ${dnssec}:</div>`
      statusTooltip = 'DNS Security Extensions\n\nYour DNS responses are authenticated'
      statusClass = 'green'
    } else {
      // one or more ed25519 failing domains connected
      title = `<div class="dialogue">Okay! Your DNS responses are authenticated, except when using newer ${dnssec} algorithms:</div>`
      statusTooltip = 'DNS Security Extensions\n\nYour DNS responses are authenticated (except Ed25519)'
      statusClass = 'yellow'
    }
  } else {
    // inconclusive
    title = '<div class="dialogue">Hmm... There was an issue checking your DNS security:</div>'
    statusTooltip = 'DNS Security Extensions\n\nAn error occurred'
    statusClass = 'yellow'
  }
  if (statusClass) {
    dnssecStatusSpan.innerHTML = `<span class="${statusClass}" title="${statusTooltip}">DNSSEC</span>`
  }
  dnssecDiv.innerHTML = title +
    '<div><table class="dnssec"><thead><tr>' +
    '<th></th>' +
    '<th>ECDSA <span class="nowrap">P-256</span></th>' +
    '<th>ECDSA <span class="nowrap">P-384</span></th>' +
    '<th>Ed25519</th>' +
    '</tr></thead><tbody>' +
    [ 'Good', 'Bad', 'Expired', 'Missing' ].map(
      (label, sigIndex) => '<tr>' +
        `<th>${label} signature</th>` +
        [ 0, 4, 8 ].map(
          algOffset => {
            const got = dnssecTests[algOffset + sigIndex]
            if (got === undefined) {
              return '<td>&#8230;</td>'
            }
            const exp = sigIndex === 0 // only the 'Good' tests should make a successful connection
            const act = got ? 'connected' : 'not connected'
            return got === exp ?
              `<td><span class="green" title="Pass (${act})">&#10003;</span></td>` :
              `<td><span class="${algOffset === 8 && !exp ? 'yellow' : 'red'}" title="Fail (${act})">&#10005;</span></td>`
          }
        ).join('') +
        '</tr>'
    ).join('') +
    '</tbody></table></div>'
}

// detects HTTP client's IPv4 and IPv6 addresses
const testIPs = () => Promise.all([ 'ipv4', 'ipv6' ].map(
  sub => fetchOk(`https://${sub}.icanhazip.com/`)
    .then(r => r.text())
    .then(str => {
      str = str.trim()
      clientIPs[str] = { str, pending: true }
      drawIPs()
      getIPData(str).then(data => {
        clientIPs[str] = data
        drawIPs()
      })
    }, () => {})
))

// detects DNS resolvers and DNSSEC validation
const testDNS = () => new Promise(done => {
  // listen for DNS requests via WebSocket
  const socket = new WebSocket(`wss://${window.location.host}/watch/${clientId}`)

  // abort all requests on close
  const abortController = new AbortController()

  // on open
  socket.addEventListener('open', async () => {
    console.log('WebSocket opened')
    // generate some DNS requests
    for (let i = 0; i < 5; i++) {
      await Promise.all([
        makeQuery(`${String.fromCharCode(97 + i)}.${clientId}-nullip.go-ipv4`, abortController.signal),
        makeQuery(`${String.fromCharCode(97 + i)}.${clientId}-nullip.go-ipv6`, abortController.signal),
      ])
    }
    // test IPv6 support
    if (!seenIPv6) {
      ipv6StatusSpan.innerHTML = '<span class="red" title="Your DNS resolvers cannot reach IPv6 nameservers">IPv6</span>'
    }
    // test TCP fallback
    const usesTCP = await makeQuery(`${clientId}-truncate.go`, abortController.signal)
    if (!usesTCP) {
      tcpStatusSpan.innerHTML = '<span class="red" title="Your DNS resolvers do not retry over TCP">TCP</span>'
    }
    // test DNSSEC validation
    for (const [ algIndex, alg ] of [ 'alg13', 'alg14', 'alg15' ].entries()) {
      await Promise.all([ '', '-badsig', '-expiredsig', '-nosig' ].map(
        (sigOpt, sigIndex) => makeQuery(`${clientId}${sigOpt}.go-${alg}`, abortController.signal).then(
          got => {
            dnssecTests[4 * algIndex + sigIndex] = got
            drawDNSSEC()
          }
        )
      ))
    }
    // finished
    countSpan.classList.remove('light')
    setTimeout(
      () => {
        if (socket.readyState === 1) {
          socket.close(1000)
        }
      },
      10000
    )
    done()
  })

  // on message
  socket.addEventListener('message', ({ data }) => {
    // parse data
    const request = JSON.parse(data)
    console.log(`[DNS] request from ${request.remoteIp}/${request.proto}:`, request)
    // increment count
    countSpan.innerHTML = ++count
    // add resolver if new
    if (resolvers[request.remoteIp] === undefined) {
      resolvers[request.remoteIp] = {
        str: request.remoteIp,
        pending: true,
        requests: [],
      }
      drawResolvers()
      getIPData(request.remoteIp).then(data => {
        const { requests } = resolvers[request.remoteIp]
        resolvers[request.remoteIp] = { ...data, requests }
        drawResolvers()
      })
    }
    // add request
    resolvers[request.remoteIp].requests.push(request)
    // discover EDNS support, add UDP buffer size
    if (request.isEdns0 && !udpSizes.includes(request.udpSize)) {
      udpSizes.push(request.udpSize)
      udpSizes.sort((a, b) => a - b)
      ednsStatusSpan.innerHTML = `<span class="${udpSizes[0] < 1200 ? 'yellow' : 'green'}" ` +
        `title="Extension Mechanisms for DNS\n\nAdvertised UDP buffer sizes: ${udpSizes.join(', ')}">EDNS</span>`
    }
    if (count === 1 && udpSizes.length === 0) {
      ednsStatusSpan.innerHTML = '<span class="red" title="Extension Mechanisms for DNS\n\nNot advertised">EDNS</span>'
    }
    // discover ECS
    if (request.clientSubnet && !request.clientSubnet.endsWith('/0') && clientSubnets[request.clientSubnet] === undefined) {
      clientSubnets[request.clientSubnet] = {
        str: request.clientSubnet,
        pending: true,
      }
      drawClientSubnets()
      getIPData(request.clientSubnet).then(data => {
        clientSubnets[request.clientSubnet] = data
        drawClientSubnets()
      })
    }
    // discover IPv6 support
    if (!seenIPv6 && request.remoteIp.includes(':')) {
      seenIPv6 = true
      ipv6StatusSpan.innerHTML = '<span class="green" title="Your DNS resolvers connect to nameservers over IPv6">IPv6</span>'
    }
  })

  // on close
  socket.addEventListener('close', e => {
    abortController.abort()
    console.log('WebSocket closed', e)
    console.log('resolvers:', resolvers)
    if (count === 0) {
      resolversDiv.innerHTML = resolversDiv.firstElementChild.outerHTML +
        '<p><span class="red">an error occurred.</span> ' +
        '<span class="link" onclick="window.location.reload()">reload</span> to try again.'
    }
  })
})

// detects DNS average round trip time
const testRTT = async () => {
  let rand, start, avg
  const tlds = [ 'com', 'net', 'org', 'biz', 'info' ]
  for (const tld of [ ...tlds, ...tlds, ...tlds ]) {
    rand = Math.random().toString(36).slice(2)
    start = Date.now()
    await fetch(`https://test-${rand}.null-addr.${tld}/`).catch(() => {})
    rtts.push(Date.now() - start)
    avg = Math.round(rtts.reduce((sum, x) => sum + x) / rtts.length)
    rttStatusSpan.innerHTML = `<span class="${avg <= 150 ? 'green' : avg <= 500 ? 'yellow' : 'red'}">${avg}ms</span>`
  }
  rttStatusSpan.classList.remove('light')
}

// monitors resizes to toggle IP list tabular mode
const monitorResizes = () => {
  let minWidth
  const obsvr = new ResizeObserver(() => {
    requestAnimationFrame(() => {
      if (resultsDiv.classList.contains('ip-list-tabular')) {
        if (resultsDiv.scrollWidth > resultsDiv.clientWidth) {
          minWidth = resultsDiv.scrollWidth
          resultsDiv.classList.remove('ip-list-tabular')
        }
        return
      }
      if (resultsDiv.clientWidth >= minWidth) {
        resultsDiv.classList.add('ip-list-tabular')
      }
    })
  })
  obsvr.observe(resultsDiv)
  obsvr.observe(resultsDiv.firstElementChild)
}

// let's go!!!
monitorResizes()
testIPs()
await testDNS()
await Promise.allSettled(Object.values(ipData))
testRTT()
