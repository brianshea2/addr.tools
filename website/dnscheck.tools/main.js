import { IPAddr, IPRange }      from 'https://addr.tools/js/ipaddr'
import { Client as RDAPClient } from 'https://addr.tools/js/rdap'
import { encode, fetchOk }      from 'https://addr.tools/js/util'

// state
const clientId       = Math.floor(Math.random() * 0xffffffff).toString(16)
const rdapClient     = new RDAPClient()
const geoLookups     = {}               // geolocation lookup promises by IP string
const ipData         = {}               // combined IP data promises
const clientIPs      = {}               // detected HTTP request source and WebRTC ICE candidate IPs
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

// generates some DNS requests from the browser to the given subdomain
const makeQuery = (subdomain, timeout, abortSignal) => {
  if (abortSignal.aborted) {
    return Promise.resolve(false)
  }
  const controller = new AbortController()
  const abortFn = () => controller.abort()
  const timeoutID = setTimeout(abortFn, timeout)
  abortSignal.addEventListener('abort', abortFn)
  return fetch(`https://${subdomain}.dnscheck.tools/`, { signal: controller.signal })
    .then(r => r.ok, () => false)
    .finally(() => {
      clearTimeout(timeoutID)
      abortSignal.removeEventListener('abort', abortFn)
    })
}

// tests if the given IPAddr or entire IPRange is contained within a nonpublic IP space
const reservedRanges = [
  new IPRange('0.0.0.0/8'),             // current network
  new IPRange('10.0.0.0/8'),            // private
  new IPRange('100.64.0.0/10'),         // cgnat
  new IPRange('127.0.0.0/8'),           // loopback
  new IPRange('169.254.0.0/16'),        // link-local
  new IPRange('172.16.0.0/12'),         // private
  new IPRange('192.0.0.0/24'),          // protocol assignments
  new IPRange('192.0.2.0/24'),          // documentation
  new IPRange('192.168.0.0/16'),        // private
  new IPRange('198.18.0.0/15'),         // benchmarking
  new IPRange('198.51.100.0/24'),       // documentation
  new IPRange('203.0.113.0/24'),        // documentation
  new IPRange('224.0.0.0/4'),           // multicast
  new IPRange('240.0.0.0/4'),           // future use, limited broadcast
  new IPRange('::/127'),                // unspecified, loopback
  new IPRange('64:ff9b:1::/48'),        // local-use ipv4/ipv6 translation
  new IPRange('100::/64'),              // discard
  new IPRange('2001::/23'),             // protocol assignments
  new IPRange('2001:db8::/32'),         // documentation
  new IPRange('2002::/16'),             // 6to4
  new IPRange('3fff::/20'),             // documentation
  new IPRange('5f00::/16'),             // segment routing
  new IPRange('fc00::/7'),              // private
  new IPRange('fe80::/10'),             // link-local
  new IPRange('ff00::/8'),              // multicast
]
const isReserved = ipOrRange => reservedRanges.some(r => r.contains(ipOrRange))

// returns promise of RDAP registrant name or other identifier for given IPAddr or IPRange
const getReg = ipOrRange => rdapClient.lookupIP(ipOrRange).then(
  r => r.registrantName?.replace(/(?:\s+|,\s*)(?:llc|l\.l\.c\.|ltd\.?|inc\.?)$/i, '') || r.data.name || r.data.handle
)

// returns cached promise of geolocation for given IPAddr or IPRange
const getGeo = (() => {
  let fetcher = str => fetchOk(`https://ipinfo.io/${str}`, { headers: { Accept: 'application/json' } }).catch(() => {
    fetcher = str => fetchOk(`https://ipinfo.addr.tools/${str}`)
    return fetcher(str)
  })
  return ipOrRange => {
    // use first IP of range
    const ip = ipOrRange instanceof IPRange ? ipOrRange.start : ipOrRange
    // all ipv6 of the same /64 should have the same geolocation
    const str = `${ip.is4() ? ip : new IPAddr(ip & 0xffffffffffffffff0000000000000000n)}`
    if (geoLookups[str] === undefined) {
      geoLookups[str] = fetcher(str).then(r => r.json()).then(
        ({ city, region, country }) => [ city, region, country ].filter(v => v).join(', ')
      )
    }
    return geoLookups[str]
  }
})()

// returns promise of PTR name or SOA NS for given IPAddr
const getPtr = (() => {
  const headers = { Accept: 'application/dns-json' }
  let fetcher = name => fetchOk(`https://cloudflare-dns.com/dns-query?name=${name}&type=ptr`, { headers }).catch(() => {
    fetcher = name => fetchOk(`https://doh-proxy.addr.tools/dns-query?name=${name}&type=ptr`, { headers })
    return fetcher(name)
  })
  return ip => fetcher(ip.reverseZone()).then(r => r.json()).then(({ Answer, Authority }) => ({
    ptr: Answer?.find(({ type }) => type === 12)?.data?.slice(0, -1),
    ns: Authority?.find(({ type }) => type === 6)?.data?.split(' ')[0].slice(0, -1),
  }))
})()

// returns cached promise of combined geo, ptr, and rdap reg data for given IP or CIDR string
const getIPData = str => {
  if (ipData[str] === undefined) {
    const ipOrRange = str.includes('/') ? new IPRange(str) : new IPAddr(str)
    if (isReserved(ipOrRange)) {
      ipData[str] = Promise.resolve({ str, ipOrRange, reserved: true })
    } else {
      const gets = [
        getReg(ipOrRange).then(reg => ({ reg }), () => ({})),
        getGeo(ipOrRange).then(geo => ({ geo }), () => ({})),
      ]
      if (ipOrRange instanceof IPAddr) {
        gets.push(getPtr(ipOrRange).catch(() => ({})))
      }
      ipData[str] = Promise.all(gets).then(data => Object.assign({ str, ipOrRange }, ...data))
    }
  }
  return ipData[str]
}

// generates HTML for an IP list item
const ipItem = ({ str, reserved, ptr, ns, geo }) => {
  let html = '<li>'
  if (reserved) {
    html += `<span>${str}</span>`
  } else {
    html += `<span><a class="no-ul" href="https://info.addr.tools/${str}">${str}</a></span>`
  }
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
  const byReg = {}
  objs.filter(({ pending, reserved }) => !pending && !reserved).forEach(obj => {
    if (byReg[obj.reg || ''] === undefined) {
      byReg[obj.reg || ''] = [ obj ]
    } else {
      byReg[obj.reg || ''].push(obj)
    }
  })
  Object.keys(byReg).sort((a, b) => a ? b ? a.localeCompare(b) : -1 : 1).forEach(reg => {
    html += `<div class="subtitle bold">${reg ? encode(reg) : '<i>Unknown</i>'}</div>` +
      `<ul class="ip-list">${byReg[reg].sort((a, b) => a.ipOrRange.compareTo(b.ipOrRange)).map(ipItem).join('')}</ul>`
  })
  const reserved = objs.filter(({ reserved }) => reserved)
  if (reserved.length) {
    html += '<div class="subtitle bold"><i>Nonpublic Reserved IP Space</i></div>' +
      `<ul class="ip-list">${reserved.sort((a, b) => a.ipOrRange.compareTo(b.ipOrRange)).map(ipItem).join('')}</ul>`
  }
  const pending = objs.filter(({ pending }) => pending)
  if (pending.length) {
    html += '<div class="subtitle bold"><i>Pending</i></div>' +
      `<ul class="ip-list">${pending.map(ipItem).join('')}</ul>`
  }
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
const drawDNSSEC = (() => {
  let f = () => {
    dnssecDiv.innerHTML = dnssecDiv.firstElementChild.outerHTML + '<div><table class="dnssec"><thead><tr><th></th>' +
      '<th>ECDSA <span class="nowrap">P-256</span></th><th>ECDSA <span class="nowrap">P-384</span></th>' +
      '<th>Ed25519</th></tr></thead><tbody>' + [ 'Valid', 'Invalid', 'Expired', 'Missing' ].map(
        t => `<tr><th>${t} signature</th>${`<td class="pending">${'<span>.</span>'.repeat(3)}</td>`.repeat(3)}</tr>`
      ).join('') + '</tbody></table></div>'
    const cols = dnssecDiv.getElementsByTagName('td')
    const link = '<a href="https://en.wikipedia.org/wiki/Domain_Name_System_Security_Extensions" ' +
      'title="Domain Name System Security Extensions">DNSSEC</a>'
    const makeStatus = (text, className) =>
      `<span class="${className}" title="DNS Security Extensions\n\n${text}">DNSSEC</span>`
    f = () => {
      let done = true
      let error = false
      let fail = false
      dnssecTests.forEach((got, i) => {
        if (got === undefined) {
          done = false
          return
        }
        const exp = i < 3 // true for the valid signature tests
        cols[i].className = got === exp ? 'green' : 'red'
        cols[i].innerHTML = got === exp ? 'PASS' : 'FAIL'
        error ||= exp && !got
        fail ||= got && !exp
      })
      if (error) {
        // a dnssec-valid domain failed to connect
        dnssecDiv.firstElementChild.innerHTML = `Hmm... There was a network issue while checking ${link}. ` +
          'The result is inconclusive:'
        dnssecStatusSpan.innerHTML = makeStatus('An error occurred', 'yellow')
        return
      }
      if (fail) {
        // a dnssec-invalid domain connected
        dnssecDiv.firstElementChild.innerHTML = `Oh no! Your DNS responses are not authenticated with ${link}:`
        dnssecStatusSpan.innerHTML = makeStatus('Your DNS responses are not authenticated', 'red')
        return
      }
      if (done) {
        // all tests passed
        dnssecDiv.firstElementChild.innerHTML = `Great! Your DNS responses are authenticated with ${link}:`
        dnssecStatusSpan.innerHTML = makeStatus('Your DNS responses are authenticated', 'green')
        return
      }
    }
    f()
  }
  return () => f()
})()

// detects client's IPv4 and IPv6 addresses via HTTP requests and WebRTC ICE candidates
const testIPs = async () => {
  const urls = [
    'https://myipv4.addr.tools/',
    'https://myipv6.addr.tools/',
    'stun:stun.l.google.com:19302',
    'stun:stun.cloudflare.com:3478',
  ]
  const handleIP = str => {
    if (clientIPs[str] !== undefined) {
      return
    }
    clientIPs[str] = { str, pending: true }
    drawIPs()
    getIPData(str).then(data => {
      clientIPs[str] = data
      drawIPs()
    })
  }
  for (const url of urls) {
    if (!url.startsWith('https:')) {
      continue
    }
    fetchOk(url)
      .then(r => r.text())
      .then(s => s.trim())
      .then(handleIP)
      .catch(() => {})
  }
  const iceServers = urls.filter(url => url.startsWith('stun:')).map(urls => ({ urls }))
  const peerConn = new RTCPeerConnection({ iceServers })
  peerConn.addEventListener('icecandidate', ({ candidate }) => {
    if (!candidate?.candidate) {
      console.log('ICE candidate generation finished')
      peerConn.close()
      return
    }
    const parts = candidate.candidate.split(' ')
    console.log(`ICE candidate: ${parts[4]}`, candidate)
    try {
      handleIP(new IPAddr(parts[4]).toString(true))
    } catch(e) {
      // ignore invalid (i.e., .local) addresses
    }
  })
  peerConn.createDataChannel('dummy')
  peerConn.setLocalDescription(await peerConn.createOffer())
}

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
      await makeQuery(`${String.fromCharCode(97 + i)}.${clientId}-nullip.go`, 10000, abortController.signal)
      await makeQuery(`${String.fromCharCode(97 + i)}.${clientId}-nullip.go-ipv4`, 10000, abortController.signal)
    }
    // test IPv6 support
    if (!seenIPv6) {
      await makeQuery(`${clientId}-nullip.go-ipv6`, 10000, abortController.signal)
    }
    if (!seenIPv6) {
      ipv6StatusSpan.innerHTML = '<span class="red" title="Your DNS resolvers cannot reach IPv6 nameservers">IPv6</span>'
    }
    // test TCP fallback
    const usesTCP = await makeQuery(`${clientId}-truncate.go`, 10000, abortController.signal)
    if (!usesTCP) {
      tcpStatusSpan.innerHTML = '<span class="red" title="Your DNS resolvers do not retry over TCP">TCP</span>'
    }
    // test DNSSEC validation
    drawDNSSEC()
    for (const [ algIndex, alg ] of [ 'alg13', 'alg14', 'alg15' ].entries()) {
      await Promise.all([ '', '-badsig', '-expiredsig', '-nosig' ].map(
        (sigOpt, sigIndex) => makeQuery(`${clientId}${sigOpt}.go-${alg}`, 30000, abortController.signal).then(
          got => {
            dnssecTests[3 * sigIndex + algIndex] = got
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
  for (let i = 0; i < 5; i++) {
    for (const tld of [ 'com', 'net', 'org' ]) {
      rand = Math.random().toString(36).slice(2)
      start = Date.now()
      await fetch(`https://test-${rand}.null-addr.${tld}/`).catch(() => {})
      rtts.push(Date.now() - start)
      avg = Math.round(rtts.reduce((sum, x) => sum + x) / rtts.length)
      rttStatusSpan.innerHTML = `<span class="${avg <= 150 ? 'green' : avg <= 500 ? 'yellow' : 'red'}">${avg}ms</span>`
    }
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
