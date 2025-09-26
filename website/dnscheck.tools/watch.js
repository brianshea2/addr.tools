import { IPAddr }               from 'https://addr.tools/js/ipaddr'
import { Client as RDAPClient } from 'https://addr.tools/js/rdap'
import { encode, fetchOk }      from 'https://addr.tools/js/util'

// get & set clientId
const clientId = window.location.pathname.match(/^\/watch\/([0-9a-f]{1,8})$/)?.[1] ?? Math.floor(Math.random() * 0xffffffff).toString(16)
history.replaceState(null, '', `/watch/${clientId}`)
document.title = `dnscheck.tools/watch/${clientId}`
document.getElementById('clientid').innerHTML = clientId

// state
const rdapClient = new RDAPClient()
let autoscroll   = true   // toggle for autoscroll on new request
let count        = 0      // number of requests received
let countdownId           // countdown timer `setInterval()` id
let timer                 // current countdown value

// commonly used elements
const contentDiv   = document.getElementById('content')
const requestsDiv  = document.getElementById('requests')
const countSpan    = document.getElementById('count')
const wsStatusSpan = document.getElementById('ws-status')
const timerSpan    = document.getElementById('timer')

// toggle autoscroll based on user scroll position
contentDiv.addEventListener('scroll', () => {
  if (Math.abs(contentDiv.scrollTop + contentDiv.clientHeight - contentDiv.scrollHeight) < 10) {
    autoscroll = true
  } else {
    autoscroll = false
  }
})

// returns cached promise of PTR name for given IP string
const getPtr = (() => {
  const cache = {}
  return ip => {
    if (cache[ip] === undefined) {
      cache[ip] = fetchOk(
          `https://cloudflare-dns.com/dns-query?name=${new IPAddr(ip).reverseZone()}&type=ptr`,
          { headers: { Accept: 'application/dns-json' } }
        )
        .then(r => r.json())
        .then(({ Answer }) => Answer?.find(({ type }) => type === 12)?.data?.slice(0, -1))
    }
    return cache[ip]
  }
})()

// socket open handler
const handleOpen = () => {
  console.log('WebSocket opened')
  // set status
  wsStatusSpan.innerHTML = 'listening'
  wsStatusSpan.className = 'green'
  // start countdown timer
  timer = 120
  timerSpan.innerHTML = `(${timer})`
  countdownId = setInterval(() => {
    timerSpan.innerHTML = `(${--timer})`
    if (timer === 0) {
      clearInterval(countdownId)
      countdownId = undefined
    }
  }, 1000)
  // set content
  if (count === 0) {
    requestsDiv.innerHTML = '<p>listening for requests...' +
      `<p>try \`<span ondblclick="window.getSelection().selectAllChildren(this)">dig txt ${clientId}.test.dnscheck.tools</span>\`` +
      `<p>or <a href="https://${clientId}.test.dnscheck.tools/" onclick="fetch(this.href).catch(() => {});return false">click here</a>.`
  }
}

// socket message handler
const handleMessage = ({ data }) => {
  // parse data
  const request = JSON.parse(data)
  // increment count, clear placeholder content
  if (count++ === 0) {
    requestsDiv.innerHTML = ''
  }
  countSpan.innerHTML = count
  // add DNS request content
  const tmpId = Math.random().toString(36).slice(2)
  const ipLink = `<a href="https://info.addr.tools/${request.remoteIp}">${request.remoteIp}</a>`
  let html = `<div class="dns-request-wrapper"><span>#${count}</span><div class="dns-request">${encode(request.msgText).replace(/\n/g, '<br>')}` +
    `<br>;; CLIENT: ${ipLink}#${request.remotePort}<span id="ptr-${tmpId}">(<i>pending</i>)</span>` +
    `<span id="rdap-${tmpId}"> (<i>pending</i>)</span> (${request.proto})`
  if (request.tlsVersion) {
    html += `<br>;; TLS: version ${request.tlsVersion.replace(/^TLS ?/, '')}; cipherSuite: ${request.tlsCipherSuite}`
    if (request.tlsNamedGroup) {
      html += `; namedGroup: ${encode(request.tlsNamedGroup)}`
    }
    if (request.tlsDidResume) {
      html += '; sessionReuse: true'
    }
    if (request.tlsServerName) {
      html += `; serverName: ${encode(request.tlsServerName)}`
    }
    if (request.tlsNegotiatedProtocol) {
      html += `; alpn: ${encode(request.tlsNegotiatedProtocol)}`
    }
  }
  html += `<br>;; WHEN: ${new Date(request.time * 1000).toLocaleString()}</div></div>`
  requestsDiv.innerHTML += html
  // autoscroll
  if (autoscroll) {
    contentDiv.scrollTo(contentDiv.scrollLeft, contentDiv.scrollHeight)
  }
  // get PTR, update when available
  getPtr(request.remoteIp).catch(() => {}).then(ptr => {
    const span = document.getElementById(`ptr-${tmpId}`)
    if (ptr) {
      span.innerHTML = `(${encode(ptr)})`
    } else {
      span.remove()
    }
  })
  // get RDAP, update when available
  rdapClient.lookupIP(request.remoteIp).then(r => {
    const reg = r.registrantName || r.data.name || r.data.handle
    const span = document.getElementById(`rdap-${tmpId}`)
    if (reg) {
      span.innerHTML = ` (${encode(reg)})`
    } else {
      span.remove()
    }
  })
}

// socket close handler
const handleClose = e => {
  console.log('WebSocket closed', e)
  // set status
  wsStatusSpan.innerHTML = 'done'
  wsStatusSpan.className = 'red'
  // stop countdown timer
  if (countdownId) {
    clearInterval(countdownId)
    countdownId = undefined
  }
  timerSpan.innerHTML = ''
  // set content
  if (e.code === 4000) { // clientId is already in use
    requestsDiv.innerHTML = `<p class="red">error: ${clientId} is already in use`
  } else {
    timerSpan.innerHTML = `<span class="link" onclick="window.openSocket()">reopen</span>`
    if (count === 0) {
      requestsDiv.innerHTML = `<p>no requests received`
    }
  }
}

// opens and sets listeners on WebSocket connection to recieve DNS requests
window.openSocket = () => {
  const socket = new WebSocket(`wss://ws.dnscheck.tools/watch/${clientId}`, 'full')
  socket.addEventListener('open', handleOpen)
  socket.addEventListener('message', handleMessage)
  socket.addEventListener('close', handleClose)
  // keep socket alive
  let keepAliveId
  socket.addEventListener('open', () => {
    keepAliveId = setInterval(() => socket.readyState === 1 && socket.send('keepalive'), 25000)
  })
  socket.addEventListener('close', () => keepAliveId && clearInterval(keepAliveId))
}

// start listening
window.openSocket()
