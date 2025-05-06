import { IPAddr, IPRange } from 'https://addr.tools/js/ipaddr'
import { Mutex, fetchOk }  from 'https://addr.tools/js/util'
export class RDAPServiceNotFoundError extends Error {
  constructor(query) {
    super(`No RDAP service found for ${query}`)
    this.query = query
    this.name = 'RDAPServiceNotFoundError'
  }
}
class Response {
  constructor(query, data) {
    this.query = query
    this.data = data
  }
  findEntityByRole(role) {
    return this.data?.entities?.find(({ roles }) => roles?.includes(role))
  }
  get registrantName() {
    return this.findEntityByRole('registrant')?.vcardArray?.[1]?.find(([ name ]) => name === 'fn')?.[3]
  }
}
class DomainService {
  constructor(url) {
    this.url = url
  }
  lookup(domain, fetchOpts) {
    return fetchOk(`${this.url}domain/${domain}`, fetchOpts).then(r => r.json())
  }
}
class IPService {
  constructor(url) {
    this.url = url
    this.mu = new Mutex()
    this.cache = []
  }
  addCache(data) {
    if (!data.startAddress || !data.endAddress) {
      return
    }
    try {
      this.cache.push({ data, range: new IPRange(data.startAddress, data.endAddress) })
    } catch (e) {
      // ignore invalid startAddress or endAddress
    }
  }
  getCached(ipOrRange) {
    return this.cache.find(({ range }) => range.contains(ipOrRange))?.data
  }
  async lookup(ipOrRange, fetchOpts) {
    let data = this.getCached(ipOrRange)
    if (!data) {
      await this.mu.lock()
      try {
        data = this.getCached(ipOrRange)
        if (!data) {
          data = await fetchOk(`${this.url}ip/${ipOrRange}`, fetchOpts).then(r => r.json())
          this.addCache(data)
        }
      } finally {
        this.mu.unlock()
      }
    }
    return data
  }
}
export class Client {
  constructor() {
    this.domainServices = []
    this.ipServices = []
  }
  async bootstrapDNS() {
    const data = await fetchOk('https://data.iana.org/rdap/dns.json').then(r => r.json())
    const servicesByURL = {}
    data.services.forEach(svc => {
      const url = svc[1].find(str => str.startsWith('https://'))
      if (url === undefined) {
        return
      }
      if (servicesByURL[url] === undefined) {
        servicesByURL[url] = new DomainService(url)
      }
      this.domainServices.push(...svc[0].map(str => ({
        tld: '.' + str.toLowerCase(),
        service: servicesByURL[url]
      })))
    })
    this.domainServices.sort((a, b) => b.tld.length - a.tld.length)
  }
  async bootstrapIP() {
    const data = await Promise.all([
      fetchOk('https://data.iana.org/rdap/ipv4.json').then(r => r.json()),
      fetchOk('https://data.iana.org/rdap/ipv6.json').then(r => r.json())
    ])
    const servicesByURL = {}
    data.flatMap(obj => obj.services).forEach(svc => {
      const url = svc[1].find(str => str.startsWith('https://'))
      if (url === undefined) {
        return
      }
      if (servicesByURL[url] === undefined) {
        servicesByURL[url] = new IPService(url)
      }
      this.ipServices.push(...svc[0].map(cidr => ({
        range: new IPRange(cidr),
        service: servicesByURL[url]
      })))
    })
    this.ipServices.sort((a, b) =>
      b.range.start.compareTo(a.range.start) ||   // start address descending
      a.range.end.compareTo(b.range.end)          // end address ascending
    )
  }
  async lookupDomain(domain, fetchOpts) {
    domain = domain.toLowerCase()
    if (this.domainServicesReady === undefined) {
      this.domainServicesReady = this.bootstrapDNS()
    }
    await this.domainServicesReady
    const { service, tld } = this.domainServices.find(({ tld }) => domain.endsWith(tld)) ?? {}
    if (!service) {
      throw new RDAPServiceNotFoundError(domain)
    }
    return new Response(domain, await service.lookup(domain, fetchOpts))
  }
  async lookupIP(ipOrRange, fetchOpts) {
    if (!(ipOrRange instanceof IPAddr) && !(ipOrRange instanceof IPRange)) {
      ipOrRange = ipOrRange.includes('/') ? new IPRange(ipOrRange) : new IPAddr(ipOrRange)
    }
    if (this.ipServicesReady === undefined) {
      this.ipServicesReady = this.bootstrapIP()
    }
    await this.ipServicesReady
    const service = this.ipServices.find(({ range }) => range.contains(ipOrRange))?.service
    if (!service) {
      throw new RDAPServiceNotFoundError(ipOrRange)
    }
    return new Response(ipOrRange, await service.lookup(ipOrRange, fetchOpts))
  }
}
