import { IPAddr, IPRange } from 'https://addr.tools/js/ipaddr'
import { Mutex, fetchOk } from 'https://addr.tools/js/util'
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
  async lookup(domain, fetchOpts) {
    return fetchOk(`${this.url}domain/${domain}`, fetchOpts).then(r => r.json())
  }
}
class IPService {
  constructor(url) {
    this.url = url
  }
  #cache = []
  #addCache(data) {
    if (!data.startAddress || !data.endAddress) {
      return
    }
    try {
      this.#cache.push({ data, range: new IPRange(data.startAddress, data.endAddress) })
    } catch (e) {
      // ignore invalid startAddress or endAddress
    }
  }
  #getCached(ipOrRange) {
    return this.#cache.find(({ range }) => range.contains(ipOrRange))?.data
  }
  #mu = new Mutex()
  async lookup(ipOrRange, fetchOpts) {
    let data = this.#getCached(ipOrRange)
    if (!data) {
      await this.#mu.lock()
      try {
        data = this.#getCached(ipOrRange)
        if (!data) {
          data = await fetchOk(`${this.url}ip/${ipOrRange}`, fetchOpts).then(r => r.json())
          this.#addCache(data)
        }
      } finally {
        this.#mu.unlock()
      }
    }
    return data
  }
}
export class Client {
  #domainServicesPromise
  async #getDomainServices() {
    if (this.#domainServicesPromise === undefined) {
      this.#domainServicesPromise = fetchOk(this.constructor.dnsBootstrapURL)
        .then(r => r.json())
        .then(({ services }) => {
          const servicesByURL = {}
          return services
            .map(([ tlds, urls ]) => ({ tlds, url: urls.find(s => s.startsWith('https:')) }))
            .filter(({ url }) => url !== undefined)
            .flatMap(({ tlds, url }) => {
              if (servicesByURL[url] === undefined) {
                servicesByURL[url] = new DomainService(url)
              }
              return tlds.map(tld => ({ tld: '.' + tld.toLowerCase(), service: servicesByURL[url] }))
            })
            .sort((a, b) => b.tld.length - a.tld.length)
        })
    }
    return this.#domainServicesPromise
  }
  #ipServicesPromise
  async #getIPServices() {
    if (this.#ipServicesPromise === undefined) {
      this.#ipServicesPromise = Promise.all([
          fetchOk(this.constructor.ipv4BootstrapURL).then(r => r.json()),
          fetchOk(this.constructor.ipv6BootstrapURL).then(r => r.json())
        ])
        .then(values => {
          const servicesByURL = {}
          return values
            .flatMap(({ services }) => services)
            .map(([ cidrs, urls ]) => ({ cidrs, url: urls.find(s => s.startsWith('https:')) }))
            .filter(({ url }) => url !== undefined)
            .flatMap(({ cidrs, url }) => {
              if (servicesByURL[url] === undefined) {
                servicesByURL[url] = new IPService(url)
              }
              return cidrs.map(cidr => ({ range: new IPRange(cidr), service: servicesByURL[url] }))
            })
            .sort((a, b) =>
              b.range.start.compareTo(a.range.start) ||   // start address descending
              a.range.end.compareTo(b.range.end)          // end address ascending
            )
        })
    }
    return this.#ipServicesPromise
  }
  async lookupDomain(domain, fetchOpts) {
    domain = domain.toLowerCase()
    const services = await this.#getDomainServices()
    const { service } = services.find(({ tld }) => domain.endsWith(tld)) ?? {}
    if (!service) {
      throw new RDAPServiceNotFoundError(domain)
    }
    return new Response(domain, await service.lookup(domain, fetchOpts))
  }
  async lookupIP(ipOrRange, fetchOpts) {
    if (!(ipOrRange instanceof IPAddr) && !(ipOrRange instanceof IPRange)) {
      ipOrRange = ipOrRange.includes('/') ? new IPRange(ipOrRange) : new IPAddr(ipOrRange)
    }
    const services = await this.#getIPServices()
    const { service } = services.find(({ range }) => range.contains(ipOrRange)) ?? {}
    if (!service) {
      throw new RDAPServiceNotFoundError(ipOrRange)
    }
    return new Response(ipOrRange, await service.lookup(ipOrRange, fetchOpts))
  }
  static dnsBootstrapURL = 'https://data.iana.org/rdap/dns.json'
  static ipv4BootstrapURL = 'https://data.iana.org/rdap/ipv4.json'
  static ipv6BootstrapURL = 'https://data.iana.org/rdap/ipv6.json'
}
