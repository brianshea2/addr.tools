class IPAddr {
  constructor(value) {
    if (typeof value === 'bigint') {
      this.value = value
    } else if (this.constructor.v4Regex.test(value)) {
      const buffer = new DataView(new ArrayBuffer(4))
      value.split('.').forEach((octet, i) => buffer.setUint8(i, octet))
      this.value = BigInt(buffer.getUint32(0)) | 0xffff00000000n
    } else if (this.constructor.v6Regex.test(value)) {
      const buffer = new DataView(new ArrayBuffer(16))
      const parts = value.split('::')
      parts[0].split(':').forEach((wyde, i) => wyde !== '' && buffer.setUint16(2*i, parseInt(wyde, 16)))
      if (parts[1] !== undefined) {
        parts[1].split(':').reverse().forEach((wyde, i) => wyde !== '' && buffer.setUint16(14-2*i, parseInt(wyde, 16)))
      }
      this.value = (buffer.getBigUint64(0) << 64n) | buffer.getBigUint64(8)
    } else {
      throw new Error(`Cannot parse ${value} as an IP address`)
    }
  }
  #octets() {
    return Array.from(Array(4), (_, i) => (this.value >> BigInt(24-8*i)) & 0xffn)
  }
  #hexString() {
    return this.value.toString(16).padStart(32, '0')
  }
  compareTo(other) {
    return this.value < other.value ? -1 : this.value > other.value ? 1 : 0
  }
  is4() {
    return (this.value & 0xffffffffffffffffffffffff00000000n) === 0xffff00000000n
  }
  reverseZone() {
    return this.is4() ?
      `${this.#octets().reverse().join('.')}.in-addr.arpa` :
      `${this.#hexString().split('').reverse().join('.')}.ip6.arpa`
  }
  toString(short6, force6) {
    if (this.is4() && !force6) {
      return this.#octets().join('.')
    }
    let str = this.#hexString().match(/.{4}/g).join(':')
    if (short6) {
      const contiguousZeroWydes = [ ...str.matchAll(/:?(0000(?::0000)+):?/g) ]
      if (contiguousZeroWydes.length) {
        const longestMatch = contiguousZeroWydes.reduce((a, b) => b[1].length > a[1].length ? b : a)
        str = str.slice(0, longestMatch.index) + '::' + str.slice(longestMatch.index + longestMatch[0].length)
      }
      str = str.replace(/(?<=^|:)0{1,3}/g, '')
    }
    return str
  }
  valueOf() {
    return this.value
  }
  static v4Pattern = Array(4).fill('(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])').join('\\.')
  static v6Pattern = `(?:${[
    '(?:[0-9a-fA-F]{1,4}:){7}(?:[0-9a-fA-F]{1,4}|:)',
    ...Array.from(Array(6), (_, i) => `(?:[0-9a-fA-F]{1,4}:){${6-i}}(?:(?::[0-9a-fA-F]{1,4}){1,${i+1}}|:)`),
    ':(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)',
  ].join('|')})`
  static v4Regex = new RegExp(`^${this.v4Pattern}$`)
  static v6Regex = new RegExp(`^${this.v6Pattern}$`)
}
class IPRange {
  constructor(str, end) {
    if (end === undefined) {
      let hostBits
      if (this.constructor.cidr4Regex.test(str)) {
        hostBits = 0x000000000000000000000000ffffffffn
      } else if (this.constructor.cidr6Regex.test(str)) {
        hostBits = 0xffffffffffffffffffffffffffffffffn
      } else {
        throw new Error(`Cannot parse ${str} as CIDR notation`)
      }
      const parts = str.split('/')
      const ip = new IPAddr(parts[0])
      hostBits >>= BigInt(parts[1])
      this.start = new IPAddr(ip & ~hostBits)
      this.end = new IPAddr(ip | hostBits)
    } else {
      this.start = new IPAddr(str)
      this.end = new IPAddr(end)
      if (this.start > this.end) {
        throw new Error(`Start address ${str} is greater than end address ${end}`)
      }
    }
  }
  compareTo(other) {
    return this.start.compareTo(other.start) || this.end.compareTo(other.end)
  }
  contains(ipOrRange) {
    if (ipOrRange instanceof IPRange) {
      return this.contains(ipOrRange.start) && this.contains(ipOrRange.end)
    }
    return ipOrRange >= this.start && ipOrRange <= this.end
  }
  toString(short6) {
    let hostBits = this.start ^ this.end
    if ((hostBits + 1n) & hostBits) {
      const force6 = !this.start.is4() || !this.end.is4()
      return `${this.start.toString(short6, force6)} - ${this.end.toString(short6, force6)}`
    }
    let prefixLength = 128
    while (hostBits >= 0xffn) {
      hostBits >>= 8n
      prefixLength -= 8
    }
    while (hostBits) {
      hostBits >>= 1n
      prefixLength -= 1
    }
    return `${this.start.toString(short6)}/${this.start.is4() ? prefixLength - 96 : prefixLength}`
  }
  static cidr4Pattern = `${IPAddr.v4Pattern}/(?:3[0-2]|[1-2][0-9]|[0-9])`
  static cidr6Pattern = `${IPAddr.v6Pattern}/(?:12[0-8]|1[0-1][0-9]|[1-9][0-9]|[0-9])`
  static cidr4Regex = new RegExp(`^${this.cidr4Pattern}$`)
  static cidr6Regex = new RegExp(`^${this.cidr6Pattern}$`)
}
export { IPAddr, IPRange }
