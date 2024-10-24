class HTTPError extends Error {
  constructor(code) {
    super(`Received HTTP status code ${code}`)
    this.code = code
    this.name = 'HTTPError'
  }
}
class Mutex {
  #queue
  #locked
  constructor() {
    this.#queue = []
    this.#locked = false
  }
  lock() {
    return new Promise(resolve => {
      if (this.#locked) {
        this.#queue.push({ resolve })
      } else {
        this.#locked = true
        resolve()
      }
    })
  }
  unlock() {
    const next = this.#queue.shift()
    if (next) {
      next.resolve()
    } else {
      this.#locked = false
    }
  }
}
function encode(str) {
  return str?.replace(/["&<>]/g, match => `&#${match.charCodeAt(0)};`)
}
function fetchOk(resource, opts) {
  return fetch(resource, Object.assign({ referrerPolicy: 'no-referrer' }, opts)).then(response => {
    if (!response.ok) {
      throw new HTTPError(response.status)
    }
    return response
  })
}
export { HTTPError, Mutex, encode, fetchOk }
