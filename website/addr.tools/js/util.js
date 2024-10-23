class HTTPError extends Error {
  constructor(code) {
    super(`Received HTTP status code ${code}`)
    this.code = code
    this.name = 'HTTPError'
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
export { HTTPError, encode, fetchOk }
