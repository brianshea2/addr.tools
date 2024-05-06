function encode(str) {
  return str?.replace(/["&<>]/g, match => `&#${match.charCodeAt(0)};`)
}
function fetchOk(resource, opts) {
  return fetch(resource, Object.assign({ referrerPolicy: "no-referrer" }, opts)).then(response => {
    if (!response.ok) {
      throw new Error(`Received HTTP status code ${response.status}`)
    }
    return response
  })
}
export { encode, fetchOk }
