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
  async runExclusively(callback) {
    await this.lock()
    try {
      return await callback()
    } finally {
      this.unlock()
    }
  }
}
export { Mutex }
