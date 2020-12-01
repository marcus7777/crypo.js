export {generate, sign, verify}

if (typeof localStorage === 'undefined') {
  async function getKeys(cb = console.log) {
    if (!localStorage.prvKey) {
      await generate(p => {localStorage.prvKey = p}, p => {localStorage.pubKey = p})
      cb(localStorage.prvKey, localStorage.pubKey)
    }
    let {prvKey,pubKey} = localStorage
    return {prvKey,pubKey}
  }
  async function getSig(signThis, cb){
    let keys = await getKeys()
    if (typeof signThis === "string") {
      return await sign(signThis, keys.prvKey, cb)
    } else {
      return await sign(JSON.stringify(signThis), keys.prvKey, cb)
    }
  }
  export {getSig}
}
