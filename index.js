const Crypto = typeof window !== 'undefined' ? crypto : require('crypto').webcrypto
const Atob =   typeof window !== 'undefined' ? atob : require('atob')
// const Btoa =   typeof window !== 'undefined' ? btoa : require('btoa')

function importKey (KeyAsJson, cb) {
  let key = JSON.parse(KeyAsJson)
  let hard = key.hard ? new RegExp(key.hard, 'g') : ''

  return Crypto.subtle.importKey('jwk', key, {name: 'ECDSA', namedCurve: 'P-256'}, false, key.key_ops).then(function (key) {
    return cb(key, hard)
  }).then(function (ret) {
    return ret
  }).catch(function (e) {
    console.error(e)
  })
}
function ab2str (buf) {
  return String.fromCharCode.apply(null, new Uint16Array(buf))
}
function str2ab (str) {
  let buf = new ArrayBuffer(str.length * 2) // 2 bytes for each char
  let bufView = new Uint16Array(buf)
  for (var i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i)
  }
  return buf
}
function arrayToBase64String (ab) {
  let dView = new Uint8Array(ab)   // Get a byte view
  let arr = Array.prototype.slice.call(dView) // Create a normal array
  let arr1 = arr.map(function (item) {
    return String.fromCharCode(item)    // Convert
  })
  return Btoa(arr1.join(''))  // Form a string
}

function base64ToArrayBuffer (s) {
  let asciiString = Atob(s)
  return new Uint8Array([...asciiString].map(char => char.charCodeAt(0)))
}
  
function sign (string, privateKey, cb = console.log) {
  let data = str2ab(string)

  return importKey(privateKey, function (key, regx) {
    if (!regx) {
      return Crypto.subtle.sign({name: 'ECDSA', hash: {name: 'SHA-256'}}, key, data).then(function (signature) {
        return cb(arrayToBase64String(signature))
      }).catch(function (e) {
        console.error(e)
      })
    } else {
      let doWork = function () {
      let work = Crypto.subtle.sign({name: 'ECDSA', hash: {name: 'SHA-256'}}, key, data)
        return work.then(function (signature) {
          let sig = arrayToBase64String(signature)
          if (regx.test(sig)) {
            return cb(sig)
          } else {
            return doWork()
          }
        })
      }
      return doWork()
    }
  })
}

function exportKey (Key, cb = console.log) {
  return Crypto.subtle.exportKey('jwk', Key).then(function (keydata) {
    const key = JSON.stringify(keydata)
    cb(key)
    return key
  }).catch(function (err) {
    console.error(err)
  })
}

function generate (privateKeyCB, publicKeyCB) {
  let keys = {}
  return Crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256'}, true, ['sign', 'verify']).then(function (key) {
    return exportKey(key.privateKey, privateKeyCB).then(function (privateKey) {
      keys.privateKey = privateKey
      return exportKey(key.publicKey, publicKeyCB).then(function (publicKey) {
        keys.publicKey = publicKey
      })
    }).then(function () {
      return keys
    })
  }).catch(function (e) {
    console.error(e)
  })
}
function verify (string, signature, publicKey, cb = console.log) {
  let data = str2ab(string)
  importKey(publicKey, function (key) {
    Crypto.subtle.verify({name: 'ECDSA', hash: {name: 'SHA-256'}}, key, base64ToArrayBuffer(signature), data).then(function (isvalid) {
    // returns a boolean on whether the signature is true or not
      cb(isvalid)
    }).catch(function (e) {
      console.error(e)
    })
  })
}

function sha256 (str) {
  let buffer = new TextEncoder('utf-8').encode(str)
  return Crypto.subtle.digest('SHA-256', buffer).then(function (hash) {
    return hex(hash)
  })
}

function hex (buffer) {
  let hexCodes = []
  let view = new DataView(buffer)
  for (let i = 0; i < view.byteLength; i += 4) {
  // Using getUint32 reduces the number of iterations needed (we process 4 bytes each time)
    let value = view.getUint32(i)
    // toString(16) will give the hex representation of the number without padding
    let stringValue = value.toString(16)
    // We use concatenation and slice for padding
    let padding = '00000000'
    let paddedValue = (padding + stringValue).slice(-padding.length)
    hexCodes.push(paddedValue)
  }
  return hexCodes.join('')
}
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

export {generate, sign, verify, getSig}
