
  function importKey (KeyAsJson, cb) {
    var key = JSON.parse(KeyAsJson)
    var hard = key.hard ? new RegExp(key.hard, 'g') : ''

    return window.crypto.subtle.importKey('jwk', key, {name: 'ECDSA', namedCurve: 'P-256'}, false, key.key_ops).then(function (key) {
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
    var buf = new ArrayBuffer(str.length * 2) // 2 bytes for each char
    var bufView = new Uint16Array(buf)
    for (var i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i)
    }
    return buf
  }
  function arrayToBase64String (ab) {
    var dView = new Uint8Array(ab)   // Get a byte view
    var arr = Array.prototype.slice.call(dView) // Create a normal array
    var arr1 = arr.map(function (item) {
      return String.fromCharCode(item)    // Convert
    })
    return window.btoa(arr1.join(''))  // Form a string
  }

  function base64ToArrayBuffer (s) {
    var asciiString = window.atob(s)
    return new Uint8Array([...asciiString].map(char => char.charCodeAt(0)))
  }
  
  function sign (string, privateKey, cb) {
    var data = str2ab(string)

    return importKey(privateKey, function (key, regx) {
      if (!regx) {
        return window.crypto.subtle.sign({name: 'ECDSA', hash: {name: 'SHA-256'}}, key, data).then(function (signature) {
          return cb(arrayToBase64String(signature))
        }).catch(function (e) {
          console.error(e)
        })
      } else {
        var doWork = function () {
          var work = window.crypto.subtle.sign({name: 'ECDSA', hash: {name: 'SHA-256'}}, key, data)
          return work.then(function (signature) {
            var sig = arrayToBase64String(signature)
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

  function exportKey (Key, cb) {
    return window.crypto.subtle.exportKey('jwk', Key).then(function (keydata) {
      const key = JSON.stringify(keydata)
      cb(key)
      return key
    }).catch(function (err) {
      console.error(err)
    })
  }
  function generate (privateKeyCB, publicKeyCB) {
    var keys = {}
    return window.crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256'}, true, ['sign', 'verify']).then(function (key) {
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
  function verify (string, signature, publicKey, cb) {
    var data = str2ab(string)
    importKey(publicKey, function (key) {
      window.crypto.subtle.verify({name: 'ECDSA', hash: {name: 'SHA-256'}}, key, base64ToArrayBuffer(signature), data).then(function (isvalid) {
      // returns a boolean on whether the signature is true or not
        cb(isvalid)
      }).catch(function (e) {
        console.error(e)
      })
    })
  }
  function sha256 (str) {
    var buffer = new TextEncoder('utf-8').encode(str)
    return crypto.subtle.digest('SHA-256', buffer).then(function (hash) {
      return hex(hash)
    })
  }

  function hex (buffer) {
    var hexCodes = []
    var view = new DataView(buffer)
    for (var i = 0; i < view.byteLength; i += 4) {
    // Using getUint32 reduces the number of iterations needed (we process 4 bytes each time)
      var value = view.getUint32(i)
    // toString(16) will give the hex representation of the number without padding
      var stringValue = value.toString(16)
    // We use concatenation and slice for padding
      var padding = '00000000'
      var paddedValue = (padding + stringValue).slice(-padding.length)
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
  async function getSig(signThis){
    if (typeof signThis === "string") {
      return await sign(signThis, getKeys().prvKey)
    } else {
      return await sign(JSON.stringify(), getKeys().prvKey)
  }
  export {generate, sign, verify, getSig}
  