const pubKey = '{"crv":"P-256","ext":true,"key_ops":["verify"],"kty":"EC","x":"86P-wMy_0Hq8EOziW9LJgSLz7JPMOctj5HVsqt5XS0Q","y":"s3n-CRWuA8x7Trwhw_mgrMGp0HrljFvCrvBKu4fXx08"}'
const prvKey = '{"crv":"P-256","d":"9hdpveEK5OE2VPwOhwrSzcOvbnhSLjjnoi5WVWgw8mE","ext":true,"key_ops":["sign"],"kty":"EC","x":"86P-wMy_0Hq8EOziW9LJgSLz7JPMOctj5HVsqt5XS0Q","y":"s3n-CRWuA8x7Trwhw_mgrMGp0HrljFvCrvBKu4fXx08"}'

const {sign, verify} = require('./index')

sign(1234, prvKey, sig => {
  verify(1234, sig, pubKey, isvalid => {
    if (isvalid) {
      console.log("yes", sig)
    } else {
      return false
    }
  })
})
