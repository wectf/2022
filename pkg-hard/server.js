const express = require('express');
const {encrypt, decrypt} = require("./encryption1.js")
const path = require('path')
const axios = require("axios")
const fs = require("fs")
const app = express()
const port = 10001
const jwt = require('jsonwebtoken');
BASE = "https://fierce-pickle-raccon.ctf.so"
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, './views'))

function randomGenerator(length) {
  var result           = '';
  var characters       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  var charactersLength = characters.length;
  for ( var i = 0; i < length; i++ ) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
 }
 return result;
}

const OTP = "twnxtodoqaixrmbwytpqeerfraxpjzmvnwagexygqlugcsianmo"

const flagLength = 51;
const jwtPrivateKey = fs.readFileSync(path.join(__dirname, "jwtRS256.key"));


app.get('/', (req, res) => {
  res.render("flag.ejs", {eflag: OTP})
})

app.get('/check_flag', async (req, res) => {
  try {
    const flag = req.query.flag || "";
    if (flag.length < flagLength) return res.send("length mismatch")
    const d1 = encrypt(flag);

    const serverPad = randomGenerator(flagLength);

    let serverResp = await axios.get(BASE + '/eflag', {
      headers: {
        'auth': jwt.sign({
          pad: serverPad
          }, jwtPrivateKey, { algorithm: 'RS256'})
      }
    });
    if (decrypt(serverResp.data.eflag, pad=serverPad) === d1){
      return res.send("ok")
    }
  } catch (e) {}
  return res.send("wtf")
})

app.listen(port, () => {
  console.log(`App listening on port ${port}`)
})
