const oneTimePad = "twnxtodoqaixrmbwytpqeerfraxpjzmvnwagexygqlugcsianmo"

function encrypt(flag, pad=oneTimePad){
    let result = ""
    for (let idx = 0; idx < pad.length; idx++) {
        const otpEl = pad[idx];
        const flagEl = flag[idx];
        const encryptedFlagEl = otpEl.charCodeAt(0) ^ flagEl.charCodeAt(0);
        result += String.fromCharCode(encryptedFlagEl);
    }
    return result
}

function decrypt(eflag, pad=oneTimePad){
    let result = ""
    for (let idx = 0; idx < eflag.length; idx++) {
        const otpEl = pad[idx];
        const eflagEl = eflag[idx];
        const flagEl = otpEl.charCodeAt(0) ^ eflagEl.charCodeAt(0);
        result += String.fromCharCode(flagEl);
    }
    return result
}

module.exports =  {
    encrypt,
    decrypt
}