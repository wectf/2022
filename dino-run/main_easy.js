const { Server, WebSocket } = require('ws');
const jwt = require('jsonwebtoken');
const wss = new Server({ port: 7071 });
const {randomBytes} = require("crypto")
const fs = require("fs");
const request = require('request');

const privateKey = fs.readFileSync('private.key');
const publicKey = fs.readFileSync('public.key');

let locationMap = new Map();
const secretKey = "6Lcw_OcZAAAAALfd_FvUm_Dm1SxjinZlH_sNC_i7"
const FLAG = "we{4ae56569-449a-4ff7-a5f3-fe1da7a367ce@w3Lc0me-t0-W3C7F}"
const boardSize = 32;

const currentTime = () => {
    return Date.now() / 1000
}

function verify_recaptcha_token(token, callback){
    request("https://www.google.com/recaptcha/api/siteverify?secret=" + secretKey + "&response=" + token,function(error,response,body) {
        body = JSON.parse(body);
        callback(body.success)
    });
}

const normalizeBoundary = (coordXY) => {
    coordXY = coordXY > 0 ? coordXY : 0;
    coordXY = coordXY < boardSize ? coordXY : boardSize - 1;
    return coordXY
}

const changePos = (pos, direction) => {
    pos.y += direction === "up" ? -1 : direction === "down" ? 1 : 0;
    pos.x += direction === "left" ? -1 : direction === "right" ? 1 : 0;
    return {
        x: normalizeBoundary(pos.x),
        y: normalizeBoundary(pos.y)
    }
}

const isDead = (pos) => {
    return false;
}

let USERNAMES = {}

setInterval(()=>{
    let locations = [];
    const toDeletes = [];
    const currentTimestamp = currentTime();
    locationMap.forEach((v, k) => {
        if (currentTimestamp - v.lastMove > 300)
            toDeletes.push(k)
        if (v.x !== 0 || v.y !== 0)
            locations.push(v)
    })
    toDeletes.forEach((k) => locationMap.delete(k));
    locations = locations.slice(0, 100)
    // console.log("sending", locations, "deleted", toDeletes, "broadcasted", wss.clients.size, "at", currentTimestamp);
    wss.clients.forEach(function each(client) {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({
                command: "state",
                locations: locations,
                success: true
            }));
        }
    });
}, 1000)

wss.on('connection', (ws) => {
    ws.on('message', (messageAsString) => {
        const messages = JSON.parse(messageAsString)
        switch (messages.command) {
            case "create":
                verify_recaptcha_token(messages.captcha, (correct) => {
                    if (correct) {
                        const usernameB64 = Buffer.from(messages.name).toString("base64");
                        if (USERNAMES[usernameB64] !== undefined) {
                            return ws.send(JSON.stringify({
                                success: false, msg: "username taken"
                            }))
                        }
                        USERNAMES[usernameB64] = true;
                        const key = randomBytes(32).toString("base64")
                        locationMap.set(key, {x: 0, y: 0, lastMove: currentTime(), name: messages.name, dino: messages.dino})
                        const token = jwt.sign({
                            position: {x: 0, y: 0}, dead: false, key, name: messages.name
                        }, privateKey, { algorithm: 'RS256'});
                        return ws.send(JSON.stringify({
                            command: "set_token",
                            token,
                            dead: false,
                            success: true,
                        }))
                    }
                    return ws.send(JSON.stringify({
                        success: false, msg: "recaptcha wrong"
                    }))
                })
                break
            case "up":
            case "down":
            case "left":
            case "right":
                try {
                    const decoded = jwt.verify(messages.token, publicKey, { algorithm: 'RS256'});
                    if (decoded.dead) {
                        return ws.send(JSON.stringify({
                            success: false,
                            msg: "your dino is dead"
                        }))
                    }
                    const position = changePos(decoded.position, messages.command);
                    const dead = isDead(position)

                    let item = locationMap.get(decoded.key) || {};
                    item.x = position.x
                    item.y = position.y
                    item.lastMove =  currentTime()

                    const token = jwt.sign({
                        position: dead ? {x: 0, y: 0} : position, dead, key: decoded.key, name: messages.name
                    }, privateKey, { algorithm: 'RS256'});
                    return ws.send(JSON.stringify({
                        command: "set_token",
                        token,
                        dead,
                        flag: position.x === boardSize - 1 && position.y === boardSize - 1 ? FLAG : "",
                        success: true,
                    }))
                } catch(err) {
                    console.log(err)
                }
        }
    });
    ws.on("close", () => {
    });
});



