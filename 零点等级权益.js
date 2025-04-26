

let userPhone = []
if (process?.env?.dx) {
    process?.env?.dx.split('&').map(item => {
        if (item) {
            let phone = item.split('#')[0]
            let password = item.split('#')[1]
            userPhone.push({ phone, password })
        }
    })
} else {
    return console.log('未找到环境变量，请设置环境变量dx')
    return
}

const tool = require('./tools/tool.js')
const axios = require('axios')
const getCookie = require('./tools/index.js')
const CryptoJS = require('crypto-js');
const JSEncrypt = require('node-jsencrypt');
let pubKey = `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBkLT15ThVgz6/NOl6s8GNPofdWzWbCkWnkaAm7O2LjkM1H7dMvzkiqdxU02jamGRHLX/ZNMCXHnPcW/sDhiFCBN18qFvy8g6VYb9QtroI09e176s+ZCtiv7hbin2cCTj99iUpnEloZm19lwHyo69u5UMiPMpq0/XKBO8lYhN/gwIDAQAB`
const decrypt = new JSEncrypt(); // 创建加密对象实例
decrypt.setPrivateKey(pubKey)
let pubKey1 = `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+ugG5A8cZ3FqUKDwM57GM4io6JGcStivT8UdGt67PEOihLZTw3P7371+N47PrmsCpnTRzbTgcupKtUv8ImZalYk65dU8rjC/ridwhw9ffW2LBwvkEnDkkKKRi2liWIItDftJVBiWOh17o6gfbPoNrWORcAdcbpk2L+udld5kZNwIDAQAB`
const decrypt1 = new JSEncrypt(); // 创建加密对象实例
decrypt1.setPrivateKey(pubKey1)
const fs = require('fs')
let Cache = {}
let cookies=null
let runArr=[]
async function loginPhone(phone, password) {
    try {
        let timestamp = tool.TIMEstamp()
        let rdmstr = tool.randomString(16)
        // console.log(rdmstr, rdmstr.substring(0, 13));

        let encrypttext = decrypt.encrypt(`iPhone 14 15.4.${rdmstr.substring(0, 12)}${phone}${timestamp}${password}0$$$0.`)
        // console.log(encrypttext);
        let strphone = ''
        for (let a of phone) {
            if (a <= 7) {
                strphone += String(Number(a) + 2)
            } else {
                if (a == 8) {
                    strphone += ':'
                } else if (a == 9) {
                    strphone += ';'
                }
            }
        }
        let data = {
            "headerInfos": {
                "code": "userLoginNormal",
                "timestamp": timestamp,
                "broadAccount": "",
                "broadToken": "",
                "clientType": "#9.6.1#channel50#iPhone 14 Pro Max#",
                "shopId": "20002",
                "source": "110003",
                "sourcePassword": "Sid98s",
                "token": "",
                "userLoginName": phone
            },
            "content": {
                "attach": "test",
                "fieldData": {
                    "loginType": "4",
                    "accountType": "",
                    "loginAuthCipherAsymmertric": encrypttext,
                    "deviceUid": rdmstr,
                    "phoneNum": strphone,
                    "isChinatelecom": "0",
                    "systemVersion": "15.4.0",
                    "authentication": password
                }
            }
        }
        // console.log(data);
        if (!Cache[phone]) {
            let options = {
                url: 'https://appgologin.189.cn:9031/login/client/userLoginNormal',
                method: 'POST',
                data: data
            }
            let res = await axios(options)
            // console.log(res.data);
            // console.log(options);
            Cache[phone] = {
                ...res.data.responseData.data.loginSuccessResult
            }
        } else {
        }

        // console.log(res.data.responseData);
        // return
        let userInfo = {
            ...Cache[phone]
        }
        fs.writeFileSync('./Cache.json', JSON.stringify(Cache), 'utf8')
        let userToken = Cache[phone].token
        let userId = Cache[phone].userId
        timestamp = tool.TIMEstamp()
        data = `<Request>
                                <HeaderInfos>
                                    <Code>getSingle</Code>
                                    <Timestamp>${timestamp}</Timestamp>
                                    <BroadAccount></BroadAccount>
                                    <BroadToken></BroadToken>
                                    <ClientType>#9.6.1#channel50#iPhone 14 Pro Max#</ClientType>
                                    <ShopId>20002</ShopId>
                                    <Source>110003</Source>
                                    <SourcePassword>Sid98s</SourcePassword>
                                    <Token>${userToken}</Token>
                                    <UserLoginName>${phone}</UserLoginName>
                                </HeaderInfos>
                                <Content>
                                    <Attach>test</Attach>
                                    <FieldData>
                                        <TargetId>${tool.encrypt_req('1234567`90koiuyhgtfrdewsaqaqsqde', '', userId)}</TargetId>
                                        <Url>4a6862274835b451</Url>
                                    </FieldData>
                                </Content>
                    </Request>`
        options = {
            url: `https://appgologin.189.cn:9031/map/clientXML`,
            method: 'post',
            data,
            'headers': {
                'Content-Type': 'application/xml;charset=utf-8'
            }
        }
        let titckRes = await axios(options)
        // console.log(titckRes.data);
        if (String(titckRes.data).includes('过期') || String(titckRes.data).includes('校验错误')) {
            timestamp = tool.TIMEstamp()
            rdmstr = tool.randomString(16)
            // console.log(rdmstr, rdmstr.substring(0, 13));

            encrypttext = decrypt.encrypt(`iPhone 14 15.4.${rdmstr.substring(0, 12)}${phone}${timestamp}${password}0$$$0.`)
            // console.log(encrypttext);
            strphone = ''
            for (let a of phone) {
                if (a <= 7) {
                    strphone += String(Number(a) + 2)
                } else {
                    if (a == 8) {
                        strphone += ':'
                    } else if (a == 9) {
                        strphone += ';'
                    }
                }
            }
            data = {
                "headerInfos": {
                    "code": "userLoginNormal",
                    "timestamp": timestamp,
                    "broadAccount": "",
                    "broadToken": "",
                    "clientType": "#9.6.1#channel50#iPhone 14 Pro Max#",
                    "shopId": "20002",
                    "source": "110003",
                    "sourcePassword": "Sid98s",
                    "token": "",
                    "userLoginName": phone
                },
                "content": {
                    "attach": "test",
                    "fieldData": {
                        "loginType": "4",
                        "accountType": "",
                        "loginAuthCipherAsymmertric": encrypttext,
                        "deviceUid": rdmstr,
                        "phoneNum": strphone,
                        "isChinatelecom": "0",
                        "systemVersion": "15.4.0",
                        "authentication": password
                    }
                }
            }
            options = {
                url: 'https://appgologin.189.cn:9031/login/client/userLoginNormal',
                method: 'POST',
                data: data
            }
            res = await axios(options)
            // console.log(res.data);
            Cache[phone] = {
                ...res.data.responseData.data.loginSuccessResult
            }
            fs.writeFileSync('./Cache.json', JSON.stringify(Cache), 'utf8')
            return await loginPhone(phone, password)
        }
        let tickettext = titckRes.data.split('<Ticket>')[1].split('</Ticket>')[0]
        let uid = tool.decrypt_req('1234567`90koiuyhgtfrdewsaqaqsqde', '', tickettext)
        // console.log(uid,'uid');
        userInfo.uid = uid
        userInfo.password = password
        userInfo.phoneNbr = phone
        return userInfo
    } catch (e) {
        return false
    }
}
async function ssoHomLogin(ticket) {
    let options = {
        url: 'https://wappark.189.cn/jt-sign/ssoHomLogin?ticket=' + ticket,
        method: 'GET',
        headers: {
            cookie: cookies.cookie + await getCookie.RefreshCookie(),
        }
    }
    let res = await axios(options)
    return res.data
}
// 获取等级权益
async function getLevelRightsList(userinfo, signData) {
    try {
        let data = {
            phone: userinfo.phoneNbr,
        };
        let options = {
            url: 'https://wappark.189.cn/jt-sign/paradise/getLevelRightsList',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json;charset=utf-8',
                sign: signData.sign,
                cookie: cookies.cookie + await getCookie.RefreshCookie(),
            },
            data: {
                para: tool.encrypt_rsa_hex(data)
            }
        }
        axios(options).then(res => {
            // console.log(res.data.currentLevel);
            // console.log(res.data);
            let level = 'V' + res.data.currentLevel
            res.data[level].map(async (item, index) => {

                if (String(item.righstName).includes('话费')) {
                    // console.log(item);
                    let state = await getState(userinfo, signData, item,level)
                    if (state) {
                        return
                    }
                    runArr.push({
                        userinfo,
                        signData,
                        item
                    })
                    // let jianche = setInterval(() => {
                    //     const now = new Date();
                    //     const hour = now.getHours();
                    //     const minute = now.getMinutes();
                    //     const second = now.getSeconds();
                    //     // 检查时间是否在9点59分59秒到10点0分10秒之间
                    //     if (hour === 0 && minute === 0 && second >= 0) {
                    //         getConversionRights(userinfo, signData, item)
                    //         clearInterval(jianche);
                    //     }
                    // }, 1000);
                }
            })
            // console.log(res.data.V5);
        })
    } catch (err) {
        getLevelRightsList(userinfo, signData)
    }
}
let runNumber=0
async function getState(userinfo, signData, receive,level) {
    if(runNumber>=15) return true
    let data = {
        phone: userinfo.phoneNbr,
        rightsId: receive.id,
        receiveCount: receive.receiveType
    };
    let options = {
        url: 'https://wappark.189.cn/jt-sign/paradise/getConversionRights',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json;charset=utf-8',
            sign: signData.sign,
            cookie: cookies.cookie + await getCookie.RefreshCookie(),
        },
        data: {
            para: tool.encrypt_rsa_hex(data)
        }
    }
    let datas = await axios(options)
    if (datas.data['rightsStatus'].includes('已兑换') || datas.data['rightsStatus'].includes('已领取')) {
        console.log('已兑换--', userinfo.phoneNbr,level)
        return true
    } else {
        console.log('运行兑换--', userinfo.phoneNbr,level)
        runNumber++
        return false
    }
}
async function getConversionRights(userinfo, signData, receive, number = 1) {


    if (number >= 50) return
    data = {
        phone: userinfo.phoneNbr,
        rightsId: receive.id,
    };
    options = {
        url: 'https://wappark.189.cn/jt-sign/paradise/conversionRights',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json;charset=utf-8',
            sign: signData.sign,
            cookie: cookies.cookie + await getCookie.RefreshCookie(),
        },
        data: {
            para: tool.encrypt_rsa_hex(data)
        }
    }
    axios(options).then(res => {
        if (res.data.resoultCode == '0') {
            console.log(userinfo.phoneNbr, '兑换成功~');
        } else if (res.data.resoultCode == '1') {
            setTimeout(() => {
                getConversionRights(userinfo, signData, receive, number + 1)
            }, 1500)
        } else if (res.data.resoultMsg == '您当前金豆数不足~') {
            console.log('您当前金豆数不足~');
        } else if (res.data.resoultMsg == '权益已兑换~') {
            console.log('权益已兑换~');
        } else {
            setTimeout(() => {
                getConversionRights(userinfo, signData, receive, number + 1)
            }, 1500)
        }
    }).catch(err => {
        // console.log(err.);

    })

}
async function main(phone, passwdord) {
    let res = await loginPhone(phone, passwdord)
    if (!res) return
    // console.log(res);
    let res1 = await ssoHomLogin(res.uid)
    // console.log(res1);
    // console.log(res);
    // return
    getLevelRightsList(res, res1)
}
async function getUser() {
    try {
        Cache = JSON.parse(fs.readFileSync('./Cache.json', 'utf8'));
    } catch (error) {
        fs.writeFileSync('./Cache.json', JSON.stringify({}), 'utf8');
        Cache = JSON.parse(fs.readFileSync('./Cache.json', 'utf8'));
    }
    // let arrs=[]
    console.log('获取账号成功', userPhone.length)
    userPhone.map((item, index) => {
        setTimeout(async () => {
            if(runNumber>=15) return
            cookies = await getCookie.initCookie('https://wapact.189.cn:9001/gateway/standExchange/detailNew/exchange')
            main(item.phone, item.password)
        }, 7000 * index);
    })
}
getUser()
// 获取当前时间
function getCurrentTime() {
    const now = new Date();
    return {
        hour: now.getHours(),
        minute: now.getMinutes()
    };
}

// 判断是否是23点59分
function is2359() {
    const { hour, minute } = getCurrentTime();
    return hour === 23 && minute === 59;
}

let day = setInterval(async () => {
    if (is2359()) {
        try {
            cookies = await getCookie.initCookie('https://wapact.189.cn:9001/gateway/standExchange/detailNew/exchange')
            clearInterval(day); // 关闭定时器
            console.log('定时器已关闭');
        } catch (error) {
            console.error('Error initializing cookie:', error);
        }
    }
}, 1000 * 60);

function run(){
    runArr.map(item => {
        getConversionRights(item.userinfo, item.signData, item.item)
    })
}
function waitForSpecificTime(callback) {
    const now = new Date();
    const targetHour = 23;
    const targetMinute = 59;
    const targetSecond = 59;
    const targetMillisecond = 500;

    // 计算今天的23:59:59.500
    let targetTime = new Date(now.getFullYear(), now.getMonth(), now.getDate(), targetHour, targetMinute, targetSecond, targetMillisecond);

    // 如果现在已经是或超过了目标时间，则设置为明天的目标时间
    if (now >= targetTime) {
        targetTime.setDate(targetTime.getDate() + 1);
    }

    // 计算与目标时间的差距（以毫秒为单位）
    const timeDifference = targetTime - now;

    console.log(`Waiting for ${timeDifference} milliseconds until 23:59:59.500`);

    // 使用setTimeout等待直到目标时间到达，然后执行提供的回调函数
    setTimeout(callback, timeDifference);
}
// 调用等待函数并传入你自己的函数作为参数
waitForSpecificTime(run);