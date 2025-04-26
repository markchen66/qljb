// 抢个数 填写:1或者2
let qdgs = 2
// 单兑换请求次数 填写:数量
let runNumber = 2
// 场次检测开始执行的时间 填写: HH:MM:SS 例：12:11:59
const targetTimes = ['09:59:59:900', '13:59:59:900'];



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
const moment = require('moment');
// const getCookie = require('./tools/index.js')
const axios = require('axios').default
const fs = require('fs')
const CryptoJS = require('crypto-js');
const JSEncrypt = require('node-jsencrypt');
let pubKey = `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBkLT15ThVgz6/NOl6s8GNPofdWzWbCkWnkaAm7O2LjkM1H7dMvzkiqdxU02jamGRHLX/ZNMCXHnPcW/sDhiFCBN18qFvy8g6VYb9QtroI09e176s+ZCtiv7hbin2cCTj99iUpnEloZm19lwHyo69u5UMiPMpq0/XKBO8lYhN/gwIDAQAB`
const decrypt = new JSEncrypt(); // 创建加密对象实例
decrypt.setPrivateKey(pubKey)
let Cache = {}
let CacheRunJs = 'CacheRunJs.js'
let ruisuConetnt
try {
    ruisuConetnt = fs.readFileSync('ruisu.js', 'utf8');
} catch (error) {
    console.error('Error reading the file:', error);
    return
}
let axiosRequestList = []
let runUser = []
let initialCookie = {}

function initCookie(url = 'https://wapact.189.cn:9001/gateway/standExchange/detailNew/exchange') {
    return new Promise((resolve, reject) => {
        axios.post(url).then(res => {
        }).catch(async (err) => {
            try {
                let htmls = String(err.response.data)
                let cookie = err.response.headers['set-cookie'][0].split(';')[0] + ';'
                let cfarr = null
                if (htmls.split(' content="')[2]) {
                    cfarr = htmls.split(' content="')[2].split('" r=')
                } else {
                    cfarr = htmls.split(' content="')[1].split('" r=')
                }
                let content = 'content="' + cfarr[0] + '"'
                let newContent = ruisuConetnt.replace('content="content_code"', content)
                let code1 = htmls.split('$_ts=window')[1].split('</script><script type="text/javascript"')[0]
                let code1Content = '$_ts=window' + code1
                let Url = htmls.split('$_ts.lcd();</script><script type="text/javascript" charset="utf-8" src="')[1].split('" r=')[0]
                const parsedUrl = new URL(url);
                let downloadUrl = parsedUrl.origin + Url
                // let fileData=(await axios.get(downloadUrl)).data
                fs.access(CacheRunJs, fs.constants.F_OK, async (err) => {
                    let CacheRunData = ''
                    if (err) {
                        // 文件不存在，从远程下载
                        console.log('文件不存在，从远程下载');

                        CacheRunData = await downloadFile(downloadUrl, CacheRunJs);
                    } else {
                        // 文件存在，读取文件内容
                        CacheRunData = fs.readFileSync(CacheRunJs, 'utf8');

                    }
                    newContent = newContent + code1Content + CacheRunData + " return document.cookie.split(';')[0]"
                    const RefreshCookie = new Function(newContent);
                    console.log(cookie, RefreshCookie);
                    resolve({
                        cookie,
                        RefreshCookie
                    })
                });
            } catch (err) {
                initCookie()
            }
        })
    })
}
function downloadFile(url, filePath) {
    return new Promise((resolve, reject) => {
        // 下载文件并写入到本地
        axios({
            method: 'GET',
            url,
        }).then(response => {
            // console.log(response.data);
            try {
                // 写入文件
                fs.writeFileSync(filePath, response.data, 'utf8');

            } catch (error) {
                console.error('写入文件时出错：', error);
            }
            resolve(response.data)
        }).catch(error => {
            console.error('下载文件时出错：', error);
        });
    })
}
// initCookie()

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
function aesEcbEncrypt(plaintext, key) {
    // 确保密钥长度为16/24/32字节
    if (![16, 24, 32].includes(key.length)) {
        throw new Error("密钥长度必须为16/24/32字节");
    }

    // 将密钥转换为WordArray对象
    const keyBytes = CryptoJS.enc.Utf8.parse(key);

    // 对明文进行加密
    const encrypted = CryptoJS.AES.encrypt(plaintext, keyBytes, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    });
    // 返回Base64编码的密文
    return encrypted.toString();
}
async function userLogin(userInfo, instance) {
    try {
        let loginData = {
            "ticket": userInfo.uid,
            "backUrl": "https%3A%2F%2Fwapact.189.cn%3A9001",
            "platformCode": "P201010301",
            "loginType": 2
        };

        // 使用AES-ECB加密登录数据
        const encryptedData = aesEcbEncrypt(JSON.stringify(loginData), 'telecom_wap_2018');

        let options = {
            url: 'https://wapact.189.cn:9001/unified/user/login',
            method: 'POST',
            headers: {
                "User-Agent": "Mozilla/5.0 (Linux; Android 13; 22081212C Build/TKQ1.220829.002) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.97 Mobile Safari/537.36",
                "Content-Type": "application/json;charset=UTF-8",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                Cookie: initialCookie.cookie + initialCookie.RefreshCookie(),
            },
            transformRequest: function transformRequest(data, headers) {
                const hasJSONContentType = () => {
                    const contentType = (headers && headers['Content-Type']) || '';
                    return contentType.indexOf('application/json') > -1;
                };
                if (typeof data === 'string' && hasJSONContentType()) {
                    return data;
                }
            },
            data: encryptedData
        };
        // console.log(userInfo);

        instance(options).then(res => {
            // console.log(res.data.biz.token);
            // console.log(res.headers);
            // console.log(instance.defaults);
            instance.defaults.headers.Authorization = "Bearer " + res.data.biz.token
            // console.log(res.config.headers.Cookie,'----------');
            userInfo.Authorization = "Bearer " + res.data.biz.token
            queryInfo(userInfo, instance)
        }).catch((err) => {
            console.log(err);
        })
    } catch (e) {
        console.log(e);
        
    }
    // return res.data
}
function queryInfo(userInfo, instance) {
    try {
        let options = {
            url: 'https://wapact.189.cn:9001/gateway/golden/api/queryInfo',
            method: 'get',
            headers: {
                Cookie: initialCookie.cookie + initialCookie.RefreshCookie(),
            }
        }
        instance(options).then(res => {
            console.log(String(userInfo.phoneNbr).replace(/^(.{3})(.*)(.{4})$/, "$1****$3"), '金豆余额为', res.data.biz.amountTotal, tool.TIMEstamp1());
            userInfo.amountTotal = res.data.biz.amountTotal
            // console.log(res.config.headers.Cookie,'----------');
            queryBigDataAppGetOrInfo(userInfo, instance)
        }).catch((err) => {
            console.log(err);
        })
    } catch (e) {
        queryInfo(userInfo, instance)
    }
}
async function queryBigDataAppGetOrInfo(userInfo, instance) {
    // console.log('queryBigDataAppGetOrInfo');
    try {
        let options = {
            url: 'https://wapact.189.cn:9001/gateway/golden/goldGoods/getGoodsList?userType=1&page=1&order=3&tabOrder=1',
            method: 'get',
            headers: {
                Cookie: initialCookie.cookie + initialCookie.RefreshCookie(),
            }
        }
        let signData = await ssoHomLogin(userInfo.uid)
        let RecordsInfo = await getCoinMallExchangetRecords(signData, userInfo)
        let dhlb = []
        const currentMonth = new Date().getMonth(); // 获取当前月份，注意JavaScript中月份是从0开始的（0代表1月）
        RecordsInfo.data.map(item => {
            if (item.createdDate && String(item.title).includes('话费')) {
                const createdMonth = new Date(item.createdDate).getMonth();
                if (createdMonth === currentMonth) {
                    dhlb.push(item.title);
                }
            }
        })
        console.log(String(userInfo.phoneNbr).replace(/^(.{3})(.*)(.{4})$/, "$1****$3"), '当前月已兑换', dhlb.join(','), tool.TIMEstamp1());
        instance(options).then(res => {
            let runArr = []
            res.data.biz.ExchangeGoodslist.map((item, index) => {
                // console.log(item.inventoryInfo);
                const now = new Date();
                const currentHour = now.getHours();
                // 检查商品标题是否已经在dhlb数组中，即是否已被兑换
                const isRedeemed = dhlb.includes(item.title);
                if (!isRedeemed) { // 只有当项目没有被兑换时才进一步检查
                    if (currentHour < 13) {
                        if (String(item.title).includes('0.5元') || String(item.title).includes('5元')) {
                            if (Number(item.amount.match(/\d+/)[0]) <= userInfo.amountTotal) {
                                runArr.push(item)
                            }
                        }
                    } else {
                        if (String(item.title).includes('1元') || String(item.title).includes('10元')) {
                            if (Number(item.amount.match(/\d+/)[0]) <= userInfo.amountTotal) {
                                runArr.push(item)
                            }
                        }
                    }
                }
            })
            console.log(String(userInfo.phoneNbr).replace(/^(.{3})(.*)(.{4})$/, "$1****$3"), '可兑换内容', runArr.map(item => item.title), tool.TIMEstamp1());
            runArr.map((item, index) => {
                if (qdgs == 1) {
                    if (index == runArr.length - 1) {
                        runUser.push({ userInfo, item })
                    }
                } else {
                    runUser.push({ userInfo, item })
                }
                // exchange(userInfo, item)

            })
        }).catch((err) => {
            console.log(err);
        })
    } catch (e) {
        queryBigDataAppGetOrInfo(userInfo, instance)
    }
}
// async function exchange(userInfo, item) {
//     try {
//         let arrs = []
//         // let initcookies=await initCookie()
//         for (let i = 0; i < 100; i++) {
//             let options = {
//                 url: 'https://wapact.189.cn:9001/gateway/standExchange/detailNew/exchange',
//                 method: 'POST',
//                 headers: {
//                     "User-Agent": "Mozilla/5.0 (Linux; Android 13; 22081212C Build/TKQ1.220829.002) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.97 Mobile Safari/537.36",
//                     "Referer": "https://wapact.189.cn:9001/JinDouMall/JinDouMall_independentDetails.html",
//                     Cookie: initialCookie.cookie + initialCookie.RefreshCookie(),
//                     Authorization: userInfo.Authorization
//                 },
//                 data: {
//                     "activityId": item.id
//                 }
//             }
//             let reqse = axios(options)
//             arrs.push(reqse)
//         }
//         axios.all(arrs).then(axios.spread((...responses) => {
//             // 所有请求成功后执行的代码
//             console.log(responses[0]);

//             console.log('请求成功次数', responses.length);
//             // 如果你需要根据这些响应做进一步的操作，可以在这里进行处理
//         }))
//             .catch(errors => {
//                 // 捕获任何错误
//                 console.error('Error occurred:', errors);
//             });
//     } catch (e) {
//         console.log('e', '请求兑换报错');
//     }
// }
async function ssoHomLogin(ticket) {
    try {
        let options = {
            url: 'https://wappark.189.cn/jt-sign/ssoHomLogin?ticket=' + ticket,
            method: 'GET',
            headers: {
                Cookie: initialCookie.cookie + initialCookie.RefreshCookie(),
            }
        }
        let res = await axios(options)
        return res.data
    } catch (e) {
        return await ssoHomLogin(ticket)
    }
}
async function getCoinMallExchangetRecords(signData, userInfo) {
    try {
        let data = {
            accId: signData.accId,
            page: 0,
            size: 100
        };
        let options = {
            url: 'https://wappark.189.cn/jt-sign/paradise/getCoinMallExchangetRecords',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json;charset=utf-8',
                sign: signData.sign,
                Cookie: initialCookie.cookie + initialCookie.RefreshCookie(),
            },
            data: {
                para: tool.encrypt_rsa_hex(data)
            }
        }
        let res = await axios(options)
        return res.data
    } catch (e) {
        return await getCoinMallExchangetRecords(signData, userInfo)
    }
}
async function main(phone, passwdord) {
    // console.log(CookieJar.wrapper);
    // 配置 axios 实例来使用 cookie 罐子
    let instance = axios.create({
        headers: {
            "User-Agent": "Mozilla/5.0 (Linux; Android 13; 22081212C Build/TKQ1.220829.002) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.97 Mobile Safari/537.36",
            "Referer": "https://wapact.189.cn:9001/JinDouMall/JinDouMall_independentDetails.html",
        }
    });
    // 请求拦截器
    instance.interceptors.request.use(async config => {
        config.headers.Cookie = initialCookie.cookie + initialCookie.RefreshCookie()
        return config;
    }, error => {
        return Promise.reject(error);
    });
    // 响应拦截器
    instance.interceptors.response.use(response => {
        // 更新 cookie 罐子中的 cookies
        return response;
    }, error => {
        return Promise.reject(error);
    });
    let res = await loginPhone(phone, passwdord)
    if (!res) return
    userLogin(res, instance)
    // console.log(res2);
}

async function getUser() {
    try {
        Cache = JSON.parse(fs.readFileSync('./Cache.json', 'utf8'));
    } catch (error) {
        fs.writeFileSync('./Cache.json', JSON.stringify({}), 'utf8');
        Cache = JSON.parse(fs.readFileSync('./Cache.json', 'utf8'));
    }
    initialCookie = await initCookie()
    console.log('获取账号成功', userPhone.length, tool.TIMEstamp1())
    userPhone.map(item => {
        main(item.phone, item.password)
    })
}
getUser()
let runAxiosList = []
setTimeout(() => {
    console.time('time');
    runUser.map(userItem => {
        console.log(String(userItem.userInfo.phoneNbr).replace(/^(.{3})(.*)(.{4})$/, "$1****$3"), `加入抢兑 ${userItem.item.title}`);
        for (let i = 0; i < runNumber; i++) {
            let options = {
                url: 'https://wapact.189.cn:9001/gateway/standExchange/detailNew/exchange',
                method: 'POST',
                headers: {
                    "User-Agent": "Mozilla/5.0 (Linux; Android 13; 22081212C Build/TKQ1.220829.002) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.97 Mobile Safari/537.36",
                    "Referer": "https://wapact.189.cn:9001/JinDouMall/JinDouMall_independentDetails.html",
                    Cookie: initialCookie.cookie + initialCookie.RefreshCookie(),
                    Authorization: userItem.userInfo.Authorization
                },
                data: {
                    "activityId": userItem.item.id
                }
            }
            // let reqse = axios(options)
            runAxiosList.push(() => axios(options));
        }
    })
    console.timeEnd('time');
    console.log('抢兑列表个数', runUser.length);
    console.log('抢兑请求个数', runAxiosList.length);
    console.log('抢兑列表加载成功，等待抢兑', tool.TIMEstamp1());
}, 55000)

let executed = new Set();
// function executeFunction(targetTime) {
//     console.log(`当前时间：${targetTime}，执行抢兑函数`,tool.TIMEstamp1());
//     console.time('time');

//     // 在这里执行你的函数代码
// }
// let jcInterval=null
// // 检查当前时间是否为目标时间点之一
// function checkTime() {
//     const now = moment().format('HH:mm:ss');
//     targetTimes.forEach(targetTime => {
//         if (now === targetTime && !executed.has(targetTime)) {
//             executeFunction(targetTime);
//             executed.add(targetTime); // 标记该时间点已执行
//             clearInterval(jcInterval);
//         }else{
//             // console.log(`不是目标时间点,等待中`);
//         }
//     });
// }
// 每秒检查一次当前时间
function waitForSpecificTime(callback) {

    const now = new Date();
    let targetHour = 23;
    let targetMinute = 59;
    let targetSecond = 59;
    let targetMillisecond = 950;
    if (now.getHours() <= 12) {
        targetHour = targetTimes[0].split(':')[0]
        targetMinute = targetTimes[0].split(':')[1]
        targetSecond = targetTimes[0].split(':')[2]
        targetMillisecond = targetTimes[0].split(':')[3]
    } else {
        targetHour = targetTimes[1].split(':')[0]
        targetMinute = targetTimes[1].split(':')[1]
        targetSecond = targetTimes[1].split(':')[2]
        targetMillisecond = targetTimes[1].split(':')[3]
    }
    // 计算今天的23:59:59.500
    let targetTime = new Date(now.getFullYear(), now.getMonth(), now.getDate(), targetHour, targetMinute, targetSecond, targetMillisecond);

    // 如果现在已经是或超过了目标时间，则设置为明天的目标时间
    if (now >= targetTime) {
        targetTime.setDate(targetTime.getDate() + 1);
    }

    // 计算与目标时间的差距（以毫秒为单位）
    const timeDifference = targetTime - now;

    console.log(`Waiting for ${timeDifference} milliseconds until ${targetHour}:${targetMinute}:${targetSecond}.${targetMillisecond}`);

    // 使用setTimeout等待直到目标时间到达，然后执行提供的回调函数
    setTimeout(callback, timeDifference);

}
// 调用等待函数并传入你自己的函数作为参数
function run() {
    Promise.allSettled(runAxiosList.map(fn => fn()))
        .then(results => {
            let qdcggs = 0;
            let errNumber = 0
            let successNumber = 0
            results.forEach((result, index) => {
                if (result.status === 'fulfilled') {
                    console.log(`Request ${index + 1} succeeded with data:`, result.value.data, tool.TIMEstamp1());
                    if (result.value.data?.biz?.resultCode == '0') {
                        qdcggs++
                    }
                    if (result.value.data.code == 999999) {
                        errNumber++
                    } else if (result.value.data.code == 0) {
                        successNumber++
                    }
                } else {
                    console.error(`第 ${index + 1} 个请求发生报错`, tool.TIMEstamp1());
                }
            });
            console.log('请求返回成功个数：', successNumber, tool.TIMEstamp1());
            console.log('请求系统错误个数：', errNumber, tool.TIMEstamp1());
            console.log('抢兑成功个数：', qdcggs, tool.TIMEstamp1());
            console.timeEnd('time');
            process.exit()
        })
        .catch(error => {
            console.error("处理结果时出错:", error);
            process.exit()
        });
}
waitForSpecificTime(run);