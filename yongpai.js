/**
 * 甬派 日常任务赚积分+大转盘+甬音3次抽奖
 * 积分够的情况下，可以抽4次奖。基本0.4以上一天
 * 变量：yp
 * 格式: 账号1#密码1#支付宝账号1#支付宝姓名1&账号2#密码2#付宝账号2#支付宝姓名2&账号3#密码3#支付宝账号3#支付宝姓名3
 * 备注：账号就是手机号。还有一种格式（不推荐） 账号ID#设备DID#支付宝账号1#支付宝姓名1
 * 其他的配置有并发选项
 * 默认并发为false，并发的话，账号多的情况下可以使用
 * 如果甬音想一次性刷满60分钟，建议定时任务在1点以后运行
 * @author: 小赤佬
 */
const jsName = "甬派";
const env_key = 'yp';
const $ = new Env(jsName);
let tokens = $.getdata(env_key) || process.env[env_key] || '';
//是否并发？false不并发，true并发
let ysbingfa=false;
//甬音一次刷时长多久？60s代表1分钟，不怕封号的，可以尝试直接刷满60*60就行了。如果甬音想一次性刷满60分钟，建议定时任务在1点以后运行
let yyRs=60;//会随机+10秒以内的秒数
let yyRsWait=60;//刷时长以后等待多久
!function (n) {
    "use strict";

    function t(n, t) {
        var r = (65535 & n) + (65535 & t);
        return (n >> 16) + (t >> 16) + (r >> 16) << 16 | 65535 & r
    }

    function r(n, t) {
        return n << t | n >>> 32 - t
    }

    function e(n, e, o, u, c, f) {
        return t(r(t(t(e, n), t(u, f)), c), o)
    }

    function o(n, t, r, o, u, c, f) {
        return e(t & r | ~t & o, n, t, u, c, f)
    }

    function u(n, t, r, o, u, c, f) {
        return e(t & o | r & ~o, n, t, u, c, f)
    }

    function c(n, t, r, o, u, c, f) {
        return e(t ^ r ^ o, n, t, u, c, f)
    }

    function f(n, t, r, o, u, c, f) {
        return e(r ^ (t | ~o), n, t, u, c, f)
    }

    function i(n, r) {
        n[r >> 5] |= 128 << r % 32, n[14 + (r + 64 >>> 9 << 4)] = r;
        var e, i, a, d, h, l = 1732584193, g = -271733879, v = -1732584194, m = 271733878;
        for (e = 0; e < n.length; e += 16) i = l, a = g, d = v, h = m, g = f(g = f(g = f(g = f(g = c(g = c(g = c(g = c(g = u(g = u(g = u(g = u(g = o(g = o(g = o(g = o(g, v = o(v, m = o(m, l = o(l, g, v, m, n[e], 7, -680876936), g, v, n[e + 1], 12, -389564586), l, g, n[e + 2], 17, 606105819), m, l, n[e + 3], 22, -1044525330), v = o(v, m = o(m, l = o(l, g, v, m, n[e + 4], 7, -176418897), g, v, n[e + 5], 12, 1200080426), l, g, n[e + 6], 17, -1473231341), m, l, n[e + 7], 22, -45705983), v = o(v, m = o(m, l = o(l, g, v, m, n[e + 8], 7, 1770035416), g, v, n[e + 9], 12, -1958414417), l, g, n[e + 10], 17, -42063), m, l, n[e + 11], 22, -1990404162), v = o(v, m = o(m, l = o(l, g, v, m, n[e + 12], 7, 1804603682), g, v, n[e + 13], 12, -40341101), l, g, n[e + 14], 17, -1502002290), m, l, n[e + 15], 22, 1236535329), v = u(v, m = u(m, l = u(l, g, v, m, n[e + 1], 5, -165796510), g, v, n[e + 6], 9, -1069501632), l, g, n[e + 11], 14, 643717713), m, l, n[e], 20, -373897302), v = u(v, m = u(m, l = u(l, g, v, m, n[e + 5], 5, -701558691), g, v, n[e + 10], 9, 38016083), l, g, n[e + 15], 14, -660478335), m, l, n[e + 4], 20, -405537848), v = u(v, m = u(m, l = u(l, g, v, m, n[e + 9], 5, 568446438), g, v, n[e + 14], 9, -1019803690), l, g, n[e + 3], 14, -187363961), m, l, n[e + 8], 20, 1163531501), v = u(v, m = u(m, l = u(l, g, v, m, n[e + 13], 5, -1444681467), g, v, n[e + 2], 9, -51403784), l, g, n[e + 7], 14, 1735328473), m, l, n[e + 12], 20, -1926607734), v = c(v, m = c(m, l = c(l, g, v, m, n[e + 5], 4, -378558), g, v, n[e + 8], 11, -2022574463), l, g, n[e + 11], 16, 1839030562), m, l, n[e + 14], 23, -35309556), v = c(v, m = c(m, l = c(l, g, v, m, n[e + 1], 4, -1530992060), g, v, n[e + 4], 11, 1272893353), l, g, n[e + 7], 16, -155497632), m, l, n[e + 10], 23, -1094730640), v = c(v, m = c(m, l = c(l, g, v, m, n[e + 13], 4, 681279174), g, v, n[e], 11, -358537222), l, g, n[e + 3], 16, -722521979), m, l, n[e + 6], 23, 76029189), v = c(v, m = c(m, l = c(l, g, v, m, n[e + 9], 4, -640364487), g, v, n[e + 12], 11, -421815835), l, g, n[e + 15], 16, 530742520), m, l, n[e + 2], 23, -995338651), v = f(v, m = f(m, l = f(l, g, v, m, n[e], 6, -198630844), g, v, n[e + 7], 10, 1126891415), l, g, n[e + 14], 15, -1416354905), m, l, n[e + 5], 21, -57434055), v = f(v, m = f(m, l = f(l, g, v, m, n[e + 12], 6, 1700485571), g, v, n[e + 3], 10, -1894986606), l, g, n[e + 10], 15, -1051523), m, l, n[e + 1], 21, -2054922799), v = f(v, m = f(m, l = f(l, g, v, m, n[e + 8], 6, 1873313359), g, v, n[e + 15], 10, -30611744), l, g, n[e + 6], 15, -1560198380), m, l, n[e + 13], 21, 1309151649), v = f(v, m = f(m, l = f(l, g, v, m, n[e + 4], 6, -145523070), g, v, n[e + 11], 10, -1120210379), l, g, n[e + 2], 15, 718787259), m, l, n[e + 9], 21, -343485551), l = t(l, i), g = t(g, a), v = t(v, d), m = t(m, h);
        return [l, g, v, m]
    }

    function a(n) {
        var t, r = "", e = 32 * n.length;
        for (t = 0; t < e; t += 8) r += String.fromCharCode(n[t >> 5] >>> t % 32 & 255);
        return r
    }

    function d(n) {
        var t, r = [];
        for (r[(n.length >> 2) - 1] = void 0, t = 0; t < r.length; t += 1) r[t] = 0;
        var e = 8 * n.length;
        for (t = 0; t < e; t += 8) r[t >> 5] |= (255 & n.charCodeAt(t / 8)) << t % 32;
        return r
    }

    function h(n) {
        return a(i(d(n), 8 * n.length))
    }

    function l(n, t) {
        var r, e, o = d(n), u = [], c = [];
        for (u[15] = c[15] = void 0, o.length > 16 && (o = i(o, 8 * n.length)), r = 0; r < 16; r += 1) u[r] = 909522486 ^ o[r], c[r] = 1549556828 ^ o[r];
        return e = i(u.concat(d(t)), 512 + 8 * t.length), a(i(c.concat(e), 640))
    }

    function g(n) {
        var t, r, e = "";
        for (r = 0; r < n.length; r += 1) t = n.charCodeAt(r), e += "0123456789abcdef".charAt(t >>> 4 & 15) + "0123456789abcdef".charAt(15 & t);
        return e
    }

    function v(n) {
        return unescape(encodeURIComponent(n))
    }

    function m(n) {
        return h(v(n))
    }

    function p(n) {
        return g(m(n))
    }

    function s(n, t) {
        return l(v(n), v(t))
    }

    function C(n, t) {
        return g(s(n, t))
    }

    function A(n, t, r) {
        return t ? r ? s(t, n) : C(t, n) : r ? m(n) : p(n)
    }

    $.md5 = A
}(this);
!(async () => {
    if (tokens.indexOf("&") != -1) {
        tokens = tokens.split('&') || [];
    } else {
        tokens = tokens.split('\n') || [];
    }
    tokens = tokens.filter(token => token != "");
    if (!tokens[0]) {
        $.log(`请设置环境变量添加${jsName}账号`)
        //return;
    }
    $.log(`共获取到${tokens.length}个账号`);
    // await getVersionInfo(env_key);
    let userList = [];
    tokens.forEach(token => {
        let ck = token.split("#");
        userList.push(new UserInfo(ck[0], ck[1], ck[2], ck[3]));
    })
    for (let i = 0; i < userList.length; i++) {
        let userInfo = userList[i];
        if(ysbingfa){
            userInfo.main(i);
        }else{
            await userInfo.main(i);
        }
    }
})()
    .catch((e) => $.logErr(e))
    .finally(() => {
        $.done();
    });


function getVersionInfo(key) {
    return new Promise(async resolve => {
        if (key) {
            let url = `http://api.tyh52.com/api/getJsVersion/get?key=${key}`;
            $.post({
                url: url,
            }, (err, resp, data) => {
                try {
                    if (data) {
                        data = JSON.parse(data);
                        if (data.code === 200) {
                            if (data.data) {
                                $.log(`当前版本 v${data.data.version}`)
                                $.log(`更新日志：\n${data.data.content}`);
                                if (data.data.status != 1) {
                                    throw new Error("脚本已停用")
                                }
                            }
                        } else {
                            $.log(data.message);
                        }
                    }
                } catch (e) {
                    $.log(e)
                } finally {
                    resolve(data);
                }
            });
        } else {
            resolve();
        }
    })
}


function UserInfo(username, password, aliAccount, aliName) {
    let isbreak = false;
    let index = 0;
    let token = '';
    let did = "";
    let info = {};
    let activityId = "276938597392966";
    let autologin = "";
    let wdata = "";
    let key = "";
    let window = {};
    this.main = async function (i) {
        let startTime = new Date().getTime();
        index = i + 1;
        if (username.length > 11) {
            info.userId = username;
            info.deviceId = password;
            info.nickname = username;
            did = password;
        } else {
            await login();
        }
        if (!isbreak) {
            await doTask(index);
            try{await get_id();}catch(e){console.log(e)}
            await get_autologin();
            await get_token();
            await doJoin();
            await doTakePrize();
            //需要先刷甬音的时长
            await duration();
            //需要刷满60分钟
            while (info.yyDuration<60){
                let rs=parseInt((Math.random()*10)+"")+yyRs;
                await hear(rs*1000);
                await duration();
                //延迟1分钟后再上传
                log("延迟1分钟后再提交上传时长")
                await $.wait(yyRsWait*1000)
            }
            //甬音的3个
            let ass=['284364336059191','284981603837881','284981727582016'];
            for(let aid of ass){
                await $.wait(5000)
                activityId=aid;
                await get_autologin();
                await get_token();
                await doJoin();
                await doTakePrize();
            }

        }
        const e = (new Date).getTime(), s = (e - startTime) / 1e3;
        $.log(`账号[${index}] 运行完毕, 结束! 🕛 ${s} 秒`);
    }


    async function duration() {
        let tt = new Date().getTime();
        return new Promise(async resolve => {
            let url = 'https://ypapp.cnnb.com.cn/yongpai-user/api/duiba/hear/duration?userId=' + info.userId + '&time=' + tt;
            $.get({
                url: url,
                headers: {
                    'Host': 'ypapp.cnnb.com.cn',
                    'User-Agent': 'okhttp/3.10.0'
                },
            }, async (err, resp, data) => {
                try {
                    if (data) {
                        data = JSON.parse(data);
                        if (data.code == 0) {
                            info.yyDurationScore = data.data || 0;
                            info.yyDuration = Number(info.yyDurationScore  / 1000 / 60) || 0;
                            log("当前已经听了" + info.yyDuration  +"分钟")
                        } else {
                            log(data.message);
                        }
                    }
                } catch (e) {
                    $.log(e, JSON.stringify(resp))
                } finally {
                    resolve({});
                }
            });
        })
    }

    async function hear(t) {
        let tt = new Date().getTime();
        let duration=info.yyDurationScore+t;
        let sign = $.md5(`duration${duration}timestamp${tt}userId${info.userId}hear1236..!#85862,==OHBICYVuyBikl-=!@#*()+_`);
        return new Promise(async resolve => {
            let url = 'https://ypapp.cnnb.com.cn/yongpai-user/api/duiba/hear';
            $.post({
                url: url,
                headers: {
                    'Host': 'ypapp.cnnb.com.cn',
                    'User-Agent': 'okhttp/3.10.0',
                    'Content-Type': 'application/json; charset=utf-8'
                },
                body: JSON.stringify({
                    "userId": info.userId,
                    "timestamp": tt,
                    "sign": sign,
                    "duration": duration
                })
            }, async (err, resp, data) => {
                try {
                    if (data) {
                        data = JSON.parse(data);
                        if (data.code == 0) {
                            log("上报时长【"+duration/60/1000+"分钟】成功");
                        } else {
                            log("上报时长【"+duration/60/1000+"分钟】失败："+data.message);
                        }
                    }
                } catch (e) {
                    $.log(e, JSON.stringify(resp))
                } finally {
                    resolve({});
                }
            });
        })
    }

    function log(text) {
        $.log(`账号[${info.nickname}]=>` + text)
    }


    function login() {
        let tt = new Date().getTime();
        let encryptdata = 'globalDatetime' + tt + 'username' + username + 'test_123456679890123456';
        let sg = $.md5(encryptdata).toUpperCase();
        return new Promise(async resolve => {
            let url = 'http://ypapp.cnnb.com.cn/yongpai-user/api/login2/local?username=' + username + '&password=' + password + '&deviceId=' + did + '&globalDatetime=' + tt + '&sign=' + sg;
            $.get({
                url: url,
                headers: {
                    'Host': 'ypapp.cnnb.com.cn',
                    'User-Agent': 'okhttp/3.10.0'
                },
            }, async (err, resp, data) => {
                try {
                    if (data) {
                        data = JSON.parse(data);
                        if (data.code == 0) {
                            info = data.data || {};
                            if (info.deviceId) {
                                did = info.deviceId;
                            }
                            $.log(`登录成功：${info.nickname} userId:${info.userId} deviceId:${info.deviceId}`);
                        } else {
                            $.log(data.message);
                            isbreak = true;
                        }
                    }
                } catch (e) {
                    $.log(e, JSON.stringify(resp))
                } finally {
                    resolve({});
                }
            });
        })
    }

    async function doTask(page = 1) {
        let url = `https://ypapp.cnnb.com.cn/yongpai-news/api/v2/news/list?channelId=0&currentPage=${page}&timestamp=${new Date().getTime()}`;
        let res = await get(url);
        for (const item of res.data.content) {
            let newsId = item.newsId;
            url = `https://ypapp.cnnb.com.cn/yongpai-news/api/news/detail?newsId=${newsId}&userId=${info.userId}`;
            res = await get(url);
            res.message == 'OK' ? log(`阅读：[${item.title}]:✅`) : log(`阅读：[${item.title}]:❌ =>${res.message}`)
            await $.wait(200);
            let likeHeaders = {
                "appversion": `10.1.7`,
            }
            url = `https://ypapp.cnnb.com.cn/yongpai-ugc/api/praise/save_news?deviceId=${did}&newsId=${newsId}&userId=${info.userId}`
            res = await get(url, likeHeaders);
            res.message == 'OK' ? log(`点赞：[${item.title}]:✅`) : log(`点赞：[${item.title}]:❌ =>${res.message}`)
            await $.wait(200);
            url = `https://ypapp.cnnb.com.cn/yongpai-ugc/api/forward/news?newsId=${newsId}&source=4&userId=${info.userId}`
            res = await get(url);
            res.message == 'OK' ? log(`分享：[${item.title}]:✅`) : log(`分享：[${item.title}]:❌ =>${res.message}`)
            await $.wait(200);
        }
    }

    async function get_id() {
        let url = `https://ypapp.cnnb.com.cn/yongpai-news/api/v2/news/list?channelId=0&currentPage=1&timestamp=${new Date().getTime()}`;
        let res = await get(url);
        let newsId = (res.data.content.find(c => c.title.includes("大转盘")))?.newsId
        if (!newsId) {
            newsId = (res.data.content.find(c => c.title.includes("转一转")))?.newsId
        }
        if (!newsId) {
            newsId = (res.data.content.find(c => c.title.includes("转转")))?.newsId
        }
        if (!newsId) {
            newsId = (res.data.content.find(c => c.title.includes("红包")))?.newsId
        }
        if (!newsId) {
            newsId = (res.data.content.find(c => c.title.includes("祝福")))?.newsId
        }
        if (newsId) {
            url = `https://ypapp.cnnb.com.cn/yongpai-news/api/news/detail?newsId=${newsId}&userId=${info.userId}`;
            console.log(url)
            res = await get(url);
            let aid = /hdtool\/index\?id=(\d*)&/.exec(res.data.body)[1]
            if (aid) {
                activityId = aid;
            }
        }

        log(`获取到抽奖活动ID为${activityId}`);
    }

    async function get_autologin() {
        let url = `https://ypapp.cnnb.com.cn/yongpai-user/api/duiba/autologin?dbredirect=https%3A//92722.activity-12.m.duiba.com.cn/hdtool/index?id%3D${activityId}%26dbnewopen&userId=${info.userId}`;
        autologin = (await get(url)).data;
    }

    async function get_token() {
        return new Promise(async resolve => {
            $.get({
                url: autologin,
                headers: {
                    "maxRedirects": 0
                },
                followRedirect: false
            }, async (err, resp, data) => {
                try {
                    wdata = resp.headers["set-cookie"].map(item => item.split(";")[0]).join(";");
                    if (wdata) {
                        let url = `https://92722.activity-12.m.duiba.com.cn/hdtool/index?id=${activityId}&dbnewopen&from=login&spm=92722.1.1.1`;
                        let headers = {
                            'authority': '92722.activity-12.m.duiba.com.cn',
                            'accept': 'application/json',
                            'accept-language': 'zh-CN,zh;q=0.9',
                            'cache-control': 'no-cache',
                            'cookie': wdata,
                            'origin': 'https://92722.activity-12.m.duiba.com.cn',
                            'pragma': 'no-cache',
                            'referer': `https://92722.activity-12.m.duiba.com.cn/hdtool/index?id=${activityId}&dbnewopen&from=login&spm=92722.1.1.1`,
                            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                            'sec-ch-ua-mobile': '?1',
                            'sec-ch-ua-platform': '"Android"',
                            'sec-fetch-dest': 'empty',
                            'sec-fetch-mode': 'cors',
                            'sec-fetch-site': 'same-origin',
                            'user-agent': 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36',
                            'x-requested-with': 'XMLHttpRequest'
                        }
                        let res = await get(url, headers);
                        let code = /<script\b[^>]*>\s*var([\s\S]*?)<\/script>/.exec(res)[1];
                        eval(code)
                        key = /var\s+key\s+=\s+'([^']+)';/.exec(getDuibaToken.toString())[1];
                        url = 'https://92722.activity-12.m.duiba.com.cn/hdtool/ctoken/getTokenNew';
                        let data = `timestamp=${new Date().getTime()}&activityId=${activityId}&activityType=hdtool&consumerId=4066466507`;
                        eval((await post(url, data, headers)).token);
                    }
                } catch (e) {
                    log(e)
                } finally {
                    resolve();
                }
            });
        })
    }


    async function doJoin() {
        let url = `https://92722.activity-12.m.duiba.com.cn/hdtool/doJoin?dpm=92722.3.1.0&activityId=${activityId}&_=${new Date().getTime()}`;
        let data = `actId=${activityId}&oaId=${activityId}&activityType=hdtool&consumerId=4066466507&token=${window[key]}`
        let headers = {
            'authority': '92722.activity-12.m.duiba.com.cn',
            'accept': 'application/json',
            'accept-language': 'zh-CN,zh;q=0.9',
            'cache-control': 'no-cache',
            'cookie': wdata,
            'origin': 'https://92722.activity-12.m.duiba.com.cn',
            'pragma': 'no-cache',
            'referer': `https://92722.activity-12.m.duiba.com.cn/hdtool/index?id=${activityId}&dbnewopen&from=login&spm=92722.1.1.1`,
            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36',
            'x-requested-with': 'XMLHttpRequest'
        }
        let res = await post(url, data, headers);
        if (res.success) {
            await doTakePrize();
        } else {
            log(res.message);
        }
    }


    async function doTakePrize() {
        let url = `https://92722.activity-12.m.duiba.com.cn/crecord/getrecord?page=1&_=${new Date().getTime()}`;
        let headers = {
            'Accept': 'application/json',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            "Content-Type": "application/x-www-form-urlencoded",
            'Cookie': wdata,
            'Origin': 'https://92722.activity-12.m.duiba.com.cn',
            'Pragma': 'no-cache',
            'Referer': 'https://92722.activity-12.m.duiba.com.cn/activity/takePrizeNew?recordId=7074365348&dpm=92722.26.0.1&dcm=101.53.217692856808979.0&dbnewopen',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"'
        }
        let res = await get(url, headers);
        //console.log(JSON.stringify(res));
        //let recordIds = res.records.filter(c => !c.quantity).map(c => (JSON.parse(c.emdJson).info));
        let records = res.records.filter(c => !c.quantity);
        for (const record of records) {
            let recordId = JSON.parse(record.emdJson).info;
            url = `https://92722.activity-12.m.duiba.com.cn/activity/takePrizeNew?recordId=${recordId}&dpm=92722.26.0.1&dcm=101.53.217692856808979.0&dbnewopen`;
            headers['Referer'] = 'https://92722.activity-12.m.duiba.com.cn/crecord/record?dbnewopen&dpm=92722.3.2.0';
            res = await get(url, headers);
            let code = /<script\b[^>]*>\s*var([\s\S]*?)<\/script>/.exec(res)[1];
            eval(code)
            key = /var\s+key\s+=\s+'([^']+)';/.exec(getDuibaToken.toString())[1];
            url = 'https://92722.activity-12.m.duiba.com.cn/ctoken/getToken.do';
            res = eval((await post(url, '', headers)).token);
            url = 'https://92722.activity-12.m.duiba.com.cn/activity/doTakePrize';
            let data = `alipay=${encodeURIComponent(aliAccount)}&realname=${encodeURIComponent(aliName)}&recordId=${recordId}&token=${window[key]}`
            res = await post(url, data, headers)
            log(record.orderTypeTitle + "：" + record.title + "支付宝账户：" + aliAccount + ",结果：" + res.message);
        }
    }

    function get(url, headers) {
        return new Promise(async resolve => {
            $.get({
                url: url,
                headers: headers
            }, async (err, resp, data) => {
                try {
                    if (data) {
                        data = JSON.parse(data);
                        resolve(data);
                    }
                } catch (e) {
                    //$.log(e, JSON.stringify(resp))
                } finally {
                    resolve(data);
                }
            });
        })
    }

    function post(url, data, headers) {
        return new Promise(async resolve => {
            $.post({
                url: url,
                body: data,
                headers: headers
            }, async (err, resp, data) => {
                try {
                    if (data) {
                        data = JSON.parse(data);
                        resolve(data);
                    }
                } catch (e) {
                    $.log(e)
                } finally {
                    resolve(data);
                }
            });
        })
    }

    function formatReqParams(params) {
        let keys = Object.keys(params);
        return keys.map(key => key + '=' + params[key]).join("&");
    }
}


function Env(t, e) {
    "undefined" != typeof process && JSON.stringify(process.env).indexOf("GITHUB") > -1 && process.exit(0);

    class s {
        constructor(t) {
            this.env = t
        }

        send(t, e = "GET") {
            t = "string" == typeof t ? {url: t} : t;
            let s = this.get;
            return "POST" === e && (s = this.post), new Promise((e, i) => {
                s.call(this, t, (t, s, r) => {
                    t ? i(t) : e(s)
                })
            })
        }

        get(t) {
            return this.send.call(this.env, t)
        }

        post(t) {
            return this.send.call(this.env, t, "POST")
        }
    }

    return new class {
        constructor(t, e) {
            this.name = t, this.http = new s(this), this.data = null, this.dataFile = "box.dat", this.logs = [], this.isMute = !1, this.isNeedRewrite = !1, this.logSeparator = "\n", this.startTime = (new Date).getTime(), Object.assign(this, e), this.log("", `🔔${this.name}, 开始!`)
        }

        isNode() {
            return "undefined" != typeof module && !!module.exports
        }

        isQuanX() {
            return "undefined" != typeof $task
        }

        isSurge() {
            return "undefined" != typeof $httpClient && "undefined" == typeof $loon
        }

        isLoon() {
            return "undefined" != typeof $loon
        }

        toObj(t, e = null) {
            try {
                return JSON.parse(t)
            } catch {
                return e
            }
        }

        toStr(t, e = null) {
            try {
                return JSON.stringify(t)
            } catch {
                return e
            }
        }

        getjson(t, e) {
            let s = e;
            const i = this.getdata(t);
            if (i) try {
                s = JSON.parse(this.getdata(t))
            } catch {
            }
            return s
        }

        setjson(t, e) {
            try {
                return this.setdata(JSON.stringify(t), e)
            } catch {
                return !1
            }
        }

        getScript(t) {
            return new Promise(e => {
                this.get({url: t}, (t, s, i) => e(i))
            })
        }

        runScript(t, e) {
            return new Promise(s => {
                let i = this.getdata("@chavy_boxjs_userCfgs.httpapi");
                i = i ? i.replace(/\n/g, "").trim() : i;
                let r = this.getdata("@chavy_boxjs_userCfgs.httpapi_timeout");
                r = r ? 1 * r : 20, r = e && e.timeout ? e.timeout : r;
                const [o, h] = i.split("@"), n = {
                    url: `http://${h}/v1/scripting/evaluate`,
                    body: {script_text: t, mock_type: "cron", timeout: r},
                    headers: {"X-Key": o, Accept: "*/*"}
                };
                this.post(n, (t, e, i) => s(i))
            }).catch(t => this.logErr(t))
        }

        loaddata() {
            if (!this.isNode()) return {};
            {
                this.fs = this.fs ? this.fs : require("fs"), this.path = this.path ? this.path : require("path");
                const t = this.path.resolve(this.dataFile), e = this.path.resolve(process.cwd(), this.dataFile),
                    s = this.fs.existsSync(t), i = !s && this.fs.existsSync(e);
                if (!s && !i) return {};
                {
                    const i = s ? t : e;
                    try {
                        return JSON.parse(this.fs.readFileSync(i))
                    } catch (t) {
                        return {}
                    }
                }
            }
        }

        writedata() {
            if (this.isNode()) {
                this.fs = this.fs ? this.fs : require("fs"), this.path = this.path ? this.path : require("path");
                const t = this.path.resolve(this.dataFile), e = this.path.resolve(process.cwd(), this.dataFile),
                    s = this.fs.existsSync(t), i = !s && this.fs.existsSync(e), r = JSON.stringify(this.data);
                s ? this.fs.writeFileSync(t, r) : i ? this.fs.writeFileSync(e, r) : this.fs.writeFileSync(t, r)
            }
        }

        lodash_get(t, e, s) {
            const i = e.replace(/\[(\d+)\]/g, ".$1").split(".");
            let r = t;
            for (const t of i) if (r = Object(r)[t], void 0 === r) return s;
            return r
        }

        lodash_set(t, e, s) {
            return Object(t) !== t ? t : (Array.isArray(e) || (e = e.toString().match(/[^.[\]]+/g) || []), e.slice(0, -1).reduce((t, s, i) => Object(t[s]) === t[s] ? t[s] : t[s] = Math.abs(e[i + 1]) >> 0 == +e[i + 1] ? [] : {}, t)[e[e.length - 1]] = s, t)
        }

        getdata(t) {
            let e = this.getval(t);
            if (/^@/.test(t)) {
                const [, s, i] = /^@(.*?)\.(.*?)$/.exec(t), r = s ? this.getval(s) : "";
                if (r) try {
                    const t = JSON.parse(r);
                    e = t ? this.lodash_get(t, i, "") : e
                } catch (t) {
                    e = ""
                }
            }
            return e
        }

        setdata(t, e) {
            let s = !1;
            if (/^@/.test(e)) {
                const [, i, r] = /^@(.*?)\.(.*?)$/.exec(e), o = this.getval(i),
                    h = i ? "null" === o ? null : o || "{}" : "{}";
                try {
                    const e = JSON.parse(h);
                    this.lodash_set(e, r, t), s = this.setval(JSON.stringify(e), i)
                } catch (e) {
                    const o = {};
                    this.lodash_set(o, r, t), s = this.setval(JSON.stringify(o), i)
                }
            } else s = this.setval(t, e);
            return s
        }

        getval(t) {
            return this.isSurge() || this.isLoon() ? $persistentStore.read(t) : this.isQuanX() ? $prefs.valueForKey(t) : this.isNode() ? (this.data = this.loaddata(), this.data[t]) : this.data && this.data[t] || null
        }

        setval(t, e) {
            return this.isSurge() || this.isLoon() ? $persistentStore.write(t, e) : this.isQuanX() ? $prefs.setValueForKey(t, e) : this.isNode() ? (this.data = this.loaddata(), this.data[e] = t, this.writedata(), !0) : this.data && this.data[e] || null
        }

        initGotEnv(t) {
            this.got = this.got ? this.got : require("got"), this.cktough = this.cktough ? this.cktough : require("tough-cookie"), this.ckjar = this.ckjar ? this.ckjar : new this.cktough.CookieJar, t && (t.headers = t.headers ? t.headers : {}, void 0 === t.headers.Cookie && void 0 === t.cookieJar && (t.cookieJar = this.ckjar))
        }

        get(t, e = (() => {
        })) {
            t.headers && (delete t.headers["Content-Type"], delete t.headers["Content-Length"]), this.isSurge() || this.isLoon() ? (this.isSurge() && this.isNeedRewrite && (t.headers = t.headers || {}, Object.assign(t.headers, {"X-Surge-Skip-Scripting": !1})), $httpClient.get(t, (t, s, i) => {
                !t && s && (s.body = i, s.statusCode = s.status), e(t, s, i)
            })) : this.isQuanX() ? (this.isNeedRewrite && (t.opts = t.opts || {}, Object.assign(t.opts, {hints: !1})), $task.fetch(t).then(t => {
                const {statusCode: s, statusCode: i, headers: r, body: o} = t;
                e(null, {status: s, statusCode: i, headers: r, body: o}, o)
            }, t => e(t))) : this.isNode() && (this.initGotEnv(t), this.got(t).on("redirect", (t, e) => {
                try {
                    if (t.headers["set-cookie"]) {
                        const s = t.headers["set-cookie"].map(this.cktough.Cookie.parse).toString();
                        s && this.ckjar.setCookieSync(s, null), e.cookieJar = this.ckjar
                    }
                } catch (t) {
                    this.logErr(t)
                }
            }).then(t => {
                const {statusCode: s, statusCode: i, headers: r, body: o} = t;
                e(null, {status: s, statusCode: i, headers: r, body: o}, o)
            }, t => {
                const {message: s, response: i} = t;
                e(s, i, i && i.body)
            }))
        }

        post(t, e = (() => {
        })) {
            if (t.body && t.headers && !t.headers["Content-Type"] && (t.headers["Content-Type"] = "application/x-www-form-urlencoded"), t.headers && delete t.headers["Content-Length"], this.isSurge() || this.isLoon()) this.isSurge() && this.isNeedRewrite && (t.headers = t.headers || {}, Object.assign(t.headers, {"X-Surge-Skip-Scripting": !1})), $httpClient.post(t, (t, s, i) => {
                !t && s && (s.body = i, s.statusCode = s.status), e(t, s, i)
            }); else if (this.isQuanX()) t.method = "POST", this.isNeedRewrite && (t.opts = t.opts || {}, Object.assign(t.opts, {hints: !1})), $task.fetch(t).then(t => {
                const {statusCode: s, statusCode: i, headers: r, body: o} = t;
                e(null, {status: s, statusCode: i, headers: r, body: o}, o)
            }, t => e(t)); else if (this.isNode()) {
                this.initGotEnv(t);
                const {url: s, ...i} = t;
                this.got.post(s, i).then(t => {
                    const {statusCode: s, statusCode: i, headers: r, body: o} = t;
                    e(null, {status: s, statusCode: i, headers: r, body: o}, o)
                }, t => {
                    const {message: s, response: i} = t;
                    e(s, i, i && i.body)
                })
            }
        }

        time(t, e = null) {
            const s = e ? new Date(e) : new Date;
            let i = {
                "M+": s.getMonth() + 1,
                "d+": s.getDate(),
                "H+": s.getHours(),
                "m+": s.getMinutes(),
                "s+": s.getSeconds(),
                "q+": Math.floor((s.getMonth() + 3) / 3),
                S: s.getMilliseconds()
            };
            /(y+)/.test(t) && (t = t.replace(RegExp.$1, (s.getFullYear() + "").substr(4 - RegExp.$1.length)));
            for (let e in i) new RegExp("(" + e + ")").test(t) && (t = t.replace(RegExp.$1, 1 == RegExp.$1.length ? i[e] : ("00" + i[e]).substr(("" + i[e]).length)));
            return t
        }

        msg(e = t, s = "", i = "", r) {
            const o = t => {
                if (!t) return t;
                if ("string" == typeof t) return this.isLoon() ? t : this.isQuanX() ? {"open-url": t} : this.isSurge() ? {url: t} : void 0;
                if ("object" == typeof t) {
                    if (this.isLoon()) {
                        let e = t.openUrl || t.url || t["open-url"], s = t.mediaUrl || t["media-url"];
                        return {openUrl: e, mediaUrl: s}
                    }
                    if (this.isQuanX()) {
                        let e = t["open-url"] || t.url || t.openUrl, s = t["media-url"] || t.mediaUrl;
                        return {"open-url": e, "media-url": s}
                    }
                    if (this.isSurge()) {
                        let e = t.url || t.openUrl || t["open-url"];
                        return {url: e}
                    }
                }
            };
            if (this.isMute || (this.isSurge() || this.isLoon() ? $notification.post(e, s, i, o(r)) : this.isQuanX() && $notify(e, s, i, o(r))), !this.isMuteLog) {
                let t = ["", "==============📣系统通知📣=============="];
                t.push(e), s && t.push(s), i && t.push(i), console.log(t.join("\n")), this.logs = this.logs.concat(t)
            }
        }

        log(...t) {
            t.length > 0 && (this.logs = [...this.logs, ...t]), console.log(t.join(this.logSeparator))
        }

        logErr(t, e) {
            const s = !this.isSurge() && !this.isQuanX() && !this.isLoon();
            s ? this.log("", `❗️${this.name}, 错误!`, t.stack) : this.log("", `❗️${this.name}, 错误!`, t)
        }

        wait(t) {
            return new Promise(e => setTimeout(e, t))
        }

        done(t = {}) {
            const e = (new Date).getTime(), s = (e - this.startTime) / 1e3;
            this.log("", `🔔${this.name}, 结束! 🕛 ${s} 秒`), this.log(), (this.isSurge() || this.isQuanX() || this.isLoon()) && $done(t)
        }
    }(t, e)
}



