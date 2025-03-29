/*
[task_local]
# cron: 0 15 6 * * ?
*/

const axios = require('axios');

(async () => {
  let message = [];

  // 封装 GET 请求（基于 Promise）
  function httpGet(url, params, headers) {
    return new Promise((resolve, reject) => {
      // 拼接 query string
      if (params) {
        const query = Object.keys(params)
          .map(key => `${encodeURIComponent(key)}=${encodeURIComponent(params[key])}`)
          .join("&");
        url = url + "?" + query;
      }
      const options = {
        url: url,
        headers: headers
      };
      axios.get(url, { headers: headers })
        .then(response => {
          resolve(response.data);
        })
        .catch(error => {
          reject(error);
        });
    });
  }

  // Base64 编码（注意：btoa仅支持 ASCII）
  function b64encode(data) {
    return btoa(data);
  }

  // 生成随机字符串
  function getNonceStr(length = 32) {
    const source = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < length; i++) {
      result += source.charAt(Math.floor(Math.random() * source.length));
    }
    return result;
  }

  class XiaoHeiHe {
    constructor(user) {
      this.cookie = user.cookie;
      this.imei = user.imei;
      this.heybox_id = user.heybox_id;
      this.version = user.version;
      this.n = getNonceStr();
      this.t = Math.floor(Date.now() / 1000);
    }

    head() {
      return {
        "User-Agent": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.118 Safari/537.36 ApiMaxJia/1.0",
        "cookie": this.cookie,
        "Referer": "http://api.maxjia.com/"
      };
    }

    async hkey(key) {
      const params = {
        urlpath: key,
        nonce: this.n,
        timestamp: this.t
      };
      try {
        let res = await httpGet("http://146.56.234.178:8077/encode", params, {});
        return res;
      } catch (error) {
        console.log("hkey error:", error);
        return "";
      }
    }

    async params(key) {
      let hkeyVal = await this.hkey(key);
      return {
        _time: this.t,
        hkey: hkeyVal,
        nonce: this.n,
        imei: this.imei,
        heybox_id: this.heybox_id,
        version: this.version,
        divice_info: "M2012K11AC",
        x_app: "heybox",
        channel: "heybox_xiaomi",
        os_version: "13",
        os_type: "Android"
      };
    }

    async getpost() {
      try {
        let paramsNews = await this.params("/bbs/app/feeds/news");
        let data = await httpGet("https://api.xiaoheihe.cn/bbs/app/feeds/news", paramsNews, this.head());
        let json = JSON.parse(data);
        let linkid = json.result.links[1].linkid;

        // 分享请求
        const click = async (link_id) => {
          let paramsClick = await this.params("/bbs/app/link/share/click");
          paramsClick.h_src = b64encode('news_feeds_-1');
          paramsClick.link_id = link_id;
          paramsClick.index = 1;
          let res = await httpGet("https://api.xiaoheihe.cn/bbs/app/link/share/click", paramsClick, this.head());
          let resJson = JSON.parse(res);
          if (resJson.status === "ok") {
            console.log("分享成功");
            message.push("😊分享成功");
            return "分享成功";
          } else {
            console.log("分享失败");
            message.push("😢分享失败");
            return "分享失败";
          }
        };

        // 检查分享
        const check = async () => {
          let paramsCheck = await this.params("/task/shared/");
          paramsCheck.h_src = b64encode('news_feeds_-1');
          paramsCheck.shared_type = 'normal';
          let res = await httpGet("https://api.xiaoheihe.cn/task/shared/", paramsCheck, this.head());
          let resJson = JSON.parse(res);
          if (resJson.status === "ok") {
            console.log("检查分享成功");
            return "检查分享成功";
          } else {
            console.log("检查分享失败");
            return "检查分享失败";
          }
        };

        let clickRes = await click(linkid);
        let checkRes = await check();
        return clickRes + "\n" + checkRes;
      } catch (error) {
        console.log("getpost error:", error);
        return "getpost error: " + error;
      }
    }

    async heibox_sgin() {
      if (!this.cookie) {
        console.log("小黑盒:没有配置cookie");
        message.push("😢小黑盒:没有配置cookie");
        return "没有配置cookie";
      }
      try {
        let paramsSign = await this.params("/task/sign/");
        let data = await httpGet("https://api.xiaoheihe.cn/task/sign/", paramsSign, this.head());
        let resJson = JSON.parse(data);
        let fx = await this.getpost();
        if (resJson.status === "ok") {
          if (!resJson.msg) {
            console.log("小黑盒:已经签到过了");
            message.push(`${this.heybox_id}, 小黑盒:已经签到过了`);
            return fx + "\n已经签到过了";
          } else {
            console.log("小黑盒:" + resJson.msg);
            message.push(`${this.heybox_id}, 小黑盒: ${resJson.msg}`);
            return fx + "\n" + resJson.msg;
          }
        } else {
          console.log("小黑盒:签到失败 - " + resJson.msg);
          message.push("小黑盒:签到失败 - " + resJson.msg);
          return fx + "\n签到失败 - " + resJson.msg;
        }
      } catch (error) {
        console.log("小黑盒:出现了错误,错误信息" + error);
        message.push("小黑盒:出现了错误,错误信息" + error);
        return "出现了错误,错误信息" + error;
      }
    }
  }

  // 配置数组，请根据实际情况修改各项参数
  let config = [
    { switch: true, cookie: "用户1cookie", imei: "用户1imei", heybox_id: "用户1heybox_id", version: "1.3.229" },
    // { switch: true, cookie: "用户2cookie", imei: "用户2imei", heybox_id: "用户2heybox_id", version: "1.3.229" },
  ];

  // 主流程
  for (let i = 0; i < config.length; i++) {
    let user = config[i];
    if (!user.switch) {
      console.log(`😢第${i + 1}个 switch值为False, 不进行任务`);
      message.push(`😢第${i + 1}个 switch值为False, 不进行任务`);
      continue;
    }
    let xiaohei = new XiaoHeiHe(user);
    await xiaohei.heibox_sgin();
  }

  // 发送通知
  console.log("小黑盒:\n" + message.join("\n"));
})();
