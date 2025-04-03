/**
 * 变量名：CLOUD_189
 * 值：手机号#密码，多账号，直接换行或者重新弄一个变量，格式一样。 
 *  需要安装的依赖 cloud189-sdk
 * 定时规则
 * 每天早上8点，跟晚上8点签到。
 * cron: 0 0 8,20 * * *
 */
const { CloudClient, FileTokenStore } = require('cloud189-sdk');
const fs = require('fs');

const mask = (s, start, end) => s.split('').fill('*', start, end).join('');

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const logMessage = message => {
  console.log(message);
  return message;
};

const executeTask = async cloudClient => {
  const result = [];
  const signResult = await cloudClient.userSign();
  result.push(`${signResult.isSign ? '已经签到过了，' : ''}签到获得${signResult.netdiskBonus}M空间`);
  return result;
};

const executeFamilyTask = async cloudClient => {
  if (typeof cloudClient.getFamilyList !== 'function') {
    throw new Error('CloudClient 对象没有 getFamilyList 方法');
  }
  const { familyInfoResp } = await cloudClient.getFamilyList();
  const result = [];
  if (familyInfoResp) {
    for (const { familyId } of familyInfoResp) {
      if (typeof cloudClient.familyUserSign !== 'function') {
        throw new Error('CloudClient 对象没有 familyUserSign 方法');
      }
      const res = await cloudClient.familyUserSign(familyId);
      result.push(`家庭任务${res.signStatus ? '已经签到过了，' : ''}签到获得${res.bonusSpace}M空间`);
    }
  }
  return result;
};

const getStorageInfo = async cloudClient => {
  const { cloudCapacityInfo, familyCapacityInfo } = await cloudClient.getUserSizeInfo();
  return `个人：${(cloudCapacityInfo.totalSize / 1024 ** 3).toFixed(2)}G, 家庭：${(familyCapacityInfo.totalSize / 1024 ** 3).toFixed(2)}G`;
};

const createCloudClient = (username, password) => {
  return new CloudClient({ username, password });
};

async function main(userName, password) {
  if (!userName || !password) return;
  const userNameInfo = mask(userName, 3, 7);
  const message = [];
  try {
    message.push(logMessage(`账户 ${userNameInfo}开始执行`));
    const cloudClient = createCloudClient(userName, password);
    const taskResult = await executeTask(cloudClient);
    taskResult.forEach(logMessage);
    const familyTaskResult = await executeFamilyTask(cloudClient);
    familyTaskResult.forEach(logMessage);
    logMessage('任务执行完毕');
    const storageInfo = await getStorageInfo(cloudClient);
    message.push(storageInfo);
    logMessage(storageInfo);
  } catch (e) {
    console.error(e);
    if (e.code === 'ECONNRESET') throw e;
  } finally {
    message.push(logMessage(`账户 ${userNameInfo}执行完毕`));
  }
  return message;
}

(async () => {
  try {
    const c189s = process.env.CLOUD_189;
    if (!c189s) {
      console.log('未获取到天翼云盘 CLOUD_189');
      return;
    }
    const accounts = c189s.split('\n');
    const allMessages = [];
    for (const account of accounts) {
      const [userName, password] = account.split('#');
      const messages = await main(userName, password);
      allMessages.push(...messages);
    }
    console.log(allMessages.join('\n'));
    fs.writeFileSync('天翼云盘签到日志.txt', allMessages.join('\n'));
  } catch (error) {
    console.error('执行过程中发生错误:', error);
  }
})();