import yaml, requests, json, socket, time, speedtest, os, re, subprocess, threading, queue, sqlite3

def setPaths():
    global path, en2zhPath, clashPath
    path = os.path.abspath('.')
    path = r'C:\Users\zjsxp\Desktop\proxypool'
    en2zhPath = os.path.join(path, 'en2zh.yaml')
    clashPath = os.path.join(path, 'clash.exe')

def initialDB():
    global dbConn, c
    dbConn = sqlite3.connect(os.path.join(path, 'proxies.db'))
    c = dbConn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS   `ss`
           (`id` INTEGER  PRIMARY KEY  AUTOINCREMENT,
           `proxy-type`       CHAR(10) default 'ss',
           `server`           TEXT     NOT NULL,
           `port`             INT      NOT NULL,
           `password`         TEXT     NOT NULL,
           `cipher`           TEXT     NOT NULL,
           `plugin`           TEXT,
           `plugin-opts`      TEXT     );''')
    c.execute('''CREATE TABLE IF NOT EXISTS   `ssr`
           (`id` INTEGER  PRIMARY KEY  AUTOINCREMENT,
           `proxy-type`       CHAR(10) default 'ssr',
           `server`           TEXT     NOT NULL,
           `port`             INT      NOT NULL,
           `password`         TEXT     NOT NULL,
           `cipher`           TEXT     NOT NULL,
           `protocol`         TEXT,
           `protocol-param`   TEXT,
           `obfs`             TEXT,
           `obfs-param`       TEXT     );''')
    c.execute('''CREATE TABLE IF NOT EXISTS   `trojan`
           (`id` INTEGER  PRIMARY KEY  AUTOINCREMENT,
           `proxy-type`       CHAR(10) default 'trojan',
           `server`           TEXT     NOT NULL,
           `port`             INT      NOT NULL,
           `password`         TEXT     NOT NULL,
           `sni`              TEXT,
           `skip-cert-verify` INT(1)     DEFAULT False     );''')
    c.execute('''CREATE TABLE IF NOT EXISTS   `vmess`
           (`id` INTEGER  PRIMARY KEY  AUTOINCREMENT,
           `proxy-type`       CHAR(10) default 'vmess',
           `server`           TEXT     NOT NULL,
           `port`             INT      NOT NULL,
           `uuid`             TEXT     NOT NULL,
           `alterId`          INT      NOT NULL,
           `cipher`           TEXT     NOT NULL,
           `tls`              INT(1)   ,
           `skip-cert-verify` INT(1)   DEFAULT 0,
           `network`          TEXT     ,
           `http-opts`        TEXT     ,
           `h2-opts`          TEXT     ,
           `servername`       TEXT     ,
           `ws-path`          TEXT     ,
           `ws-headers`       TEXT     );''')
    c.execute('''CREATE TABLE IF NOT EXISTS   `networkEnvironment`
           (`id` INTEGER  PRIMARY KEY  AUTOINCREMENT,
           `isp`            TEXT     NOT NULL,
           `location`       TEXT     NOT NULL,
           `download`       INT      NOT NULL default 100,
           `upload`         INT      );''')
    c.execute('''CREATE TABLE IF NOT EXISTS   `tcping`
           (`id` INTEGER  PRIMARY KEY  AUTOINCREMENT,
           `proxy-type`      CHAR(10) NOT NULL,
           `proxy-id`        INT      NOT NULL,
           `env-id`          INT      NOT NULL,
           `success`        INT(1)     NOT NULL,
           `delay`          INT      NOT NULL,
           `time`           TIMESTAMP default (datetime('now', 'localtime')),
           FOREIGN KEY (`env-id`)
           REFERENCES networkEnvironment (`id`)     );''')
    c.execute('''CREATE TABLE IF NOT EXISTS   `delay`
           (`id` INTEGER  PRIMARY KEY  AUTOINCREMENT,
           `proxy-type`      CHAR(10) NOT NULL,
           `proxy-id`        INT      NOT NULL,
           `env-id`          INT      NOT NULL,
           `success`        INT(1)     NOT NULL,
           `delay`          INT      NOT NULL,
           `url`            TEXT     default 'http://www.gstatic.com/generate_204',
           `time`           TIMESTAMP default (datetime('now', 'localtime')),
           FOREIGN KEY (`env-id`)
           REFERENCES networkEnvironment (`id`)     );''')
    c.execute('''CREATE TABLE IF NOT EXISTS   `ip`
           (`id` INTEGER  PRIMARY KEY  AUTOINCREMENT,
           `proxy-type`      CHAR(10)  NOT NULL,
           `proxy-id`        INT       NOT NULL,
           `env-id`          INT       NOT NULL,
           `ip`              TEXT      NOT NULL,
           `ip-version`      INT(1)    NOT NULL,
           `ip-type`         INT(1)    NOT NULL,
           `time`            TIMESTAMP default (datetime('now', 'localtime')),
           FOREIGN KEY (`env-id`)
           REFERENCES networkEnvironment (`id`)     );''')
    c.execute('''CREATE TABLE IF NOT EXISTS   `ip-info`
           (`id` INTEGER  PRIMARY KEY  AUTOINCREMENT,
           `ip`             TEXT       NOT NULL,
           `ip-version`     INT(1)     NOT NULL,
           `country-code`   TEXT,
           `province`       TEXT,
           `city`           TEXT,
           `isp`            TEXT,
           `latitude`       TEXT,
           `longitude`      TEXT,
           `source`         TEXT,
           `time`           TIMESTAMP  default (datetime('now', 'localtime'))     );''')
    c.execute('''CREATE TABLE IF NOT EXISTS   `speedtest`
           (`id` INTEGER  PRIMARY KEY  AUTOINCREMENT,
           `ip`                TEXT     NOT NULL,
           `env-id`            INT      NOT NULL,
           `download`          REAL     NOT NULL,
           `upload`            REAL,
           `ping`              REAL,
           `share-pic`         TEXT,
           `download-tracffic` REAL,
           `upload-tracffic`   REAL,
           `source`            TEXT     NOT NULL,
           `time`              TIMESTAMP default (datetime('now', 'localtime')),
           FOREIGN KEY (`env-id`)
           REFERENCES networkEnvironment (`id`)       );''')
    c.execute('''CREATE TABLE IF NOT EXISTS   `region`
           (`id` INTEGER  PRIMARY KEY  AUTOINCREMENT,
           `ip`             TEXT       NOT NULL,
           `ip-version`     INT(1)     NOT NULL,
           `result`         TEXT       NOT NULL,
           `country-code`   TEXT,
           `site`           TEXT       NOT NULL,
           `time`           TIMESTAMP  default (datetime('now', 'localtime'))     );''')

def importProxies(data): #Import proxies to DB, return existCount, insertCount
    global dbConn, c
    config = yaml.safe_load(data)
    existCount, insertCount = 0, 0
    for proxyDict in config['proxies']:
        del proxyDict['name']
        type = proxyDict['type']
        del proxyDict['type']
        if 'country' in proxyDict: del proxyDict['country']
        if 'udp' in proxyDict: del proxyDict['udp']
        if 'protocol_param' in proxyDict: 
            proxyDict['protocol-param'] = proxyDict['protocol_param']
            del proxyDict['protocol_param']
        if 'obfs_param' in proxyDict: 
            proxyDict['obfs-param'] = proxyDict['obfs_param']
            del proxyDict['obfs_param']
        list = []
        for key in proxyDict:
            if proxyDict[key] in [True, False]:
                list.append('`%s`='%key + '1' if proxyDict[key] else '0')
            else:
                list.append('`%s`='%key + "'" + str(proxyDict[key]).replace("'", "''") + "'")
        sql = "select * from `%s` where " % type + ' and '.join(list)
        list = c.execute(sql).fetchall()
        if len(list) > 0: 
            existCount += 1
            continue
        #print(sql)
        sql = insertRecordSql(type, proxyDict)
        #print(sql)
        insertCount += 1
        c.execute(sql)
    dbConn.commit()
    return existCount, insertCount

def portIsOpen(ip,port):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        s.connect((ip,int(port)))
        s.shutdown(2)
        #print '%d is open' % port
        return True
    except:
        #print '%d is down' % port
        return False

def initClash():
    global attributes, clashPath, configPath, proxyListenPort, proxySetAddress, externalControllerListenPort, externalController, clashPopenObj
    proxyListenPort = 7890
    while (portIsOpen('127.0.0.1', proxyListenPort)):
       proxyListenPort += 1
    proxySetAddress = "http://127.0.0.1:" + str(proxyListenPort)

    externalControllerListenPort = 9090
    while (portIsOpen('127.0.0.1', externalControllerListenPort)):
       externalControllerListenPort += 1
    externalController = "http://127.0.0.1:" + str(externalControllerListenPort)
    
    #Dump config file
    result = {'mixed-port': proxyListenPort, 'external-controller': '127.0.0.1:' + str(externalControllerListenPort), 
    'secret': '', 'ipv6': True, 'mode': 'Global', 'allow-lan': True, 'log-level': 'info', 'proxies': []}
    for protocolType in attributes:
        cur = c.execute("select * from `" + protocolType +'`')
        result['proxies'] += dumpProxies(cur.fetchall())['proxies']
    configPath = os.path.join(path, str(int(time.time())) + '.yaml')
    yaml.safe_dump(result, open(configPath, 'w', encoding='UTF-8'), allow_unicode=True)
    
    #Create clash process
    clashPopenObj = subprocess.Popen(clashPath + ' -f ' + configPath)

def dumpProxies(Proxies, name = '{1} {0}', nameParams = None): #nameParams 5列
    import ast
    global attributes
    result = {'proxies': []}
    for k, row in enumerate(Proxies):
        dict = {}
        for i, attribute in enumerate(attributes[row[1]]):
            if i == 0: 
                if nameParams == None:
                    dict['name'] = name.format(row[0], row[1])
                else:
                    dict['name'] = name.format(row[0], row[1], nameParams[k][0], nameParams[k][1], nameParams[k][2], nameParams[k][3], nameParams[k][4])
                continue
            if row[i] != None:
                if attribute in ['plugin-opts', 'ws-headers', 'http-opts', 'h2-opts']:
                    dict[attribute] = ast.literal_eval(row[i])
                elif attribute in ['tls', 'skip-cert-verify']:
                    dict[attribute] = True if row[i] == 1 else False
                else:
                    dict[attribute] = row[i]
        result['proxies'].append(dict)
    return result

def setProxiesEnv(proxySetAddress):
    global proxySet, proxySetNone 
    proxySet = {"http": proxySetAddress, "https": proxySetAddress}
    proxySetNone = {"http": "", "https": ""}
    os.environ['http_proxy'] = proxySetAddress
    os.environ['https_proxy'] = proxySetAddress

def initCountryNameDict(): 
    global code2name, en2zhPath
    import pycountry
    code2name = {}
    en2zh = yaml.safe_load(open(en2zhPath, 'r', encoding='UTF-8'))
    #print(en2zh)
    for country in pycountry.countries:
        code2name[country.alpha_2] = en2zh[country.name] if country.name in en2zh else country.name

def clash_getProxiesInfo(name=''):
    r = requests.get(externalController + '/proxies/' + name, proxies=proxySetNone)
    return r.json() #return all, now, udp, etc.

def clash_getProxiesDelay(name, timeout = 2000, url = 'http://www.gstatic.com/generate_204'): #return json delay or message
    r = requests.get(externalController + '/proxies/' + name + '/delay', params={'timeout':timeout,'url':url}, proxies=proxySetNone)
    return r.json() #return delay or message

def clash_switchProxy(name): 
    r = requests.put(externalController + '/proxies/' + 'GLOBAL', data=json.dumps({'name':name}), proxies=proxySetNone)
    return r.status_code == 204 #return 204: No Content

def getIPIPdotNet(times=3):
    try:
        errorTimes = 0
        for i in range(times):
            r = requests.get("https://api.myip.la/cn?json", proxies=proxySet)
            #{"ip":"141.164.35.170","location":{"city":"","country_code":"KR","country_name":"韩国","latitude":"37.553674","longitude":"126.991138","province":"首尔"}}
            if r.status_code == 200:
                break
            else:
                errorTimes += 1
        return r.json() if errorTimes<times else "Failed"
    except Exception:
        return "Failed"

def getIP(version, times=3):
    try:
        errorTimes = 0
        for i in range(times):
            r = requests.get('http://v%d.ip.zxinc.org/info.php?type=json'%(version), proxies=proxySet)
            #{"code":0,"data":{"myip":"112.14.241.145","location":"浙江省绍兴市 移动","country":"浙江省绍兴市","local":"移动","ver4":"纯真网络 2021年08月18日IP数据","ver6":" ZX公网IPv6库\t20210726版","count4":530725,"count6":178724}}
            if r.status_code == 200:
                break
            else:
                errorTimes += 1
        return r.json()['data'] if errorTimes<times else "Failed"
    except Exception:
        return "Failed"

def tcping(host, port=80, timeout=1):
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.settimeout(timeout)
    try:
        t1 = time.time()
        sk.connect((socket.gethostbyname(host), port))
        t2 = time.time()
        sk.close()
        return True, int(round((t2-t1)*1000))
    except Exception:
        sk.close()
        return False, timeout*1000

def getIPInfo(ip): #纯真网络
    appcode = 'b6d2e6063aec445293258e531ae4137d'
    header = {'Authorization':'APPCODE ' + appcode}
    r = requests.get('http://cz88.rtbasia.com/search', params={'ip':ip}, proxies=proxySetNone,headers=header)
    return r.json()

def multithread(f, number, work): #f(data, &c)
    exitFlag = 0
    
    class myThread (threading.Thread):
        def __init__(self, threadID, name, q):
            threading.Thread.__init__(self)
            self.threadID = threadID
            self.name = name
            self.q = q
        def run(self):
            process_data(self.name, self.q)
    def process_data(threadName, q):
        global path
        dbConn = sqlite3.connect(os.path.join(path, 'proxies.db'))
        
        while not exitFlag:
            queueLock.acquire()
            if not workQueue.empty():
                data = q.get() #取得任务
                queueLock.release()
                c = dbConn.cursor()
                f(data, c)
                c.close()
                dbConn.commit()
            else:
                queueLock.release()
            time.sleep(1)
        dbConn.close()
    
    queueLock = threading.Lock()
    workQueue = queue.Queue(0)
    threads = []

    # 创建新线程
    for threadID in range(1, number):
        thread = myThread(threadID, "Thread-{}".format(threadID), workQueue)
        thread.start()
        threads.append(thread)
        threadID += 1

    # 填充队列
    queueLock.acquire()
    for data in work:
        workQueue.put(data)
    queueLock.release()

    # 等待队列清空
    while not workQueue.empty():
        pass

    # 通知线程是时候退出
    exitFlag = 1

    # 等待所有线程完成
    for t in threads:
        t.join()

def testTcping(proxy, c):
    success, delay = tcping(proxy[2], proxy[3])
    print('Tcping {} {} ({}:{}) {}, {}ms'.format(proxy[1], proxy[0], proxy[2], proxy[3], success, delay))
    sql = insertRecordSql('tcping', {'proxy-type': proxy[1], 'proxy-id': proxy[0], 'env-id': envId, 'success': 1 if success else 0, 'delay': delay})
    #print(sql)
    c.execute(sql)

def testDelay(proxy, c, timeout = 2000, url = 'http://www.gstatic.com/generate_204'):
    result = clash_getProxiesDelay(proxy[1]+' '+str(proxy[0]), timeout, url)
    if 'message' in result:
        success = 0
        delay = timeout
    else:
        success = 1
        delay = result['delay']
    print('delay test {} {} ({}:{}) {}, {}ms'.format(proxy[1], proxy[0], proxy[2], proxy[3], success, delay))
    sql = insertRecordSql('delay', {'proxy-type': proxy[1], 'proxy-id': proxy[0], 'env-id': envId, 'success': success, 'delay': delay, 'url': url})
    #print(sql)
    c.execute(sql)

def isIPv6(ip):
    return ip.find(':') != -1

def insertRecordSql(table, dict): #return sql
    for key in dict:
        dict[key] = "'" + str(dict[key]).replace("'", "''") + "'" if not(isinstance(dict[key], int) or isinstance(dict[key], float) or isinstance(dict[key], bool)) else str(dict[key])
    return "INSERT INTO `%s` (`" % table + '`, `'.join(dict.keys()) + "`) VALUES (" + ', '.join(dict.values()) + ")"

def getIPs(proxies):
    global dbConn, c, envId
    for proxy in proxies:
        clash_switchProxy(proxy[1] + ' ' + str(proxy[0]))
        
        #get request ip
        requestIP = socket.gethostbyname(proxy[2])
        sql = "select * from `ip` where `proxy-type`='{}' and `proxy-id`={} and `env-id`={} and `ip`='{}' and `ip-type`={}".format(proxy[1], proxy[0], envId, requestIP, 0)
        if len(c.execute(sql).fetchall()) == 0: 
            sql = "INSERT INTO `ip` (`proxy-type`, `proxy-id`, `env-id`, `ip`, `ip-version`, `ip-type`) VALUES ('{}', {}, {}, '{}', {}, {})".format(proxy[1], proxy[0], envId, requestIP, isIPv6(requestIP), 0)
            print(sql)
            c2 = dbConn.cursor()
            c2.execute(sql)
            c2.close()
        else: continue
        
        #get respond ip
        sql = "select * from `ip` where `proxy-type`='{}' and `proxy-id`={} and `env-id`={} and `ip-type`={}".format(proxy[1], proxy[0], envId, 1)
        if len(c.execute(sql).fetchall()) == 0: 
            print(proxy)
            result = getIPIPdotNet()
            #print(result)
            if result != "Failed":
                sql = "INSERT INTO `ip` (`proxy-type`, `proxy-id`, `env-id`, `ip`, `ip-version`, `ip-type`) VALUES ('{}', {}, {}, '{}', {}, {})".format(proxy[1], proxy[0], envId, result['ip'], isIPv6(result['ip']), 1)
                print(sql)
                c2 = dbConn.cursor()
                c2.execute(sql)
                c2.close()
                
                sql = "select * from `ip-info` where `ip`='{}' and `source`='{}'".format(result['ip'], 'myip.la')
                if len(c.execute(sql).fetchall()) == 0: 
                    sql = "INSERT INTO `ip-info` (`ip`, `ip-version`, `country-code`, `province`, `city`, `latitude`, `longitude`, `source`) VALUES ('{}', {}, '{}', '{}', '{}', '{}', '{}', '{}')".format(result['ip'], isIPv6(result['ip']), result['location']['country_code'], result['location']['province'], result['location']['city'], result['location']['latitude'], result['location']['longitude'], 'myip.la')
                    print(sql)
                    c2 = dbConn.cursor()
                    c2.execute(sql)
                    c2.close()
                
                sql = "select * from `ip-info` where `ip`='{}' and `source`='{}'".format(result['ip'], '纯真网络')
                if len(c.execute(sql).fetchall()) == 0: 
                    result = getIP(4 if isIPv6(result['ip']) else 6)
                    if result != "Failed":
                        sql = "INSERT INTO `ip-info` (`ip`, `ip-version`, `city`, `isp`, `source`) VALUES ('{}', {}, '{}', '{}', '{}')".format(result['myip'], isIPv6(result['myip']), result['country'], result['local'], '纯真网络')
                        print(sql)
                        c2 = dbConn.cursor()
                        c2.execute(sql)
                        c2.close()
            else:
                result = getIP(4)
                if result != "Failed":
                    sql = "INSERT INTO `ip-info` (`ip`, `ip-version`, `city`, `isp`, `source`) VALUES ('{}', {}, '{}', '{}', '{}')".format(result['myip'], isIPv6(result['myip']), result['country'], result['local'], '纯真网络')
                    print(sql)
                    c2 = dbConn.cursor()
                    c2.execute(sql)
                    c2.close()
                result = getIP(6)
                if result != "Failed":
                    sql = "INSERT INTO `ip-info` (`ip`, `ip-version`, `city`, `isp`, `source`) VALUES ('{}', {}, '{}', '{}', '{}')".format(result['myip'], isIPv6(result['myip']), result['country'], result['local'], '纯真网络')
                    print(sql)
                    c2 = dbConn.cursor()
                    c2.execute(sql)
                    c2.close()
            dbConn.commit()

def testSpeed(proxies): #speedtest.net
    global dbConn, c, envId
    for proxy in proxies:
        sql = "select ip from `ip` where `proxy-type`='{}' and `proxy-id`={} and `env-id`={} and `ip-version`={} and `ip-type`={}".format(proxy[1], proxy[0], envId, 0, 1)
        print(sql)
        result = c.execute(sql).fetchall()
        if len(result) > 0: 
            sql = "select * from `speedtest` where `ip`='{}' and `env-id`={} and `source`='{}'".format(c.execute(sql).fetchall()[0][0], envId, 'speedtest.net')
            result = c.execute(sql).fetchall()
            print(sql)
        if len(result) == 0: 
            clash_switchProxy(proxy[1] + ' ' + str(proxy[0]))
            print('Use:', clash_getProxiesInfo('GLOBAL')['now'])
            #test speed
            try:
                s = speedtest.Speedtest()
                s.get_servers([])
                s.get_best_server()
                s.download(threads=None)
                s.upload(threads=None)
                s.results.share()
            except Exception:
                continue
            D = s.results.dict()
            sql = insertRecordSql('speedtest', {'ip': D['client']['ip'], 'env-id': envId, 'download': D['download']/1000000, 'upload': D['upload']/1000000, 'ping': D['ping'], 'share-pic': D['share'], 'download-tracffic': D['bytes_received']/1000000, 'upload-tracffic': D['bytes_sent']/1000000, 'source': 'speedtest.net'})
            print(sql)
            c2 = dbConn.cursor()
            c2.execute(sql)
            c2.close()
            sql = insertRecordSql('ip-info', {'ip': D['client']['ip'], 'ip-version': isIPv6(D['client']['ip']), 'country-code': D['client']['country'], 'isp': D['client']['isp'], 'latitude': D['client']['lat'], 'longitude': D['client']['lon'], 'source': 'speedtest.net'})
            print(sql)
            c2 = dbConn.cursor()
            c2.execute(sql)
            c2.close()
            
            dbConn.commit()

def dumpSpeedProxies(IPnum = 10):
    global dbConn, c, code2name
    results = c.execute("select distinct ip,`country-code`,`env-id`,download,upload,ping from `speed-result`").fetchall()
    
    #取得国家列表
    countryCodes = list(set([x[1] for x in results]))
    
    #按国家取 IPnum 个节点的 IP
    output = []
    for countryCode in countryCodes:
        IPs = list(set([x[0] for x in results if x[1] == countryCode]))
        download = []
        for ip in IPs:
            data = [x[3] for x in results if x[0] == ip]
            download.append({'ip': ip, 'download': sum(data)/len(data)})
        download = sorted(download, key = lambda i: i['download'], reverse=True)
        for i in range(IPnum):
            if i >= len(download): break
            download[i]['rank'] = i + 1
            download[i]['country'] = countryCode
            output.append(download[i])
    
    #查询 IP 对应的节点
    nameParams = []
    proxies = []
    for dict in output:
        proxy = c.execute("select distinct `proxy-type`,`proxy-id` from ip where ip='%s' and `ip-type`=1"%dict['ip']).fetchall()[0]
        proxies.append(c.execute("select * from `%s` where `id`=%s"%(proxy[0], proxy[1])).fetchall()[0])
        delays = c.execute("select delay from `delay` where success=1 and `proxy-type`='%s' and `proxy-id`=%s"%(proxy[0], proxy[1])).fetchall()
        nameParam = [(code2name[dict['country']] if dict['country'] in code2name else dict['country']), dict['rank'], int(dict['download']), (int(sum([x[0] for x in delays])/len(delays)) if len(delays)>0 else 0)]
        netflix = c.execute("select result,`country-code` from `region` where ip='%s'"%dict['ip']).fetchall()
        if len(netflix) == 0:
            nameParam.append('')
        else:
            nameParam.append(' 奈飞自制剧' if netflix[0][0] == 'Originals Only' else (' 奈飞%s'%(code2name[netflix[0][1]] if netflix[0][1] in code2name else netflix[0][1]) if netflix[0][0] == 'Yes' else ''))
        nameParams.append(nameParam)
    result = dumpProxies(proxies, '{2}{3} {4}Mbps {5}ms{6}', nameParams)
    configPath = os.path.join(path, 'ClashConfigRaw.yml')
    yaml.safe_dump(result, open(configPath, 'w', encoding='UTF-8'), allow_unicode=True)

def testUnblockNefflix(proxies):
    def test():
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0',
        }
        try:
            r = requests.get("https://www.netflix.com/title/81215567", headers=headers, proxies=proxySet, timeout=(5, 10))
        except Exception:
            return "Failed", "Failed"
        if r.status_code == 200:
            try:
                r2 = requests.get("https://www.netflix.com/title/80018499", headers=headers, proxies=proxySet, allow_redirects=False, timeout=(5, 10))
            except Exception:
                return 'Yes', 'Failed'
            if 'location' in r2.headers:
                return 'Yes', r2.headers['location'].split('/')[3].split('-')[0].upper()
            else:
                return 'Yes', 'US'
        caseDict = {404: 'Originals Only', 403: 'No', 200: 'Yes', 0: 'Failed'}
        return caseDict[r.status_code], "Failed"
    global dbConn, c, envId
    for proxy in proxies:
        sql = "select ip from `ip` where `proxy-type`='{}' and `proxy-id`={} and `env-id`={} and `ip-version`={} and `ip-type`={}".format(proxy[1], proxy[0], envId, 0, 1)
        result = c.execute(sql).fetchall()
        sql = "select ip from `ip` where `proxy-type`='{}' and `proxy-id`={} and `env-id`={} and `ip-version`={} and `ip-type`={}".format(proxy[1], proxy[0], envId, 1, 1)
        result2 = c.execute(sql).fetchall()
        if len(result) > 0 and len(result2) == 0: 
            ip = result[0][0]
            sql = "select ip from `speedtest` where `ip`='{}' and `ip` not in (select ip from `region`)".format(ip)
            result3 = c.execute(sql).fetchall()
            if len(result3) == 0: continue
            clash_switchProxy(proxy[1] + ' ' + str(proxy[0]))
            print('Use:', clash_getProxiesInfo('GLOBAL')['now'])
            result, country = test()
            sql = insertRecordSql('region', {'ip': ip, 'ip-version': 0, 'result': result, 'country-code': country, 'site': 'Netflix'})
            print(sql)
            c2 = dbConn.cursor()
            c2.execute(sql)
            c2.close()
            dbConn.commit()
        else:
            continue

def getGithub():
    return 'https://raw.githubusercontent.com/chfchf0306/jeidian4.18/455bc762b64d820be96651bf3cd2c40d8bde71c5/4.18'

if __name__ == "__main__":
    setPaths()
    initialDB()
    
    #clash订阅导入
    urls = ['https://www.proxypool.ml/clash/proxies', 'https://hello.stgod.com/clash/proxies', 'https://193.123.234.61/clash/proxies', 'https://fq.lonxin.net/clash/proxies', 'https://free886.herokuapp.com/clash/proxies', 'https://149.248.8.112/clash/proxies', 'https://proxypool.fly.dev/clash/proxies', 'http://8.135.91.61/clash/proxies', 'http://antg.xyz/clash/proxies', 'https://proxy.51798.xyz/clash/proxies', 'https://sspool.herokuapp.com/clash/proxies', 'https://alexproxy003.herokuapp.com/clash/proxies', 'https://origamiboy.herokuapp.com/clash/proxies', 'https://hellopool.herokuapp.com/clash/proxies', 'http://guobang.herokuapp.com/clash/proxies', 'https://proxypool-guest997.herokuapp.com/clash/proxies', 'https://us-proxypool.herokuapp.com/clash/proxies', 'https://eu-proxypool.herokuapp.com/clash/proxies', 'https://proxypoolv2.herokuapp.com/clash/proxies']
    setProxiesEnv('http://127.0.0.1:7890')
    for url in urls:
        print(url)
        try:
            r = requests.get(url, proxies=proxySet)
        except Exception:
            print('Failed')
            continue
        print(importProxies(r.text))
    
    attributes = {'ss': ['id', 'type', 'server', 'port', 'password', 'cipher', 'plugin', 'plugin-opts'], 
    'ssr': ['id', 'type', 'server', 'port', 'password', 'cipher', 'protocol', 'protocol-param', 'obfs', 'obfs-param'], 
    'vmess': ['id', 'type', 'server', 'port', 'uuid', 'alterId', 'cipher', 'tls', 'skip-cert-verify', 'network', 'http-opts', 'h2-opts', 'servername', 'ws-path', 'ws-headers'], 
    'trojan': ['id', 'type', 'server', 'port', 'password', 'sni', 'skip-cert-verify']}
    
    envId = 1 #浙江移动 100M
    
    #test tcping  测过的，不测了
    proxies = c.execute("select * from trojan where id not in (select `proxy-id` from tcping where `proxy-type`='trojan')").fetchall()
    proxies += c.execute("select * from vmess where id not in (select `proxy-id` from tcping where `proxy-type`='vmess')").fetchall()
    proxies += c.execute("select * from ss where id not in (select `proxy-id` from tcping where `proxy-type`='ss')").fetchall()
    proxies += c.execute("select * from ssr where id not in (select `proxy-id` from tcping where `proxy-type`='ssr')").fetchall()
    times = 10 #测 10 次
    print('Tcping: %d 个节点，每个 %d 次' % (len(proxies), times))
    proxyQueue = []
    for i in range(times):
        proxyQueue += proxies
    multithread(testTcping, 64, proxyQueue)
    dbConn.commit()
    
    initClash()
    time.sleep(3)
    print(externalController, proxySetAddress)
    setProxiesEnv(proxySetAddress)
    
    #test delay  测过的，不测了
    proxies = c.execute("select * from ss where id in (select `proxy-id` from tcping where `proxy-type`='ss' and success=1) and id not in (select `proxy-id` from delay where `proxy-type`='ss')").fetchall()
    proxies += c.execute("select * from ssr where id in (select `proxy-id` from tcping where `proxy-type`='ssr' and success=1) and id not in (select `proxy-id` from delay where `proxy-type`='ssr')").fetchall()
    proxies += c.execute("select * from trojan where id in (select `proxy-id` from tcping where `proxy-type`='trojan' and success=1) and id not in (select `proxy-id` from delay where `proxy-type`='trojan')").fetchall()
    proxies += c.execute("select * from vmess where id in (select `proxy-id` from tcping where `proxy-type`='vmess' and success=1) and id not in (select `proxy-id` from delay where `proxy-type`='vmess')").fetchall()
    times = 10 #测 10 次
    print('测延迟: %d 个节点，每个 %d 次' % (len(proxies), times))
    proxyQueue = []
    for i in range(times):
        proxyQueue += proxies
    multithread(testDelay, 32, proxyQueue)
    dbConn.commit()
    
    #get response ip 
    proxies = c.execute("select * from ss where id in (select `proxy-id` from delay where `proxy-type`='ss' and success=1) and id not in (select `proxy-id` from ip where `proxy-type`='ss') order by id desc").fetchall()
    proxies += c.execute("select * from ssr where id in (select `proxy-id` from delay where `proxy-type`='ssr' and success=1) and id not in (select `proxy-id` from ip where `proxy-type`='ssr') order by id desc").fetchall()
    proxies += c.execute("select * from trojan where id in (select `proxy-id` from delay where `proxy-type`='trojan' and success=1) and id not in (select `proxy-id` from ip where `proxy-type`='trojan') order by id desc").fetchall()
    proxies += c.execute("select * from vmess where id in (select `proxy-id` from delay where `proxy-type`='vmess' and success=1) and id not in (select `proxy-id` from ip where `proxy-type`='vmess') order by id desc").fetchall()
    print('获取 IP: %d 个节点' % len(proxies))
    getIPs(proxies)
    dbConn.commit()
    
    #test speed 
    proxies = c.execute("select * from ss where id in (select `proxy-id` from ip where `proxy-type`='ss')").fetchall()
    proxies += c.execute("select * from ssr where id in (select `proxy-id` from ip where `proxy-type`='ssr')").fetchall()
    proxies += c.execute("select * from trojan where id in (select `proxy-id` from ip where `proxy-type`='trojan')").fetchall()
    proxies += c.execute("select * from vmess where id in (select `proxy-id` from ip where `proxy-type`='vmess')").fetchall()
    print('Speedtest: %d 个节点' % len(proxies))
    testSpeed(proxies)
    dbConn.commit()
    
    #test testUnblockNefflix 
    proxies = c.execute("select * from ss where id in (select `proxy-id` from ip where `proxy-type`='ss')").fetchall()
    proxies += c.execute("select * from ssr where id in (select `proxy-id` from ip where `proxy-type`='ssr')").fetchall()
    proxies += c.execute("select * from trojan where id in (select `proxy-id` from ip where `proxy-type`='trojan')").fetchall()
    proxies += c.execute("select * from vmess where id in (select `proxy-id` from ip where `proxy-type`='vmess')").fetchall()
    print('testUnblockNefflix: %d 个节点' % len(proxies))
    testUnblockNefflix(proxies)
    dbConn.commit()
    
    initCountryNameDict()
    
    # #print speed results
    # 
    # #print(code2name)
    # proxies = c.execute('''
    # select distinct id,ip,`country-code`,`env-id`,download,upload,ping,`download-tracffic`,`upload-tracffic`
    # from `speed-result`
    # ''').fetchall()
    # from prettytable import PrettyTable
    # t = PrettyTable(['id', 'ip', 'country', 'env-id', 'download', 'upload', 'ping', 'DL-tracffic', 'UL-tracffic'])
    # for row in proxies:
        # row = list(row)
        # row[2] = row[2]+' '+code2name[row[2]]
        # t.add_row([int(x) if isinstance(x, float) else x for x in row])
    # print(t)
    
    #
    dumpSpeedProxies()
    print('已输出可用代理')
    
    # sql = "select * from ss where `"
    input('执行完毕，回车结束')
    #Close clash 
    if clashPopenObj != None: clashPopenObj.kill()


