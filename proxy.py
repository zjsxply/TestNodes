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

def importProxies(config): #Import proxies to DB, return existCount, insertCount
    global dbConn, c
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
        dbInsert(type, proxyDict)
        insertCount += 1
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
            r = requests.get("https://api.myip.la/cn?json", proxies=proxySet, timeout=(5, 10))
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
            r = requests.get('http://v%d.ip.zxinc.org/info.php?type=json'%(version), proxies=proxySet, timeout=(5, 10))
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
    r = requests.get('http://cz88.rtbasia.com/search', params={'ip':ip}, proxies=proxySetNone,headers=header, timeout=(5, 10))
    return r.json()

def multiThread(f, number, work): #f(data, &c)
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

def dbInsertThread(flag=True): # flag: start or end
    if flag:
        global path, dbInsertQueueLock, dbInsertQueue, globalExitFlag, thread
        globalExitFlag = 0
        
        class myThread (threading.Thread):
            def __init__(self, threadID, name, q):
                threading.Thread.__init__(self)
                self.threadID = threadID
                self.name = name
                self.q = q
            def run(self):
                process_data(self.name, self.q)
        def process_data(threadName, q):
            dbConn = sqlite3.connect(os.path.join(path, 'proxies.db'))
            while not globalExitFlag:
                dbInsertQueueLock.acquire()
                sqls = []
                while not dbInsertQueue.empty(): #取得队列全部 sql 语句
                    sqls.append(q.get())
                dbInsertQueueLock.release()
                if len(sqls) != 0:
                    c = dbConn.cursor()
                    for sql in sqls:
                        c.execute(sql)
                    c.close()
                    dbConn.commit()
                    print('\n'.join(sqls)+'\n')
                else:
                    time.sleep(1) # 每 1 秒钟取得队列所有 sql 后立马释放锁，然后全部执行
            dbConn.close()
        dbInsertQueueLock = threading.Lock()
        dbInsertQueue = queue.Queue(0)
        
        # 创建线程
        thread = myThread(999, "Thread-{}".format(999), dbInsertQueue)
        thread.start()
    else:
        # 通知线程是时候退出
        globalExitFlag = 1

        # 等待线程完成
        thread.join()

def testTcping(proxy, c):
    success, delay = tcping(proxy[2], proxy[3])
    #print('Tcping {} {} ({}:{}) {}, {}ms'.format(proxy[1], proxy[0], proxy[2], proxy[3], success, delay))
    dbInsert('tcping', {'proxy-type': proxy[1], 'proxy-id': proxy[0], 'env-id': envId, 'success': 1 if success else 0, 'delay': delay})

def testDelay(proxy, c, timeout = 2000, url = 'http://www.gstatic.com/generate_204'):
    result = clash_getProxiesDelay(proxy[1]+' '+str(proxy[0]), timeout, url)
    if 'message' in result:
        success = 0
        delay = timeout
    else:
        success = 1
        delay = result['delay']
    #print('delay test {} {} ({}:{}) {}, {}ms'.format(proxy[1], proxy[0], proxy[2], proxy[3], success, delay))
    dbInsert('delay', {'proxy-type': proxy[1], 'proxy-id': proxy[0], 'env-id': envId, 'success': success, 'delay': delay, 'url': url})

def isIPv6(ip):
    return ip.find(':') != -1

def dbRead(sql):
    global c
    return c.execute(sql).fetchall()

def dbInsert(table, dict):
    global dbInsertQueueLock, dbInsertQueue
    for key in dict:
        dict[key] = "'" + str(dict[key]).replace("'", "''") + "'" if not(isinstance(dict[key], int) or isinstance(dict[key], float) or isinstance(dict[key], bool)) else str(dict[key])
    sql = "INSERT INTO `%s` (`" % table + '`, `'.join(dict.keys()) + "`) VALUES (" + ', '.join(dict.values()) + ")"
    dbInsertQueueLock.acquire()
    dbInsertQueue.put(sql)
    dbInsertQueueLock.release()
    
def getIPs(proxies):
    global dbConn, c, envId
    for proxy in proxies:
        clash_switchProxy(proxy[1] + ' ' + str(proxy[0]))
        
        #get request ip
        requestIP = socket.gethostbyname(proxy[2])
        sql = "select * from `ip` where `proxy-type`='{}' and `proxy-id`={} and `env-id`={} and `ip`='{}' and `ip-type`={}".format(proxy[1], proxy[0], envId, requestIP, 0)
        if len(dbRead(sql)) == 0: 
            dbInsert('ip', {'proxy-type': proxy[1], 'proxy-id': proxy[0], 'env-id': envId, 'ip': requestIP, 'ip-version': isIPv6(requestIP), 'ip-type': 0})
        else: continue
        
        #get respond ip
        sql = "select * from `ip` where `proxy-type`='{}' and `proxy-id`={} and `env-id`={} and `ip-type`={}".format(proxy[1], proxy[0], envId, 1)
        if len(dbRead(sql)) == 0: 
            print(proxy)
            result = getIPIPdotNet()
            #print(result)
            if result != "Failed":
                dbInsert('ip', {'proxy-type': proxy[1], 'proxy-id': proxy[0], 'env-id': envId, 'ip': result['ip'], 'ip-version': isIPv6(result['ip']), 'ip-type': 1})
                
                sql = "select * from `ip-info` where `ip`='{}' and `source`='{}'".format(result['ip'], 'myip.la')
                if len(dbRead(sql)) == 0: 
                    dbInsert('ip-info', {'ip': result['ip'], 'ip-version': isIPv6(result['ip']), 'country-code': result['location']['country_code'], 'province': result['location']['province'], 'city': result['location']['city'], 'latitude': result['location']['latitude'], 'longitude': result['location']['longitude'], 'source': 'myip.la'})
                
                sql = "select * from `ip-info` where `ip`='{}' and `source`='{}'".format(result['ip'], '纯真网络')
                if len(dbRead(sql)) == 0: 
                    result = getIP(4 if isIPv6(result['ip']) else 6)
                    if result != "Failed":
                        dbInsert('ip-info', {'ip': result['myip'], 'ip-version': isIPv6(result['myip']), 'city': result['country'], 'isp': result['local'], 'source': '纯真网络'})
            else:
                result = getIP(4)
                if result != "Failed":
                    dbInsert('ip-info', {'ip': result['myip'], 'ip-version': isIPv6(result['myip']), 'city': result['country'], 'isp': result['local'], 'source': '纯真网络'})
                result = getIP(6)
                if result != "Failed":
                    dbInsert('ip-info', {'ip': result['myip'], 'ip-version': isIPv6(result['myip']), 'city': result['country'], 'isp': result['local'], 'source': '纯真网络'})

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
            dbInsert('speedtest', {'ip': D['client']['ip'], 'env-id': envId, 'download': D['download']/1000000, 'upload': D['upload']/1000000, 'ping': D['ping'], 'share-pic': D['share'], 'download-tracffic': D['bytes_received']/1000000, 'upload-tracffic': D['bytes_sent']/1000000, 'source': 'speedtest.net'})
            dbInsert('ip-info', {'ip': D['client']['ip'], 'ip-version': isIPv6(D['client']['ip']), 'country-code': D['client']['country'], 'isp': D['client']['isp'], 'latitude': D['client']['lat'], 'longitude': D['client']['lon'], 'source': 'speedtest.net'})

def code2name(code):
    global code2nameDict, en2zhPath
    if 'code2nameDict' not in dir(): 
        import pycountry
        code2nameDict = {}
        en2zh = yaml.safe_load(open(en2zhPath, 'r', encoding='UTF-8'))
        #print(en2zh)
        for country in pycountry.countries:
            code2nameDict[country.alpha_2] = en2zh[country.name] if country.name in en2zh else country.name
    return code2nameDict[code] if code in code2nameDict else code

def dumpSpeedProxies(IPnum = 10): # 输出到 ClashConfigRaw.yml
    # 以 IP 标识节点，对每个节点计算网速、延迟，按网速排序，对每个国家取前 10 个，并验证是否可用
    IPs = [x[0] for x in dbRead("select distinct ip from `speedtest` where ip in (select ip from `ip-info`)")]
    
    country, download, netflix = {}, {}, {}
    for ip in IPs:
        # 查询 IP 国家
        results = dbRead("select `country-code`,source,time,province,city from `ip-info` where ip='%s'"%ip)
        for source in ['myip.la', 'speedtest.net']:
            result = [x for x in results if x[1] == source]
            if len(result) > 0:
                country[ip] = result[0][0]
                if country[ip] == 'CN': country[ip] = '中国' + str(result[0][4])
                break
        if ip not in country: country[ip] = 'Unknown'
        
        # 查询 IP 网速（平均值）
        results = dbRead("select `download`,source,time from `speedtest` where ip='%s' and source='speedtest.net'"%ip)
        speeds = [x[0] for x in results]
        download[ip] = sum(speeds)/len(speeds) if len(speeds) > 0 else -1
        
        # 查询奈飞支持
        results = dbRead("select result,`country-code` from `region` where ip='%s' and site='Netflix' order by time desc"%ip)
        if len(results) == 0:
            netflix[ip] = ''
        else:
            netflix[ip] = ' 奈飞自制剧' if results[0][0] == 'Originals Only' else (' 奈飞%s'%code2name(results[0][1]) if results[0][0] == 'Yes' else '')
        
    # 取得国家列表
    countryCodes = list(set(country.values()))
    
    # 按国家取 IPnum 个节点的 IP
    IPs = sorted(IPs, key = lambda i: download[i], reverse=True)
    output = {}
    proxyTypeIdDelay = {}
    for ip in IPs:
        if country[ip] not in output: output[country[ip]] = []
        if len(output[country[ip]]) >= IPnum and netflix[ip] == '': continue # 奈飞节点，不受额度限制
        # 查询 IP 对应的节点及延时（平均值）
        results = dbRead("select ip.`proxy-type`,ip.`proxy-id`,avg(delay) from ip,delay where ip='%s' and `ip-type`=1 and success=1 and ip.`proxy-type`=delay.`proxy-type` and ip.`proxy-id`=delay.`proxy-id` group by ip.`proxy-type`,ip.`proxy-id`"%ip)
        #results = dbRead("select ip.`proxy-type`,ip.`proxy-id`,avg(delay) from ip,delay,(select C.`proxy-type`,C.`proxy-id`,C.success from delay as C order by C.time desc group by C.`proxy-type`,C.`proxy-id`) where ip='%s' and `ip-type`=1 and success=1 and C.success=1 and ip.`proxy-type`=delay.`proxy-type` and ip.`proxy-id`=delay.`proxy-id` and ip.`proxy-type`=C.`proxy-type` and ip.`proxy-id`=C.`proxy-id` group by ip.`proxy-type`,ip.`proxy-id`"%ip)
        if len(results) == 0: continue
        results = sorted(results, key = lambda i: i[2])
        for result in results: # 如果最新一次 delay 测试 Failed，则跳过
            results2 = dbRead("select success from delay where `proxy-type`='%s' and `proxy-id`=%d order by time desc"%(result[0],result[1]))
            if results2[0][0] == 1: break
        if results2[0][0] == 1: 
            proxyTypeIdDelay[ip] = result
            output[country[ip]].append(ip)
    
    nameParams = []
    proxies = []
    for key in output:
        for i, ip in enumerate(output[key]):
            proxies.append(dbRead("select * from `%s` where `id`=%s"%(proxyTypeIdDelay[ip][0], proxyTypeIdDelay[ip][1]))[0])
            nameParam = [code2name(key), i + 1, int(download[ip]), int(proxyTypeIdDelay[ip][2]), netflix[ip]]
            nameParams.append(nameParam)
    
    result = dumpProxies(proxies, '{2}{3} {4}Mbps {5}ms{6}', nameParams)
    configPath = os.path.join(path, 'ClashConfigRaw.yml')
    yaml.safe_dump(result, open(configPath, 'w', encoding='UTF-8'), allow_unicode=True)

def testUnblockNefflix(proxies):
    def test():
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0'}
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
    global envId
    for proxy in proxies:
        result = dbRead("select ip from `ip` where `proxy-type`='{}' and `proxy-id`={} and `env-id`={} and `ip-version`={} and `ip-type`={}".format(proxy[1], proxy[0], envId, 0, 1))
        result2 = dbRead("select ip from `ip` where `proxy-type`='{}' and `proxy-id`={} and `env-id`={} and `ip-version`={} and `ip-type`={}".format(proxy[1], proxy[0], envId, 1, 1))
        if len(result) > 0 and len(result2) == 0: 
            ip = result[0][0]
            result3 = dbRead("select ip from `speedtest` where `ip`='{}' and `ip` not in (select ip from `region` where site='Netflix')".format(ip))
            if len(result3) == 0: continue
            clash_switchProxy(proxy[1] + ' ' + str(proxy[0]))
            print('Use:', clash_getProxiesInfo('GLOBAL')['now'])
            result, country = test()
            dbInsert('region', {'ip': ip, 'ip-version': 0, 'result': result, 'country-code': country, 'site': 'Netflix'})
        else:
            continue

def getGithub():
    return 'https://raw.githubusercontent.com/chfchf0306/jeidian4.18/455bc762b64d820be96651bf3cd2c40d8bde71c5/4.18'

if __name__ == "__main__":
    setPaths()
    initialDB()
    dbInsertThread(True)
    
    #clash订阅导入
    #urls = ['https://www.proxypool.ml/clash/proxies', 'https://hello.stgod.com/clash/proxies', 'http://193.123.234.61/clash/proxies', 'https://fq.lonxin.net/clash/proxies', 'https://free886.herokuapp.com/clash/proxies', 'https://149.248.8.112/clash/proxies', 'https://proxypool.fly.dev/clash/proxies', 'http://8.135.91.61/clash/proxies', 'http://antg.xyz/clash/proxies', 'https://proxy.51798.xyz/clash/proxies', 'https://sspool.herokuapp.com/clash/proxies', 'https://alexproxy003.herokuapp.com/clash/proxies', 'https://origamiboy.herokuapp.com/clash/proxies', 'https://hellopool.herokuapp.com/clash/proxies', 'http://guobang.herokuapp.com/clash/proxies', 'https://proxypool-guest997.herokuapp.com/clash/proxies', 'https://us-proxypool.herokuapp.com/clash/proxies', 'https://eu-proxypool.herokuapp.com/clash/proxies', 'https://proxypoolv2.herokuapp.com/clash/proxies', 'https://emby.luoml.eu.org/clash/proxies', 'http://www.fuckgfw.tk/clash/proxies', 'https://etproxypool.ga/clash/proxies', 'https://hm2019721.ml/clash/proxies', 'https://free.kingfu.cf/clash/proxies', 'https://free.dswang.ga/clash/proxies', 'https://fq.lonxin.net/clash/proxies', 'https://www.linbaoz.com/clash/proxies', 'https://www.qunima.cc/clash/proxies', 'https://www.joemt.tk/clash/proxies', 'https://raw.githubusercontent.com/chfchf0306/clash/main/clash']
    setProxiesEnv('http://127.0.0.1:7890')
    if 'urls' in dir():
        for url in urls:
            print(url)
            try:
                r = requests.get(url, proxies=proxySet)
            except Exception:
                try:
                    r = requests.get(url, proxies=proxySet, verify=False)
                except Exception:
                    print('Http Failed')
                    continue
            try:
                proxies = yaml.safe_load(r.text)
            except Exception:
                print('Failed')
                continue
            if proxies == None or 'proxies' not in proxies: continue
            print(len(proxies['proxies']), importProxies(proxies))
    
    
    attributes = {'ss': ['id', 'type', 'server', 'port', 'password', 'cipher', 'plugin', 'plugin-opts'], 
    'ssr': ['id', 'type', 'server', 'port', 'password', 'cipher', 'protocol', 'protocol-param', 'obfs', 'obfs-param'], 
    'vmess': ['id', 'type', 'server', 'port', 'uuid', 'alterId', 'cipher', 'tls', 'skip-cert-verify', 'network', 'http-opts', 'h2-opts', 'servername', 'ws-path', 'ws-headers'], 
    'trojan': ['id', 'type', 'server', 'port', 'password', 'sni', 'skip-cert-verify']}
    
    envId = 1 #浙江移动 100M
    
    #test tcping  
    times = 10 # 没测过的，测 10 次；测试次数小于 10 的，再测 1 次；上次测试超过 4 小时的，再测 1 次
    proxies = []
    for proxyType in ['vmess', 'ssr', 'ss', 'trojan']:
        proxies += dbRead("select * from `%s` where `id` not in (select `proxy-id` from `tcping` where `proxy-type`='%s')"%(proxyType,proxyType))
    proxyQueue = []
    for i in range(times):
        proxyQueue += proxies
    for proxy in dbRead("SELECT * FROM (SELECT `proxy-type`, `proxy-id`, COUNT(*) as count FROM `tcping` GROUP BY `proxy-type`, `proxy-id`) WHERE count<%d;"%times):
        proxyQueue += dbRead("select * from `%s` where `id`=%d" % (proxy[0], proxy[1]))
    for proxy in dbRead("SELECT * FROM (SELECT `proxy-type`, `proxy-id`, MAX(time) as lasttime FROM `tcping` GROUP BY `proxy-type`, `proxy-id`) WHERE julianday('now') - julianday(lasttime)>1/6;"):
        proxyQueue += dbRead("select * from `%s` where `id`=%d" % (proxy[0], proxy[1]))
    print('Tcping: 100 线程，%d 个节点未测过，共需测 %d 次' % (len(proxies),len(proxyQueue)))
    multiThread(testTcping, 100, proxyQueue)
    dbConn.commit()
    
    initClash()
    time.sleep(3)
    print(externalController, proxySetAddress)
    setProxiesEnv(proxySetAddress)
    
    #test delay  
    times = 10 # 没测过的，测 10 次；测试次数小于 10 的，再测 1 次；上次测试超过 4 小时的，再测 1 次
    proxies = []
    for proxyType in ['vmess', 'ssr', 'ss', 'trojan']:
        proxies += dbRead("select * from `%s` where `id` in (select `proxy-id` from `tcping` where `proxy-type`='%s' and success=1) and `id` not in (select `proxy-id` from `delay` where `proxy-type`='%s')"%(proxyType,proxyType,proxyType))
    proxyQueue = []
    for i in range(times):
        proxyQueue += proxies
    for proxy in dbRead("SELECT * FROM (SELECT `proxy-type`, `proxy-id`, COUNT(*) as count FROM `delay` GROUP BY `proxy-type`, `proxy-id`) WHERE count<%d;"%times):
        proxyQueue += dbRead("select * from `%s` where `id`=%d" % (proxy[0], proxy[1]))
    for proxy in dbRead("SELECT * FROM (SELECT `proxy-type`, `proxy-id`, MAX(time) as lasttime FROM `delay` GROUP BY `proxy-type`, `proxy-id`) WHERE julianday('now') - julianday(lasttime)>1/6;"):
        proxyQueue += dbRead("select * from `%s` where `id`=%d" % (proxy[0], proxy[1]))
    print('测延迟: 64 线程，%d 次' % len(proxyQueue))
    multiThread(testDelay, 64, proxyQueue)
    dbConn.commit()
    
    #get response ip 
    proxies = []
    for proxyType in ['vmess', 'ssr', 'ss', 'trojan']:
        proxies += dbRead("select * from `%s` where id in (select `proxy-id` from delay where `proxy-type`='%s' and success=1) and id not in (select `proxy-id` from ip where `proxy-type`='%s') order by id desc"%(proxyType,proxyType,proxyType))
    print('获取 IP: %d 个节点' % len(proxies))
    getIPs(proxies)
    dbConn.commit()
    
    # #test speed 
    # proxies = []
    # for proxyType in ['vmess', 'ssr', 'ss', 'trojan']:
        # proxies += dbRead("select * from `%s` where id in (select `proxy-id` from ip where `proxy-type`='%s')"%(proxyType,proxyType))
    # print('Speedtest: %d 个节点' % len(proxies))
    # testSpeed(proxies)
    # dbConn.commit()
    
    #test testUnblockNefflix 
    proxies = []
    for proxyType in ['vmess', 'ssr', 'ss', 'trojan']:
        proxies += dbRead("select * from `%s` where id in (select `proxy-id` from ip where `proxy-type`='%s')"%(proxyType,proxyType))
    print('testUnblockNefflix: %d 个节点' % len(proxies))
    testUnblockNefflix(proxies)
    dbConn.commit()
    
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
    
    #Close clash 
    if clashPopenObj != None: clashPopenObj.kill()
    dbInsertThread(False)


