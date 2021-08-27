import yaml, requests, json, socket, time, speedtest, os
externalController = 'http://127.0.0.1:7777'
config = yaml.safe_load(open(r'C:\Users\Zjsxp\Desktop\config.yaml', 'r', encoding='UTF-8'))
resultsF = open(r'C:\Users\Zjsxp\Desktop\results.yaml', 'r', encoding='UTF-8')
results = yaml.safe_load(resultsF)
#print('results read:', results)
resultsF.close()
resultsF = open(r'C:\Users\Zjsxp\Desktop\results.yaml', 'w', encoding='UTF-8')
if not results: results={'proxies':{}}
proxySet = {
  "http": "http://127.0.0.1:7895",
  "https": "http://127.0.0.1:7895",
}
proxySetNone = {
  "http": "",
  "https": "",
}
os.environ['http_proxy'] = 'http://127.0.0.1:7895'
os.environ['https_proxy'] = 'https://127.0.0.1:7895'


import pycountry
code2name = {}
for country in pycountry.countries:
    code2name[country.alpha_2] = country.name

def getProxiesInfo(name=''):
    r = requests.get(externalController + '/proxies/' + name, proxies=proxySetNone)
    return(json.loads(r.content.decode('UTF-8'))) #return all, now, udp, etc.
def getProxiesDelay(name, timeout=2000, url='http://www.gstatic.com/generate_204'):
    r = requests.get(externalController + '/proxies/' + name + '/delay', params={'timeout':timeout,'url':url}, proxies=proxySetNone)
    return(json.loads(r.content.decode('UTF-8'))) #return delay or message
def switchProxy(name): 
    r = requests.put(externalController + '/proxies/' + 'GLOBAL', data=json.dumps({'name':name}), proxies=proxySetNone)
    return(r.content.decode('UTF-8')) #return 204: No Content
def getIP(ver=4,times=3):
    errorTimes = 0
    for i in range(times):
        r = requests.get('http://v'+str(ver)+'.ip.zxinc.org/info.php?type=json', proxies=proxySet)
        if r.status_code == 200:
            break
        else:
            errorTimes += 1
    return json.loads(r.content.decode('UTF-8')) if errorTimes<times else {'data':{'myip':'Failed','location':'Failed'}}
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
def queryIPInfo(ip):
    appcode = 'b6d2e6063aec445293258e531ae4137d'
    header = {'Authorization':'APPCODE ' + appcode}
    r = requests.get('http://cz88.rtbasia.com/search', params={'ip':ip}, proxies=proxySetNone,headers=header)
    return(json.loads(r.content.decode('UTF-8')))

#proxies = getProxiesInfo('GLOBAL')['all']
#print(json.dumps(proxies, sort_keys=True, indent=4, separators=(',', ': ')))
#print(queryIPInfo('8.8.8.8'))
#exit()
tcpingTimes = 1
delayTimes = 1
for proxyDict in config['proxies']:
    
    proxy = proxyDict['name']
    print('proxy:', proxy)
    if proxy not in results['proxies']: results['proxies'][proxy] = {}
    if 'status' in results['proxies'][proxy]: continue
    #print('results:', results)
    resultsF.seek(0)
    yaml.safe_dump(results, resultsF, encoding='utf-8', allow_unicode=True)
    
    #tcping
    errorTimes = 0
    for i in range(tcpingTimes):
        tcpingResult, tcpingTime = tcping(proxyDict['server'],proxyDict['port'],1)
        print('Tcping:', tcpingResult, tcpingTime)
        if tcpingResult:
            break
        else:
            errorTimes += 1
    if errorTimes >=tcpingTimes: 
        results['proxies'][proxy]['status'] = 'tcping failed'
        continue
    
    #test delay
    errorTimes = 0
    for i in range(delayTimes):
        result = getProxiesDelay(proxy)
        if 'message' in result: errorTimes += 1
        print('delay:', result)
    if errorTimes >= delayTimes: 
        results['proxies'][proxy]['status'] = 'delay test failed'
        continue
    results['proxies'][proxy]['status'] = 'on'
    
    #get request ip
    requestIP = socket.gethostbyname(proxyDict['server'])
    IPInfo = queryIPInfo(requestIP)['data']
    print('request ip:', requestIP, IPInfo)
    results['proxies'][proxy]['request_ip'] = requestIP
    if 'country' in IPInfo: results['proxies'][proxy]['request_ip_country'] = IPInfo['country']
    if 'province' in IPInfo: results['proxies'][proxy]['request_ip_province'] = IPInfo['province']
    if 'city' in IPInfo: results['proxies'][proxy]['request_ip_city'] = IPInfo['city']
    if 'isp' in IPInfo: results['proxies'][proxy]['request_ip_isp'] = IPInfo['isp']
    
    #get respond ip
    print('switch proxy:', proxy, switchProxy(proxy))
    result = getIP(4)
    print('respond ipv4:', result['data']['myip'], result['data']['location'])
    results['proxies'][proxy]['respond_ipv4'] = result['data']['myip']
    results['proxies'][proxy]['respond_ipv4_location'] = result['data']['location']
    result = getIP(6)
    print('respond ipv6:', result['data']['myip'], result['data']['location'])
    results['proxies'][proxy]['respond_ipv6'] = result['data']['myip']
    results['proxies'][proxy]['respond_ipv6_location'] = result['data']['location']
    
    #test speed
    s = speedtest.Speedtest()
    s.get_servers([])
    s.get_best_server()
    s.download(threads=None)
    s.upload(threads=None)
    try:
        s.results.share()
    except Exception:
        results['proxies'][proxy]['share_pic'] = 'share failed'
        continue
    results_dict = s.results.dict()
    print('Download Speed:',round(results_dict['download']/1000000,2))
    print('Upload Speed:',round(results_dict['upload']/1000000,2))
    print('Ping:',round(results_dict['ping'],0))
    print('Download Traffic:',round(results_dict['bytes_received']/1000000,2))
    print('Upload Traffic:',round(results_dict['bytes_sent']/1000000,2))
    print('Share Pic:',results_dict['share'])
    print('IP:',results_dict['client']['ip'])
    print('Location:',results_dict['client']['lat'],results_dict['client']['lon'])
    print('ISP:',results_dict['client']['isp'])
    print('Country:',results_dict['client']['country'])
    results['proxies'][proxy]['download_speed'] = round(results_dict['download']/1000000,2)
    results['proxies'][proxy]['upload_speed'] = round(results_dict['upload']/1000000,2)
    results['proxies'][proxy]['ping'] = round(results_dict['ping'],0)
    results['proxies'][proxy]['download_traffic'] = round(results_dict['bytes_received']/1000000,2)
    results['proxies'][proxy]['upload_traffic'] = round(results_dict['bytes_sent']/1000000,2)
    results['proxies'][proxy]['share_pic'] = results_dict['share']
    results['proxies'][proxy]['speedtest_ip'] = results_dict['client']['ip']
    results['proxies'][proxy]['speedtest_ip_lat'] = results_dict['client']['lat']
    results['proxies'][proxy]['speedtest_ip_lon'] = results_dict['client']['lon']
    results['proxies'][proxy]['speedtest_ip_isp'] = results_dict['client']['isp']
    results['proxies'][proxy]['speedtest_ip_country'] = results_dict['client']['country']
    #test Netflix
    
    
#save result
resultsF.seek(0)
yaml.safe_dump(results, resultsF, encoding='utf-8', allow_unicode=True)
resultsF.close()

os.environ['http_proxy'] = ''
os.environ['https_proxy'] = ''
output = {'proxies':[]}
en2zhF = open(r'C:\Users\Zjsxp\Desktop\en2zh.yaml', 'r', encoding='UTF-8')
en2zh = yaml.safe_load(en2zhF)
en2zhF.close()
#print(en2zh)
for proxyDict in config['proxies']:
    proxy = proxyDict['name']
    if proxy not in results['proxies']: continue
    if 'share_pic' not in results['proxies'][proxy]: continue
    if results['proxies'][proxy]['share_pic'] == 'share failed': continue
    if results['proxies'][proxy]['speedtest_ip_country'] in code2name:
        countryName = code2name[results['proxies'][proxy]['speedtest_ip_country']]
        if countryName in en2zh: countryName = en2zh[countryName]
    else:
        countryName = results['proxies'][proxy]['speedtest_ip_country']
    proxyDict['name'] = countryName+' '+str(round(results['proxies'][proxy]['download_speed']))+'Mbps '+str(int(results['proxies'][proxy]['ping']))+'ms'+(' IPv6' if results['proxies'][proxy]['respond_ipv6'] != 'Failed' else '')
    if proxyDict['name'] in [x['name'] for x in output['proxies'] if x['name'] == proxyDict['name']]:
        for i in range(2,100):
            if proxyDict['name'] + ' ' + str(i) in [x['name'] for x in output['proxies'] if x['name'] == proxyDict['name'] + ' ' + str(i)]:
                continue
            proxyDict['name'] = proxyDict['name'] + ' ' + str(i)
            break
    print(proxyDict)
    output['proxies'].append(proxyDict)
outputF = open(r'C:\Users\Zjsxp\Desktop\proxies.yaml', 'w', encoding='UTF-8')
yaml.safe_dump(output, outputF, encoding='utf-8', allow_unicode=True)
outputF.close()


