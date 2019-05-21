# 获取对应时间段，并查询到对应可疑ip地址
get_time = body.split('\n')[4].split(' ')[1]
times = get_time.split('.')[0].split(':')[:2]
t = times[0]
t1 = int(times[1]) - 2
t2 = int(times[1]) + 2
# 将其转换为时间数组 
timeStruct = time.strptime(t + ':' + str(t1), "%Y-%m-%dT%H:%M") 
# 转换为时间戳: 
timeStamp1 = int(time.mktime(timeStruct))
# 时间戳转换为指定格式日期
localTime = time.localtime(timeStamp1) 
gt = time.strftime("%Y-%m-%dT%H:%M", localTime) 
timeStruct = time.strptime(t + ':' + str(t2), "%Y-%m-%dT%H:%M") 
# 转换为时间戳: 
timeStamp2 = int(time.mktime(timeStruct))
# 时间戳转换为指定格式日期
localTime = time.localtime(timeStamp2) 
lt = time.strftime("%Y-%m-%dT%H:%M", localTime)
# print(gt+'\n'+lt)
es = Elasticsearch("10.11.10.245:9200")
body = {
    "query": {
        "range" : {
            "@timestamp" : {
                "gt" : gt,
                "lt": lt
                            }
                    }
            }
    }
res = es.search(index="syslog", body=body)
text = res['hits']['hits']
if len(text) != 0:
    sip = text[0]['_source']['Source-address']
    dip = text[0]['_source']['Destination-address']
    dport = text[0]['_source']['Destination-Port']
    atype = text[0]['_source']['Threat-Content-Name']
    ntime = text[0]['_source']['Time-Logged']
    payload = {
        "msgtype": self.dingtalk_msgtype,
        "text": {
            "content": "IPS安全告警\n发现源ip地址: %s 在30秒内，对服务器ip：%s 的 %s 端口进行了5次攻击，攻击类型为 %s，请排除或确认攻击！\n(攻击时间点：%s)" % (sip, dip, dport, atype, ntime) 
        },
        "at": {
            "isAtAll":False
        }
    }