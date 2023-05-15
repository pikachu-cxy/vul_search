import json
import re

import requests

#漏洞情报来源：
'''
https://github.com
https://poc.shuziguanxing.com/#/issueList  
https://vip.riskivy.com/intellList
https://ti.qianxin.com/vulnerability/total-quantity 

只关注高危

'''

#poc 来源：
#https://github.com

def qianxin(keyword, number=None, total_data=10):
    url = 'https://ti.qianxin.com/alpha-api/v2/nox/api/web/portal/vuln_repo/list'
    data = {"page_no": 1, "page_size": total_data, "tag": "", "vuln_keyword": "{}".format(keyword)}
    #print(data)
    json_response = requests.post(url, json=data, timeout=10)
    data_json = json_response.json()
    print(data_json)
    #获取数据量
    total = data_json["data"]["total"]
    if number == None:
        print(total)
        return total

    data_tmp = []
    for i in range(0, total_data):

        #获取cve_id
        cve_id = data_json["data"]["data"][i]["cve_code"]
        #获取cnvd_id
        cnvd_id = data_json["data"]["data"][i]["cnvd_id"]
        if cve_id == None and cnvd_id != None:
            cve_id = cnvd_id
        #获取产品名称product_name
        product_name = data_json["data"]["data"][i]["vuln_name"]
        print(product_name)
        #print("".join(re.findall(r'[^\\u]', product_name)))
        #exp是否存在
        has_poc = bool(data_json["data"]["data"][i]["poc_flag"])

        #提交日期 published_date
        published_date = data_json["data"]["data"][i]["publish_time"]
        #vul_type
        vul_type = data_json["data"]["data"][i]["vuln_type"]
        #description
        description = data_json["data"]["data"][i]["description"]

        data_tmp.append((cve_id, product_name, has_poc, published_date, vul_type, description))
    return data_tmp



