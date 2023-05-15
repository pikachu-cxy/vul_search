import json
import re


import requests
from lxml import etree

import test2

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

#只返回高危/严重漏洞
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
        #vul_risk 漏洞危害
        vul_risk = data_json["data"]["data"][i]["rating_level"]
        if vul_risk == '高危' or vul_risk == '严重':
            data_tmp.append((cve_id, product_name, has_poc, published_date, vul_type, description))

    return data_tmp, len(data_tmp)

#搜索对应poc较为困难，目前是根据github上一个poc收集项目作为数据源，直接获取，这个地方后期需要优化很多
def search_github_poc(cve_id):

    year = re.search('[\d]{4}',cve_id).group()
    print(year)

    poc_list = []

    url = 'https://github.com/trickest/cve/blob/c9ca6f0b9fbc643be51112bc5c654bb15ccacf42/'+year+'/'+cve_id.upper()+'.md'
    print(url)

    response = requests.get(url, timeout=10)
    #print(response.text)
    html = etree.HTML(response.text)
    #links = html.xpath('//ul[@id="jxlist"]/li/a/@href')
    poc_list = html.xpath('//ul[@dir="auto"]/li/a/@href')
    print(poc_list)
    return poc_list



#只返回高危/严重漏洞
def douxiang(keyword, number=None, total_data=10):
    data_tmp = []
    url = 'https://vip.riskivy.com/api/data/vuln_list'

    data = {"keyword":"{}".format(keyword),"riskLevelSort":"","modifyTimeSort":0,"page":1,"pageSize":100}
    total_data = int(total_data)
    if total_data > 100:
        page = total_data // 100
        page_size = 100
        #data = {"keyword": "{}".format(keyword), "riskLevelSort": "", "modifyTimeSort": 0, "page": 1,"pageSize": 200}
        for p in range(1, page+1):
            data = {"keyword": "{}".format(keyword), "riskLevelSort": "", "modifyTimeSort": 0, "page": p,"pageSize": 100}
            json_response = requests.post(url, json=data, timeout=10)
            data_json = json_response.json()
            if p == page:
                page_size = total_data % 100
            for i in range(0, page_size):

                # 获取cve_id
                cve_id = "" + data_json["data"]["records"][i]["vulnCveCode"]
                # 获取cnvd_id
                cnvd_id = data_json["data"]["records"][i]["vulnCnvdCode"]
                if cve_id == None and cnvd_id != None:
                    cve_id = cnvd_id
                # 获取产品名称product_name
                #product_name = data_json["data"]["records"][i]["vulnComponentNames"][0]
                product_name = data_json["data"]["records"][i]["vulnName"]

                # print("".join(re.findall(r'[^\\u]', product_name)))
                # exp是否存在
                has_poc = bool(data_json["data"]["records"][i]["refInfo"]["vulnPocId"] or data_json["data"]["records"][i]["refInfo"]["vulnExpId"])

                # 提交日期 published_date
                published_date = data_json["data"]["records"][i]["publishTime"]
                # vul_type
                vul_type = ""
                # description
                description = ""
                # vul_risk 漏洞危害
                vul_risk = data_json["data"]["records"][i]["riskLevel"]
                if vul_risk == 'serious' or vul_risk == 'high_risk':
                    data_tmp.append((cve_id, product_name, has_poc, published_date, vul_type, description))
        return data_tmp, len(data_tmp)

    json_response = requests.post(url, json=data, timeout=10)
    data_json = json_response.json()
    #print(data_json)
    # 获取数据量
    total = data_json["data"]["total"]
    if number == None:
        print(total)
        return total


    #print(total_data)
    for i in range(0, total_data):

        # 获取cve_id
        cve_id = data_json["data"]["records"][i]["vulnCveCode"]
        # 获取cnvd_id
        cnvd_id = data_json["data"]["records"][i]["vulnCnvdCode"]
        if cve_id == None and cnvd_id != None:
            cve_id = cnvd_id
        # 获取产品名称product_name
        product_name = data_json["data"]["records"][i]["vulnName"]

        # print("".join(re.findall(r'[^\\u]', product_name)))
        # exp是否存在
        has_poc = bool(data_json["data"]["records"][i]["refInfo"]["vulnPocId"] or data_json["data"]["records"][i]["refInfo"]["vulnExpId"])

        # 提交日期 published_date
        published_date = data_json["data"]["records"][i]["publishTime"]
        # vul_type
        #vul_type = data_json["data"]["records"][i]["cwes"][0]["cweNameEn"]
        vul_type = ""
        # description
        description = ""
        # vul_risk 漏洞危害
        vul_risk = data_json["data"]["records"][i]["riskLevel"]
        if vul_risk == 'serious' or vul_risk == 'high_risk':
            data_tmp.append((cve_id, product_name, has_poc, published_date, vul_type, description))
    return data_tmp, len(data_tmp)



def threesix(keyword, number=None, total_data=10):
    pass



