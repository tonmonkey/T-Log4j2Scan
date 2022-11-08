import re

obj = "https://www.tommonkey.cn/home/page?id=598729388568&name=tommonkey&token=1981973104320858290538450&da=https://www.tommonkey.cn:8080/file&ip=1.1.1.1:9876"

rule = r"=[\u4E00-\u9FA5A-Za-z0-9:/.]*"

result = re.sub(rule,'test',obj)

print(result)