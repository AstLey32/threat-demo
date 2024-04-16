import base64
import urllib.parse
from django.http import HttpResponse
from . import search


class SpiderNews:
    title = ''
    link = ''
    pubDate = ''
    category = ''

    def get_str(self):
        return ("{\"title\": \"" + self.title + "\", \"link\": \"" + self.link + "\"," +
                "\"pubDate\": \"" + self.pubDate + "\", \"category\": \"" + self.category + "\"}")


def get_proxies():
    proxies = {
        "http": "http://l00618322:WEst%403226@proxycn2.huawei.com:8080/",
        "https": "http://l00618322:WEst%403226@proxycn2.huawei.com:8080/"
    }
    return proxies

def spider(request):
    req_text = urllib.parse.unquote(request.GET["geturl"])
    try:
        oriText = base64.b64decode(req_text).decode()
        print(oriText)
    except Exception as e:
        print(e)
        return HttpResponse("System error")
    if ".py" in oriText:
        spider_name = oriText.split('.py')[0]
        try:
            search_news = eval('search.'+ spider_name + '()')
            return HttpResponse([i.get_str() for i in search_news])
        except Exception as e:
            print(e)
            if 'no attribute' in str(e):
                return HttpResponse("Error: no spider module: " + spider_name)
            else:
                return HttpResponse("System error")
    return HttpResponse("Error: module name error: " + oriText)
