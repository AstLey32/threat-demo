from django.utils.deprecation import MiddlewareMixin
from django.middleware.csrf import get_token
from django.http import HttpResponse
import time


class IPLimitMiddleware(MiddlewareMixin):
    ipBlockDict = {}
    ipVisitDict = {}
    allowIps = ['127.0.0.1', '0.0.0.0', '10.164.217.186']

    def process_request(self, request):
        ip = request.META.get('REMOTE_ADDR')
        print(ip)
        if ip in self.ipBlockDict.keys():
            if time.time() - self.ipBlockDict[ip] > 300:
                self.ipBlockDict.pop(ip)
                self.ipVisitDict[ip] = 1
            else:
                res = int(300 + self.ipBlockDict[ip] - time.time())
                return HttpResponse("ip【" + ip + "】已被封禁！剩余" + str(res) + "秒")
        elif ip in self.ipVisitDict.keys():
            self.ipVisitDict[ip] += 1
            if self.ipVisitDict[ip] >= 10 and ip not in self.allowIps:
                self.ipBlockDict[ip] = time.time()
        else:
            self.ipVisitDict[ip] = 1


def index(request):
    ip = request.META.get('REMOTE_ADDR')
    return HttpResponse("兄弟，你好香！\n已定位到男同：来自ip【" + ip + "】")


def token(request):
    return HttpResponse(get_token(request))
