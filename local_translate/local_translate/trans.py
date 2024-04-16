import base64
import urllib.parse
import warnings
import threading
import re
from django.http import HttpResponse
from transformers import pipeline, TFAutoModelWithLMHead, AutoTokenizer

local_trans = None
mutex = threading.Lock()


class Trans:
    def __init__(self):
        warnings.filterwarnings('ignore')
        try:
            # print('Now loading zh-en translator')
            # model_zh_en = TFAutoModelWithLMHead.from_pretrained('opus-mt-zh-en')
            # tokenizer_zh_en = AutoTokenizer.from_pretrained('opus-mt-zh-en')
            # self.translation_zh_en = pipeline('translation_zh_to_en', model=model_zh_en, tokenizer=tokenizer_zh_en)
            model_en_zh = TFAutoModelWithLMHead.from_pretrained('opus-mt-en-zh')
            tokenizer_en_zh = AutoTokenizer.from_pretrained('opus-mt-en-zh')
            self.translation_en_zh = pipeline('translation_en_to_zh', model=model_en_zh, tokenizer=tokenizer_en_zh)
        except Exception as e:
            print('something error: ' + str(e))

def init():
    global local_trans
    if local_trans is None:
        mutex.acquire()
        print('Now loading en-zh translator')
        local_trans = Trans()
        print('ready')
        mutex.release()


def trans(request):
    global local_trans
    if local_trans is None:
        return HttpResponse("System error")
    req_text = urllib.parse.unquote(request.GET["words"])
    try:
        oriText = base64.b64decode(req_text).decode()
        print(oriText)
    except Exception as e:
        print(e)
        return HttpResponse("System error")
    if re.compile(r'[\u4e00-\u9fa5]').search(oriText):
        return HttpResponse(oriText)
    finalText = ""
    try:
        finalText = local_trans.translation_en_zh(oriText)[0]["translation_text"]
    except Exception as e:
        print(e)
    return HttpResponse(finalText)
