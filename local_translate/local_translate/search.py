import json
import requests
import time
from . import spider


def get_keywords():
    keywords = requests.get('http://127.0.0.1:8080/getHotSearchDict').text
    return json.loads(keywords)


def weibo():
    url = "https://s.weibo.com/top/summary?cate=realtimehot"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        'Host': 's.weibo.com',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'zh-CN,zh-Hans;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Cookie': 'SUB=_2AkMSOMUzf8NxqwFRmfoXzWPlbIhyzgrEieKkZDToJRMxHRl-yT8XqlAttRB6Objr3Fl4IcqHFu7zjVrGZpwf0LP4VVXx; SUBP=0033WrSXqPxfM72-Ws9jqgMF55529P9D9WFhCsudQj_idZ59fYUB_oRY; _s_tentry=passport.weibo.com; Apache=1537517908848.3137.1701071367195; SINAGLOBAL=1537517908848.3137.1701071367195; ULV=1701071367201:1:1:1:1537517908848.3137.1701071367195:'
    }
    requests.packages.urllib3.disable_warnings()
    r = requests.get(url, headers=headers, proxies=spider.get_proxies(), verify=False)
    news_list = []
    for line in r.text.splitlines():
        if '"_blank">' in line:
            news_list.append(line.split('"_blank">')[1].split('</a>')[0])

    kw_dicts = []
    no_kw_dicts = []
    for i in get_keywords():
        if i.startswith('-'):
            no_kw_dicts.append(i[1:])
        else:
            kw_dicts.append(i)
    ret = []
    for contentTitle in news_list:
        for kw in kw_dicts:
            if kw in contentTitle:
                for nkw in no_kw_dicts:
                    if nkw in contentTitle:
                        break
                news = spider.SpiderNews()
                news.title = contentTitle
                news.pubDate = time.strftime("%Y-%m-%d-%H:%M", time.localtime(time.time()))
                news.link = "https://s.weibo.com/weibo?q=%23" + contentTitle + "%23"
                news.category = "weibo"
                ret.append(news)
                break
    return ret
