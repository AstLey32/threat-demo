package com.sliverneedle.threatdemo.service.impl;

import org.apache.tomcat.util.codec.binary.Base64;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

public class GetDjangoService {

    public static String GetTranslateAns(String oriWords) throws Exception {
        String b64Words = new String(Base64.encodeBase64(oriWords.getBytes()));
        String translator = "http://127.0.0.1:8398/trans?words=" + URLEncoder.encode(b64Words, "utf-8");
        Document document = Jsoup.connect(translator).timeout(80000).get();
        return document.text();
    }

    public static List<String> returnPython(String url) throws IOException {
        List<String> ret = new ArrayList<>();
        String b64Url = new String(Base64.encodeBase64(url.getBytes()));
        String pythonParser = "http://127.0.0.1:8398/spider?geturl=" + URLEncoder.encode(b64Url,"utf-8");
        String retAns = Jsoup.connect(pythonParser).timeout(80000).get().text();
        if (!retAns.equals("[]")) {
            for (String ans : retAns.split("}")) {
                ret.add(ans + "}");
            }
        }
        System.out.println(ret.size());
        return ret;
    }
}
