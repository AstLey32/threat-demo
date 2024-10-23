package com.sliverneedle.threatdemo.service.impl;

import org.apache.tomcat.util.codec.binary.Base64;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;

public class GetDjangoService {
    public static String GetCSRFToken() throws IOException {
        String getToken = "http://127.0.0.1:8398/get_token";
        Connection conn = Jsoup.connect(getToken).timeout(80000);
        return conn.get().text();
    }

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

    public static void SendSharedInfo(List<String> infos) throws IOException {
        String Shared = "http://127.0.0.1:8398/share";
        String csrfToken = GetCSRFToken();
        Map<String, String> csrf = new HashMap<>();
        csrf.put("X-CSRFToken", csrfToken);
        Connection conn = Jsoup.connect(Shared).timeout(80000);
        conn.cookie("csrftoken", csrfToken);
        conn.headers(csrf);
        conn.data("data", String.join("\n",infos));
        String retAns = conn.post().text();
        if (!retAns.equals("ok")) {
            System.out.println(retAns);
        }
    }
}
