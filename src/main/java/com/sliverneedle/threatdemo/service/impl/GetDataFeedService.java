package com.sliverneedle.threatdemo.service.impl;

import com.sliverneedle.threatdemo.service.IGetDataFeedService;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.TextNode;
import org.jsoup.select.Elements;
import org.seimicrawler.xpath.JXDocument;
import org.seimicrawler.xpath.JXNode;
import org.springframework.stereotype.Service;

import java.net.Proxy;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@Service
public class GetDataFeedService implements IGetDataFeedService {

    static Document returnDocument(String url) {
        try {
            return Jsoup.connect(url).get();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    static List<String> returnRss(String url) {
        Document document = returnDocument(url);
        Elements elements =  document.getElementsByTag("item");
        if (elements.isEmpty()) {
            elements =  document.getElementsByTag("entry");
        }
        System.out.println(elements.size());
        List<String> retList = new ArrayList<>();
        for (Element ele: elements) {
            String contentTitle = ele.select("title").text();
            contentTitle = contentTitle.replaceAll("\"", "'");
            String contentLink = ele.select("link").text();
            if (contentLink.isEmpty()) {
                contentLink = ele.select("link").attr("href");
            }
            String contentPubDate = ele.select("pubDate").text();
            if (contentPubDate.isEmpty()) {
                contentPubDate = ele.select("published").text();
            }
            StringBuilder contentCategory = new StringBuilder();
            for (Element cat: ele.select("category")) {
                String catText = cat.text();
                if (catText.isEmpty()) {
                    catText = cat.attr("term");
                }
                contentCategory.append(catText).append(";");
            }
            String contentText = "{\"title\": \"" + contentTitle + "\", \"link\": \"" + contentLink + "\", \"pubDate\": \"" + contentPubDate + "\", \"category\": \"" + contentCategory + "\"}";
            retList.add(contentText);
        }
        return retList;
    }

    static List<String> returnXpath(String url, String rule) throws Exception {
        Document document = returnDocument(url);
        String xPath = rule.split("\\$")[0];
        int titleId = Integer.parseInt(rule.split("\\$")[1]);
        int pubDateId = Integer.parseInt(rule.split("\\$")[2]);
        JXDocument jxDocument = JXDocument.create(document);
        List<JXNode> jxNodes = jxDocument.selN(xPath);
        List<String> retList = new ArrayList<>();
        System.out.println(jxNodes.size());
        for (JXNode jxNode : jxNodes) {
            int parseId = 1;
            String contentLink = "";
            String contentTitle = "";
            String contentPubDate = "";
            Element element = jxNode.asElement();
            Element link = element.select("a").first();
            if (link != null) {
                String linkUrl = link.attr("href");
                url = url.split(":")[0] + "://" + new URL(url).getHost();
                if (!linkUrl.startsWith("http")) {
                    linkUrl = url + (linkUrl.startsWith("/") ? "" : "/") + linkUrl;
                }
                contentLink = linkUrl;
            }
            StringBuilder contentText = new StringBuilder();
            for (TextNode ele: element.getAllElements().textNodes()) {
                if (!ele.text().equals(" ")) {
                    if (parseId == titleId) {
                        contentTitle = ele.text().replaceAll("\"", "'");
                    } else if (parseId == pubDateId) {
                        contentPubDate = ele.text();
                    } else {
                        contentText.append(ele.text().replaceAll("\"", "'")).append(";");
                    }
                    parseId++;
                }
            }
            if (Objects.equals(contentTitle, "")) {
                contentTitle = "无标题";
            }
            String retText = "{\"title\": \"" + contentTitle + "\", \"link\": \"" + contentLink + "\", \"pubDate\": \"" + contentPubDate + "\", \"category\": \"" + contentText + "\"}";
            retList.add(retText);
        }
        return retList;
    }

    static boolean verifyRule(String url, String rule) {
        if (Objects.equals(rule,"python")) {
            return url.endsWith(".py");
        } else {
            if (!url.startsWith("http")) {
                return false;
            }
            if (!Objects.equals(rule, "rss")) {
                String[] ruleSplit = rule.split("\\$");
                if (ruleSplit.length == 3 && ruleSplit[0].startsWith("//")) {
                    int titleId = Integer.parseInt(ruleSplit[1]);
                    int pubDateId = Integer.parseInt(ruleSplit[2]);
                    return (titleId < 100 && pubDateId < 100);
                } else {
                    return false;
                }
            }
            return true;
        }
    }

    @Override
    public List<String> returnElement(String url, String rule) throws Exception {
        List<String> oriList = new ArrayList<>();
        System.out.println("Search url: " + url);
        System.out.println("Use rule: " + rule);
        if (!verifyRule(url, rule)) {
            System.out.println("Error: url or rule is not verified!");
            return oriList;
        }
        if (Objects.equals(rule, "rss")) {
            oriList = returnRss(url);
        } else if (Objects.equals(rule, "python")) {
            oriList = GetDjangoService.returnPython(url);
        } else {
            oriList = returnXpath(url, rule);
        }
        return oriList;
    }
}
