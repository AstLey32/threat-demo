package com.sliverneedle.threatdemo.service.impl;

import com.sliverneedle.threatdemo.domain.KeyWords;
import com.sliverneedle.threatdemo.domain.SavedInfo;

import java.util.*;
public class GetInfoFilterService {

    public static boolean dateTimeFilter(SavedInfo originInfo, long pastDay) {
        Date date = originInfo.getSavetime();
        long timePeriod = new Date().getTime() - date.getTime();
        return timePeriod <= pastDay * 24 * 60 * 60 * 1000;
    }

    public static String keywordsFilter(SavedInfo originInfo, List<KeyWords> keyWordsList) {
        String infoTitle = originInfo.getTitle();
        int keywordsPoints = 1;
        for (KeyWords kw: keyWordsList) {
            if (infoTitle.toLowerCase().contains(kw.getKeywords())) {
                keywordsPoints += kw.getPoints();
            }
        }
        if (originInfo.getCategory().contains("newscopy")) {
            keywordsPoints = 0;
        }
        return "" + keywordsPoints;
    }
}
