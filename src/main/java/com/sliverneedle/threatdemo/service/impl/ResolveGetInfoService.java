package com.sliverneedle.threatdemo.service.impl;

import com.sliverneedle.threatdemo.domain.KeyWords;
import com.sliverneedle.threatdemo.domain.SavedInfo;
import com.sliverneedle.threatdemo.mapper.KeyWordsMapper;
import com.sliverneedle.threatdemo.service.IResolveGetInfoService;
import org.springframework.boot.configurationprocessor.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.text.SimpleDateFormat;
import java.util.*;

@Service
public class ResolveGetInfoService implements IResolveGetInfoService {
    @Autowired
    private KeyWordsMapper keyWordsMapper;

    private List<KeyWords> keyWordsList;

    @PostConstruct
    @Override
    public void init() {
        keyWordsList = keyWordsMapper.selectNormalKeyWords();
    }

    static void dateTimeParser(SavedInfo originInfo, String pubDate) {
        String dateTimeStr = pubDate.split(":")[0].trim();
        SimpleDateFormat GMTFormat = new SimpleDateFormat("EEE, dd MMM yyyy hh", Locale.US);
        SimpleDateFormat SimpleFormat = new SimpleDateFormat("yyyy-MM-dd");
        SimpleDateFormat LongMonthFormat = new SimpleDateFormat("MMMMM d, yyyy", Locale.US);
        Date date = null;
        try {
            date = GMTFormat.parse(dateTimeStr);
        } catch (Exception e1) {
            try {
                date = SimpleFormat.parse(dateTimeStr);
            } catch (Exception e2) {
                try {
                    date = LongMonthFormat.parse(dateTimeStr);
                } catch (Exception e3) {
                    e3.fillInStackTrace();
                }
            }
        }
        if (date != null) {
            originInfo.setSavetime(date);
        } else {
            originInfo.setSavetime(new Date());
        }
    }

    @Override
    public List<SavedInfo> returnElement(List<String> originList, String poster, String category) throws Exception {
        List<SavedInfo> retList = new ArrayList<>();
        for (String info: originList) {
            SavedInfo savedInfo = new SavedInfo();
            JSONObject jsonObject = new JSONObject(info);
            savedInfo.setTitle(jsonObject.getString("title"));
            savedInfo.setLink(jsonObject.getString("link"));
            savedInfo.setPoster(poster);
            savedInfo.setCategory(category + ";" + jsonObject.getString("category"));
            savedInfo.setTitlecn("No Translation");
            dateTimeParser(savedInfo, jsonObject.getString("pubDate"));
            if (GetInfoFilterService.dateTimeFilter(savedInfo, 4)) {
                retList.add(savedInfo);
            }
        }
        return retList;
    }

    @Override
    public SavedInfo updateInfoMark(SavedInfo oriInfo) {
        oriInfo.setMark(GetInfoFilterService.keywordsFilter(oriInfo, keyWordsList));
        return oriInfo;
    }

    @Override
    public SavedInfo translateInfo(SavedInfo oriInfo) throws Exception {
        if (Objects.equals(oriInfo.getTitlecn(), "No Translation")) {
            String titleCN = GetDjangoService.GetTranslateAns(oriInfo.getTitle());
            oriInfo.setTitlecn(titleCN);
        }
        return oriInfo;
    }

    @Override
    public List<String> getHotSearchDict() {
        List<String> ret = new ArrayList<>();
        List<KeyWords> hotSearchDict =  keyWordsMapper.selectHotSearchKeyWords();
        for (KeyWords kw : hotSearchDict) {
            ret.add(kw.getKeywords());
        }
        return ret;
    }
}
