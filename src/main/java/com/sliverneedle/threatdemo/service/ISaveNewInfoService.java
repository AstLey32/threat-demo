package com.sliverneedle.threatdemo.service;

import com.sliverneedle.threatdemo.domain.SavedInfo;
import com.sliverneedle.threatdemo.domain.SavedIoc;

import java.util.List;

public interface ISaveNewInfoService {
    public int saveNewInfo(List<SavedInfo> newInfo);

    public List<SavedInfo> getSavedInfo();

    public List<SavedInfo> getSavedInfoByKeywords(String keywords);

    public List<SavedInfo> transSavedIocToSavedInfo(List<SavedIoc> iocs);

    public List<SavedIoc> getSavedIocByName(String name);

    public List<SavedInfo> getHWInfo(String kind);

    public List<SavedInfo> getNewInfo(int past, int category);

    public int updateSavedInfo(SavedInfo Info);

    public int updateSavedInfoList(List<SavedInfo> Info);
}
