package com.sliverneedle.threatdemo.service;

import com.sliverneedle.threatdemo.domain.SavedInfo;

import java.util.List;

public interface ISaveNewInfoService {
    public int saveNewInfo(List<SavedInfo> newInfo);

    public List<SavedInfo> getSavedInfo();

    public List<SavedInfo> getHWInfo(String kind);

    public List<SavedInfo> getNewInfo(int pastDate);

    public int updateSavedInfo(SavedInfo Info);

    public int updateSavedInfoList(List<SavedInfo> Info);
}
