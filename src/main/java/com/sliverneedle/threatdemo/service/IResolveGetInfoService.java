package com.sliverneedle.threatdemo.service;

import com.sliverneedle.threatdemo.domain.SavedInfo;
import java.util.List;

public interface IResolveGetInfoService {
    public void init();
    public List<SavedInfo> returnElement(List<String> originList, String poster, String category) throws Exception;

    public SavedInfo updateInfoMark(SavedInfo info);

    public SavedInfo translateInfo(SavedInfo oriInfo) throws Exception;

    public List<String> getHotSearchDict();
}
