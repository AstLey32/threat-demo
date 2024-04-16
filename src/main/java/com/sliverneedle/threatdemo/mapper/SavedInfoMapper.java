package com.sliverneedle.threatdemo.mapper;

import com.sliverneedle.threatdemo.domain.SavedInfo;
import org.apache.ibatis.annotations.Mapper;

import java.util.Date;
import java.util.List;

/**
* @author l00618322
* @description 针对表【saved_info】的数据库操作Mapper
* @createDate 2024-03-05 19:44:34
* @Entity com.sliverneedle.threatdemo.domain.SavedInfo
*/
@Mapper
public interface SavedInfoMapper {
    public int createSavedInfoList(List<SavedInfo> newInfo);
    public List<SavedInfo> selectAllSavedInfo();

    public List<SavedInfo> selectNewSavedInfo(String timeInterval);

    public List<SavedInfo> selectHWSavedInfo(String kind);

    public int updateSavedInfo(String title, String link, String poster, String category,
                               String mark, Date savetime, String titlecn, Long savedInfoId);

    public int updateSavedInfoList(List<SavedInfo> savedInfo);
}




