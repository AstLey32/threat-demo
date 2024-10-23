package com.sliverneedle.threatdemo.mapper;

import com.sliverneedle.threatdemo.domain.SavedIoc;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

/**
* @author l00618322
* @description 针对表【saved_ioc】的数据库操作Mapper
* @createDate 2024-08-29 17:30:41
* @Entity com.sliverneedle.threatdemo.domain.SavedIoc
*/
@Mapper
public interface SavedIocMapper {
    public List<SavedIoc> selectAllSavedIoc();

    public List<SavedIoc> selectOneIoc(String savedIocName);
}




