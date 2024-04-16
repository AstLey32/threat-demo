package com.sliverneedle.threatdemo.mapper;

import com.sliverneedle.threatdemo.domain.KeyWords;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

/**
* @author l00618322
* @description 针对表【key_words】的数据库操作Mapper
* @createDate 2024-03-05 14:48:20
* @Entity com.sliverneedle.threatdemo.domain.KeyWords
*/
@Mapper
public interface KeyWordsMapper {
    public List<KeyWords> selectNormalKeyWords();

    public List<KeyWords> selectHotSearchKeyWords();
}




