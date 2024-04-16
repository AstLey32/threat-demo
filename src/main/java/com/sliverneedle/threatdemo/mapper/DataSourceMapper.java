package com.sliverneedle.threatdemo.mapper;

import com.sliverneedle.threatdemo.domain.DataSource;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface DataSourceMapper {
    List<DataSource> selectValidDataSource();

    List<DataSource> selectAllDataSource();

    int updateDataSource(DataSource dataSource);
}




