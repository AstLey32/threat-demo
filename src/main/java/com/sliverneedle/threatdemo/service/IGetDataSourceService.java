package com.sliverneedle.threatdemo.service;

import com.sliverneedle.threatdemo.domain.DataSource;

import java.util.List;

public interface IGetDataSourceService {
    List<DataSource> getAllDataSource();

    List<DataSource> getValidDataSource();

    int updateDataSource(DataSource dataSource);
}
