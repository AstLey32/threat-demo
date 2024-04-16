package com.sliverneedle.threatdemo.service.impl;

import com.sliverneedle.threatdemo.domain.DataSource;
import com.sliverneedle.threatdemo.mapper.DataSourceMapper;
import com.sliverneedle.threatdemo.service.IGetDataSourceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class GetDataSourceService implements IGetDataSourceService {
    @Autowired
    private DataSourceMapper dataSourceMapper;
    @Override
    public List<DataSource> getAllDataSource(){
        return dataSourceMapper.selectAllDataSource();
    }

    @Override
    public List<DataSource> getValidDataSource(){
        return dataSourceMapper.selectValidDataSource();
    }

    @Override
    public int updateDataSource(DataSource dataSource) {
        return dataSourceMapper.updateDataSource(dataSource);
    }
}
