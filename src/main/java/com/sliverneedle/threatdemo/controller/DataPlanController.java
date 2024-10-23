package com.sliverneedle.threatdemo.controller;

import com.sliverneedle.threatdemo.domain.DataSource;
import com.sliverneedle.threatdemo.domain.SavedInfo;
import com.sliverneedle.threatdemo.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@RestController
public class DataPlanController {
    @Autowired
    private IGetDataSourceService getDatabaseService;
    @Autowired
    private IGetDataFeedService getDataFeedService;
    @Autowired
    private IResolveGetInfoService resolveGetInfoService;
    @Autowired
    private ISaveNewInfoService saveNewInfoService;

    @RequestMapping("/ins")
    public List<String> ins() {
        List<String> insLog = new ArrayList<>();
        for (DataSource ds: getDatabaseService.getValidDataSource()){
            String url = ds.getUrl();
            String rule = ds.getRule();
            try {
                List<String> oriList = getDataFeedService.returnElement(url, rule);
                List<SavedInfo> retList = resolveGetInfoService.returnElement(oriList, ds.getPoster(), ds.getCategory());
                int insertNum = saveNewInfoService.saveNewInfo(retList);
                insLog.add(ds.getPoster() + " Insert " + insertNum + " info success!");
            } catch (Exception e) {
                if (e instanceof UnknownHostException) {
                    e.printStackTrace();
                    return insLog;
                }
                ds.setValid(Boolean.FALSE);
                getDatabaseService.updateDataSource(ds);
                e.printStackTrace();
            }
        }
        return insLog;
    }

    @RequestMapping("/refresh_datasource")
    public void refreshDatasource() {
        for (DataSource ds: getDatabaseService.getAllDataSource()){
            ds.setValid(Boolean.TRUE);
            getDatabaseService.updateDataSource(ds);
        }
    }

    @RequestMapping("/trans_all")
    public List<String> transAll() {
        List<String> transLog = new ArrayList<>();
        resolveGetInfoService.init();
        for (SavedInfo info: saveNewInfoService.getSavedInfo()) {
            if (Objects.equals(info.getMark(), "HW")) {
                continue;
            }
            SavedInfo markedInfo = resolveGetInfoService.updateInfoMark(info);
            if (Objects.equals(markedInfo.getTitlecn(), "No Translation")) {
                try {
                    SavedInfo translatedInfo = resolveGetInfoService.translateInfo(markedInfo);
                    saveNewInfoService.updateSavedInfo(translatedInfo);
                    transLog.add(markedInfo.getTitle() + " => success!\n");
                } catch (Exception e) {
                    markedInfo.setTitlecn(markedInfo.getTitle());
                    saveNewInfoService.updateSavedInfo(markedInfo);
                    transLog.add(markedInfo.getTitle() + " => fail!\n");
                }
            }
        }
        return transLog;
    }
}
