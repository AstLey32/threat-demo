package com.sliverneedle.threatdemo.service.impl;

import com.sliverneedle.threatdemo.domain.SavedInfo;
import com.sliverneedle.threatdemo.mapper.SavedInfoMapper;
import com.sliverneedle.threatdemo.service.ISaveNewInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.TreeSet;
import java.util.stream.Collectors;

@Service
public class SaveNewInfoService implements ISaveNewInfoService {
    @Autowired
    private SavedInfoMapper savedInfoMapper;

    @Override
    public int saveNewInfo(List<SavedInfo> newInfo) {
        if (newInfo.isEmpty()) {
            return 0;
        } else {
            List<SavedInfo> noSameInfo = newInfo.stream().collect(
                    Collectors.collectingAndThen(
                            Collectors.toCollection(() -> new TreeSet<>(Comparator.comparing(SavedInfo::getLink))),
                            ArrayList::new
                    )
            );
            try {
                return savedInfoMapper.createSavedInfoList(noSameInfo);
            } catch (Exception e) {
                System.out.println(noSameInfo);
                e.fillInStackTrace();
                return 0;
            }
        }
    }

    @Override
    public List<SavedInfo> getSavedInfo() {
        return savedInfoMapper.selectAllSavedInfo();
    }

    @Override
    public List<SavedInfo> getHWInfo(String kind) {return savedInfoMapper.selectHWSavedInfo(kind);}

    @Override
    public List<SavedInfo> getNewInfo(int pastDate) {
        return savedInfoMapper.selectNewSavedInfo("'" + pastDate + " DAY'");
    }

    @Override
    public int updateSavedInfo(SavedInfo Info) {
        return  savedInfoMapper.updateSavedInfo(
                Info.getTitle(), Info.getLink(), Info.getPoster(), Info.getCategory(),
                Info.getMark(), Info.getSavetime(), Info.getTitlecn(), Info.getId());
    }
    @Override
    public int updateSavedInfoList(List<SavedInfo> Info) {return  savedInfoMapper.updateSavedInfoList(Info);}
}
