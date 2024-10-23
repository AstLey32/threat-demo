package com.sliverneedle.threatdemo.service.impl;

import com.sliverneedle.threatdemo.domain.SavedInfo;
import com.sliverneedle.threatdemo.domain.SavedIoc;
import com.sliverneedle.threatdemo.mapper.SavedInfoMapper;
import com.sliverneedle.threatdemo.mapper.SavedIocMapper;
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
    @Autowired
    private SavedIocMapper savedIocMapper;

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
    public List<SavedInfo> getSavedInfoByKeywords(String keywords) {
        return savedInfoMapper.selectSavedInfo(keywords);
    }

    @Override
    public List<SavedInfo> transSavedIocToSavedInfo(List<SavedIoc> iocs) {
        List<SavedInfo> savedInfoList = new ArrayList<>();
        for (SavedIoc ioc : iocs) {
            SavedInfo savedInfo = new SavedInfo();
            savedInfo.setId(ioc.getId());
            savedInfo.setTitle(ioc.getName());
            savedInfo.setCategory(ioc.getTags());
            savedInfo.setPoster(ioc.getDescription());
            savedInfo.setMark("1");
            savedInfo.setSavetime(ioc.getCreateTime());
            savedInfo.setTitlecn(ioc.getName());
            savedInfoList.add(savedInfo);
        }
        return savedInfoList;
    }

    @Override
    public List<SavedIoc> getSavedIocByName(String name) {
        return savedIocMapper.selectOneIoc(name);
    }

    @Override
    public List<SavedInfo> getHWInfo(String kind) {return savedInfoMapper.selectHWSavedInfo(kind);}

    @Override
    public List<SavedInfo> getNewInfo(int past, int category) {
        String categoryStr = ";";
        switch (category) {
            case 1: categoryStr = "incident"; break;
            case 2: categoryStr = "ransom"; break;
            case 3: categoryStr = "hotsearch"; break;
            case 4: categoryStr = "vuln"; break;
            case 5: categoryStr = "news"; break;
            case 6: return this.transSavedIocToSavedInfo(savedIocMapper.selectAllSavedIoc());
            default: break;
        }
        return savedInfoMapper.selectNewSavedInfo("'" + past + " DAY'", categoryStr);
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
