package com.sliverneedle.threatdemo.controller;

import com.sliverneedle.threatdemo.domain.SavedInfo;
import com.sliverneedle.threatdemo.service.*;
import com.sliverneedle.threatdemo.service.impl.GetDjangoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.*;

@RestController
public class SendMessageController {
    @Autowired
    private IResolveGetInfoService resolveGetInfoService;
    @Autowired
    private ISaveNewInfoService saveNewInfoService;

    @RequestMapping("/say")
    public List<SavedInfo> printAns(@RequestParam(value = "point") int point,
                                    @RequestParam(value = "page") int page,
                                    @RequestParam(value = "past") int past) {
        List<SavedInfo> savedInfoList = new ArrayList<>();
        for (SavedInfo info: saveNewInfoService.getNewInfo(past)) {
            if (info.getMark() != null && !Objects.equals(info.getMark(), "UN") && Integer.parseInt(info.getMark()) >= point) {
                savedInfoList.add(info);
            }
        }
        savedInfoList.sort(Comparator.comparing(SavedInfo::getMark).reversed());
        if (page == 0) {
            return savedInfoList;
        } else if (page * 10 - 10 > savedInfoList.size()) {
            return null;
        } else {
            return savedInfoList.subList(page * 10 - 10, Math.min(page * 10, savedInfoList.size()));
        }
    }

    @RequestMapping("/query")
    public int queryPage(@RequestParam(value = "point") int point, @RequestParam(value = "past") int past) {
        int savedInfoLength = 0;
        for (SavedInfo info: saveNewInfoService.getNewInfo(past)) {
            SavedInfo markedInfo = resolveGetInfoService.updateInfoMark(info);
            if (Integer.parseInt(markedInfo.getMark()) >= point) {
                savedInfoLength++;
            }
        }
        return (savedInfoLength + 9) / 10;
    }

    @RequestMapping("/trans")
    public String trans(@RequestParam(value = "trans") String oriWords) throws Exception {
        System.out.println(oriWords);
        return GetDjangoService.GetTranslateAns(oriWords);
    }

    @RequestMapping("/hvvinfo")
    public List<SavedInfo> printHWInfo(@RequestParam(value = "kind") String kind) {
        return saveNewInfoService.getHWInfo(kind);
    }

    @RequestMapping("/hvvaddinfo")
    public int getHWInfo(@RequestBody SavedInfo info) {
        List<SavedInfo> hvvinfo = new ArrayList<>();
        info.setSavetime(new Date());
        info.setLink(Base64.getEncoder().encodeToString(info.getTitle().getBytes(StandardCharsets.UTF_8)));
        hvvinfo.add(info);
        System.out.println(hvvinfo);
        return saveNewInfoService.saveNewInfo(hvvinfo);
    }

    @RequestMapping("/getHotSearchDict")
    public List<String> getHotSearchDict() {
        return resolveGetInfoService.getHotSearchDict();
    }
}
