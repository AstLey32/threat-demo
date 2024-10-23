package com.sliverneedle.threatdemo.controller;

import com.sliverneedle.threatdemo.domain.SavedInfo;
import com.sliverneedle.threatdemo.domain.SharedInfo;
import com.sliverneedle.threatdemo.service.*;
import com.sliverneedle.threatdemo.service.impl.GetDjangoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;

@RestController
public class SendMessageController {
    @Autowired
    private IResolveGetInfoService resolveGetInfoService;
    @Autowired
    private ISaveNewInfoService saveNewInfoService;

    @RequestMapping("/message")
    public List<SavedInfo> showMessage(@RequestParam(value = "point") int point,
                                    @RequestParam(value = "page") int page,
                                    @RequestParam(value = "past") int past,
                                    @RequestParam(value = "category" ) int category) {
        List<SavedInfo> savedInfoList = new ArrayList<>();
        for (SavedInfo info: saveNewInfoService.getNewInfo(past, category)) {
            if (info.getMark() != null && Integer.parseInt(info.getMark()) >= point) {
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
    public int queryPage(@RequestParam(value = "point") int point,
                         @RequestParam(value = "past") int past,
                         @RequestParam(value = "category" ) int category) {
        int savedInfoLength = 0;
        for (SavedInfo info: saveNewInfoService.getNewInfo(past, category)) {
            if (info.getMark() != null && Integer.parseInt(info.getMark()) >= point) {
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

    @RequestMapping("/addinfo")
    public int getAddInfo(@RequestBody SavedInfo info) {
        List<SavedInfo> addInfo = new ArrayList<>();
        info.setSavetime(new Date());
        info.setCategory(info.getPoster() + ";" + info.getCategory());
        if (info.getLink().startsWith("http")) {
            info.setPoster("用户录入");
        } else {
            info.setPoster(info.getLink());
            info.setLink(Base64.getEncoder().encodeToString(info.getTitle().getBytes(StandardCharsets.UTF_8)));
        }
        addInfo.add(info);
        System.out.println(addInfo);
        return saveNewInfoService.saveNewInfo(addInfo);
    }

    @RequestMapping("/getHotSearchDict")
    public List<String> getHotSearchDict() {
        return resolveGetInfoService.getHotSearchDict();
    }

    @RequestMapping("/search")
    public List<SavedInfo> getSearchResult(@RequestParam(value="keywords")String keywords) {
        List<SavedInfo> infos = new ArrayList<>(saveNewInfoService.getSavedInfoByKeywords(keywords));
        infos.addAll(saveNewInfoService.transSavedIocToSavedInfo(saveNewInfoService.getSavedIocByName(keywords)));
        return infos;
    }

    @RequestMapping("/share")
    public List<String> getSharedInfo(@RequestParam(value = "history") int fromHistory) {
        List<SharedInfo> sharedInfoList = new ArrayList<>();
        int pastDay = 7;
        if (fromHistory == 101001) {
            for (SavedInfo info: saveNewInfoService.getNewInfo(pastDay, 6)) {
                SharedInfo sharedInfoIoc = new SharedInfo();
                sharedInfoIoc.setId(info.getId());
                sharedInfoIoc.setName(info.getTitle());
                sharedInfoIoc.setDescription(info.getPoster());
                sharedInfoIoc.setLabels(info.getCategory());
                sharedInfoIoc.setType("ioc");
                sharedInfoIoc.setCreated(info.getSavetime());
                sharedInfoList.add(sharedInfoIoc);
            }
        }
        for (SavedInfo info: saveNewInfoService.getNewInfo(pastDay, 0)) {
            if (info.getCategory().contains("copy")) {
                continue;
            }
            SharedInfo sharedInfoReport = new SharedInfo();
            if (info.getTitle().contains("CVE-")) {
                Matcher cve = Pattern.compile("CVE-(2\\d{3})-\\d{4,}").matcher(
                        info.getTitle().replaceAll("-","-").replaceAll("–","-")
                );
                if (cve.find()) {
                    sharedInfoReport.setId(info.getId());
                    sharedInfoReport.setName(cve.group(0));
                    sharedInfoReport.setDescription(info.getTitle());
                    sharedInfoReport.setLabels(info.getCategory());
                    sharedInfoReport.setType("vulnerability");
                    sharedInfoReport.setExternalReferences(info.getLink());
                    sharedInfoReport.setCreated(info.getSavetime());
                    sharedInfoReport.setCreatedByRef(info.getSavetime());
                    sharedInfoList.add(sharedInfoReport);
                } else {
                    System.out.println(info.getTitle());
                }
            } else if (info.getTitle().contains("attack ") || info.getCategory().contains("incident;")) {
                sharedInfoReport.setId(info.getId());
                sharedInfoReport.setName(info.getTitlecn());
                sharedInfoReport.setDescription(info.getTitle());
                sharedInfoReport.setLabels(info.getCategory());
                sharedInfoReport.setType("report");
                sharedInfoReport.setExternalReferences(info.getLink());
                sharedInfoReport.setCreated(info.getSavetime());
                sharedInfoReport.setCreatedByRef(info.getSavetime());
                sharedInfoList.add(sharedInfoReport);
            }
        }
        List<String> sharedInfos = new ArrayList<>();
        if (fromHistory == 111111) {
            String testData1 = "{'id': 3220001, 'name': '202.48.31.1', 'description': '测试数据 IOC', 'external_references': 'null', 'labels': '测试数据;IOC', 'type': 'ioc', 'created': '2024-08-31 00:00:00', 'created_by_ref': None}";
            String testData2 = "{'id': 3220002, 'name': '202.48.31.2', 'description': '测试数据 IOC', 'external_references': 'null', 'labels': '测试数据;IOC', 'type': 'ioc', 'created': '2024-08-31 00:00:00', 'created_by_ref': None}";
            String testData3 = "{'id': 3220003, 'name': '202.48.31.3', 'description': '测试数据 IOC', 'external_references': 'null', 'labels': '测试数据;IOC', 'type': 'ioc', 'created': '2024-08-31 00:00:00', 'created_by_ref': None}";
            sharedInfos.add(testData1);
            sharedInfos.add(testData2);
            sharedInfos.add(testData3);
        } else {
            for (SharedInfo info: sharedInfoList) {
                sharedInfos.add(info.toString());
            }
        }
        try {
            GetDjangoService.SendSharedInfo(sharedInfos);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return sharedInfos;
    }

}
