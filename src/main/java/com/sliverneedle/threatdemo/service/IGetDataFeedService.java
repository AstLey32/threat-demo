package com.sliverneedle.threatdemo.service;

import java.util.List;

public interface IGetDataFeedService {
    List<String> returnElement(String url, String rule) throws Exception;
}
