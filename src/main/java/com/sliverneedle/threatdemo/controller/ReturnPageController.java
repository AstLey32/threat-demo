package com.sliverneedle.threatdemo.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@RestController
public class ReturnPageController {
    @RequestMapping("/")
    public ModelAndView say(){
        return new ModelAndView("index.html");
    }

    @RequestMapping("/new")
    public ModelAndView newIndex(){
        return new ModelAndView("new_index.html");
    }

    @RequestMapping("/search_result")
    public ModelAndView searchResult(){
        return new ModelAndView("search.html");
    }

}
