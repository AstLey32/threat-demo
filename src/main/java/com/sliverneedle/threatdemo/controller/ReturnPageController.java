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

    @RequestMapping("/hvv")
    public ModelAndView hvv(){
        return new ModelAndView("hvv.html");
    }

}
