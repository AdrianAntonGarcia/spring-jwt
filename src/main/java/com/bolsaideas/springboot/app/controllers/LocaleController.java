package com.bolsaideas.springboot.app.controllers;

import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LocaleController {

    @GetMapping("/locale")
    public String locale(HttpServletRequest request) {
        /**
         * El referer nos entrega la referencia de la última url
         */
        String ultimaUrl = request.getHeader("referer");
        return "redirect:".concat(ultimaUrl);
    }

}
