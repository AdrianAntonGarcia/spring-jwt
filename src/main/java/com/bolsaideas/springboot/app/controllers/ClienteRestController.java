package com.bolsaideas.springboot.app.controllers;

import com.bolsaideas.springboot.app.models.service.IClienteService;
import com.bolsaideas.springboot.app.view.xml.ClienteList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/clientes")
public class ClienteRestController {

    @Autowired
    @Qualifier("clienteServiceImpl")
    private IClienteService clienteService;

    @GetMapping(value = "/listar")
    public ClienteList listar() {
        return new ClienteList(clienteService.findaAll());
    }
}
