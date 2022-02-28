package com.bolsaideas.springboot.app.view.json;

import java.util.Map;

import com.bolsaideas.springboot.app.models.entity.Cliente;

import org.springframework.data.domain.Page;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

@Component("listar")
@SuppressWarnings("unchecked")
public class ClienteListJsonView extends MappingJackson2JsonView {

    @Override
    protected Object filterModel(Map<String, Object> model) {
        model.remove("titulo");
        model.remove("page");
        Page<Cliente> clientes = (Page<Cliente>) model.get("clientes");
        model.remove("clientes");
        model.put("clienteList", clientes.getContent());
        return super.filterModel(model);
    }

}
