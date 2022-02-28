package com.bolsaideas.springboot.app.models.dao;

import java.util.List;

import com.bolsaideas.springboot.app.models.entity.Cliente;

public interface IClienteDaoPre {

	public List<Cliente> findaAll();

	public void save(Cliente cliente);

	public Cliente findOne(Long id);

	public void delete(Long id);

}
