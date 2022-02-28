package com.bolsaideas.springboot.app.models.dao;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.springframework.stereotype.Repository;

import com.bolsaideas.springboot.app.models.entity.Cliente;

@Repository("clienteDaoJPAPre")
public class ClienteDaoImplPre implements IClienteDaoPre {

	@PersistenceContext
	private EntityManager em;

	@SuppressWarnings("unchecked")

	@Override
	public List<Cliente> findaAll() {
		return em.createQuery("from Cliente").getResultList();
	}

	@Override
	public Cliente findOne(Long id) {
		return em.find(Cliente.class, id);
	}

	@Override
	public void save(Cliente cliente) {
		if (cliente.getId() != null && cliente.getId() > 0) {
			em.merge(cliente);
		} else {
			em.persist(cliente);
		}
	}

	@Override
	public void delete(Long id) {
		Cliente cliente = findOne(id);
		if (cliente != null)
			em.remove(cliente);
	}
}
