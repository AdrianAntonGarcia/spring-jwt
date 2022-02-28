package com.bolsaideas.springboot.app.controllers;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Collection;
//import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.core.io.Resource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestWrapper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.bolsaideas.springboot.app.models.entity.Cliente;
import com.bolsaideas.springboot.app.models.service.IClienteService;
import com.bolsaideas.springboot.app.models.service.IUploadFileService;
import com.bolsaideas.springboot.app.util.paginator.PageRender;
import com.bolsaideas.springboot.app.view.xml.ClienteList;

/**
 * Guardamos el objeto cliente en sesión para tener el campo id que no vendría
 * en el formulario
 */
@Controller
@SessionAttributes("cliente")
public class ClienteController {

	private final Log logger = LogFactory.getLog(getClass());

	@Autowired
	@Qualifier("clienteServiceImpl")
	private IClienteService clienteService;

	@Autowired
	private IUploadFileService fileService;

	@Autowired
	private MessageSource messageSource;

	/**
	 * En vez de con el mvcConfig, lo hacemos a través de la respuesta http
	 * 
	 * @param id
	 * @param model
	 * @param flash
	 * @return
	 */
	@Secured({ "ROLE_ADMIN", "ROLE_USER" })
	@GetMapping(value = "/uploads/{filename:.+}")
	public ResponseEntity<Resource> verFoto(@PathVariable String filename) {
		Resource recurso = null;
		try {
			recurso = fileService.load(filename);
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
		return ResponseEntity.ok()
				.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + recurso.getFilename() + "\"")
				.body(recurso);
	}

	@PreAuthorize("hasRole('ROLE_USER')")
	@GetMapping(value = "/ver/{id}")
	public String ver(@PathVariable(value = "id") Long id, Map<String, Object> model, RedirectAttributes flash) {
		Cliente cliente = clienteService.findOneWithFacturas(id);
		if (cliente == null) {
			flash.addAttribute("error", "El cliente no existe en la base de datos");
			return "redirect:/listar";
		}
		model.put("cliente", cliente);

		model.put("titulo", "Detalle cliente: " + cliente.getNombre());
		return "ver";
	}

	/**
	 * 1 forma de hacer controladores rest, la otra es con @RestController
	 * 
	 * @return
	 */
	@GetMapping(value = "/listar-rest")
	public @ResponseBody ClienteList listarRest() {
		return new ClienteList(clienteService.findaAll());
	}

	@RequestMapping(value = { "/listar", "/" }, method = RequestMethod.GET)
	public String listar(@RequestParam(name = "page", defaultValue = "0") int page, Model model,
			Authentication authentication, HttpServletRequest request, Locale locale) {
		/**
		 * Diferentes formas de autenticar
		 */
		if (authentication != null) {
			logger.info("Hola usuario autenticado, tu username es: ".concat(authentication.getName()));
		}
		/**
		 * Como obtener el authentication de manera estática
		 */
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth != null) {
			logger.info("Utlizando forma estática SecurityContextHolder: Hola usuario autenticado, tu username es: "
					.concat(auth.getName()));
		}

		if (hasRole("ROLE_ADMIN")) {
			logger.info("Hola ".concat(auth.getName()).concat(" tienes acceso de administrador"));
		} else {
			logger.info("Hola ".concat(auth.getName()).concat(" NO tienes acceso de administrador"));
		}

		SecurityContextHolderAwareRequestWrapper securityContext = new SecurityContextHolderAwareRequestWrapper(request,
				"ROLE_");
		if (securityContext.isUserInRole("ADMIN")) {
			logger.info("Forma usando SecurityContextHolderAwareRequestWrapper: Hola ".concat(auth.getName())
					.concat(" tienes acceso de administrador"));
		} else {
			logger.info("Forma usando SecurityContextHolderAwareRequestWrapper: Hola ".concat(auth.getName())
					.concat(" NO tienes acceso de administrador"));
		}

		if (request.isUserInRole("ROLE_ADMIN")) {
			logger.info("Forma usando HttpServletRequest: Hola ".concat(auth.getName())
					.concat(" tienes acceso de administrador"));
		} else {
			logger.info("Forma usando HttpServletRequest: Hola ".concat(auth.getName())
					.concat(" NO tienes acceso de administrador"));
		}

		Pageable pageRequest = PageRequest.of(page, 5);
		Page<Cliente> clientes = clienteService.findaAll(pageRequest);
		PageRender<Cliente> pageRender = new PageRender<>("/listar", clientes);
		model.addAttribute("page", pageRender);
		model.addAttribute("titulo", messageSource.getMessage("text.cliente.listar.titulo", null, locale));
		model.addAttribute("clientes", clientes);
		return "listar";
	}

	@Secured("ROLE_ADMIN")
	@RequestMapping(value = "/form")
	public String crear(Map<String, Object> model) {
		Cliente cliente = new Cliente();
		model.put("cliente", cliente);
		model.put("titulo", "Formulario de Cliente");
		return "form";
	}

	/**
	 * El @BindingResult siempre tiene que ir junto al objeto que está validado
	 * con @Valid
	 * 
	 * El @ModelAttribute solo es necesario si el nombre con el que lo pasamos a la
	 * vista en el método anterior es distinto al que le estamos dando (Nombre de la
	 * clase) en el método receptor del form
	 * 
	 * @param cliente
	 * @param result
	 * @return
	 */
	@Secured("ROLE_ADMIN")
	@RequestMapping(value = "/form", method = RequestMethod.POST)
	public String guardar(@Valid @ModelAttribute(value = "cliente") Cliente clienteN, BindingResult result, Model model,
			@RequestParam("file") MultipartFile foto, RedirectAttributes flash, SessionStatus status) {
		if (result.hasErrors()) {
			model.addAttribute("titulo", "Formulario de Cliente");
			return "form";
		}
		if (!foto.isEmpty()) {

			if (clienteN.getId() != null && clienteN.getId() > 0 && clienteN.getFoto() != null
					&& clienteN.getFoto().length() > 0) {
				fileService.delete(clienteN.getFoto());
			}
			String uniqueFilename;
			try {
				uniqueFilename = fileService.copy(foto);
				flash.addFlashAttribute("info", "Has subido correctamente '" + uniqueFilename + "'");
				clienteN.setFoto(uniqueFilename);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		String mensajeFlash = (clienteN.getId() != null) ? "Cliente editado con éxito!" : "Cliente creado con éxito!";
		clienteService.save(clienteN);
		status.setComplete();
		flash.addFlashAttribute("success", mensajeFlash);
		return "redirect:listar";
	}

	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@RequestMapping(value = "/form/{id}")
	public String editar(@PathVariable(value = "id") Long id, Map<String, Object> model, RedirectAttributes flash) {
		Cliente cliente = null;
		if (id > 0) {
			cliente = clienteService.findOne(id);
			if (cliente == null) {
				flash.addFlashAttribute("error", "Cliente no encontrado");
				return "redirect:/listar";
			}
		} else {
			flash.addFlashAttribute("error", "Cliente no encontrado");
			return "redirect:/listar";
		}
		model.put("cliente", cliente);
		model.put("titulo", "Modificar el cliente: ".concat(id.toString()));
		return "form";
	}

	@Secured("ROLE_ADMIN")
	@RequestMapping(value = "/eliminar/{id}")
	public String eliminar(@PathVariable(value = "id") Long id, RedirectAttributes flash) {
		if (id > 0) {
			Cliente clienteEliminar = clienteService.findOne(id);
			clienteService.delete(id);
			flash.addFlashAttribute("success", "Cliente eliminado con éxito!");
			if (fileService.delete(clienteEliminar.getFoto())) {
				flash.addFlashAttribute("info", "Foto eliminada");
			}
		}
		return "redirect:/listar";
	}

	private boolean hasRole(String role) {
		SecurityContext context = SecurityContextHolder.getContext();
		if (context == null) {
			return false;
		}
		Authentication auth = context.getAuthentication();
		if (auth == null) {
			return false;
		}
		Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
		return authorities.contains(new SimpleGrantedAuthority(role));
		// for (GrantedAuthority authority : authorities) {
		// if (role.equals(authority.getAuthority())) {
		// logger.info(
		// "Hola usuario ".concat(auth.getName()).concat(" tu role es
		// ").concat(authority.getAuthority()));
		// return true;
		// }
		// }
		// return false;
	}
}
