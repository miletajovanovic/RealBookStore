package com.urosdragojevic.realbookstore.controller;

import com.urosdragojevic.realbookstore.audit.AuditLogger;
import org.springframework.security.access.prepost.PreAuthorize;
import com.urosdragojevic.realbookstore.domain.Person;
import com.urosdragojevic.realbookstore.domain.Role;
import com.urosdragojevic.realbookstore.domain.User;
import com.urosdragojevic.realbookstore.repository.PersonRepository;
import com.urosdragojevic.realbookstore.repository.RoleRepository;
import com.urosdragojevic.realbookstore.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpSession;
import java.nio.file.AccessDeniedException;

import java.sql.SQLException;
import java.util.List;

@Controller
public class PersonsController {

    private static final Logger LOG = LoggerFactory.getLogger(PersonsController.class);
    private static final AuditLogger auditLogger = AuditLogger.getAuditLogger(PersonRepository.class);

    private final PersonRepository personRepository;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public PersonsController(PersonRepository personRepository, UserRepository userRepository, RoleRepository roleRepository) {
        this.personRepository = personRepository;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @GetMapping("/persons/{id}")
    @PreAuthorize("hasAuthority('VIEW_PERSON')")
    public String person(@PathVariable int id, Model model, HttpSession session) {
        String csrf = session.getAttribute("CSRF_TOKEN").toString();
        model.addAttribute("CSRF_TOKEN", session.getAttribute("CSRF_TOKEN"));
        model.addAttribute("person", personRepository.get("" + id));
        return "person";
    }

    @GetMapping("/myprofile")
    @PreAuthorize("hasAuthority('VIEW_MY_PROFILE')")
    public String self(Model model, Authentication authentication) {
        User user = (User) authentication.getPrincipal();
        model.addAttribute("person", personRepository.get("" + user.getId()));
        return "person";
    }

    @DeleteMapping("/persons/{id}")
    @PreAuthorize("hasAuthority('UPDATE_PERSON')")
    public ResponseEntity<Void> person(@PathVariable int id) throws AccessDeniedException {
        personRepository.delete(id);
        userRepository.delete(id);
        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = (User)authentication.getPrincipal();

        List<String> userRoles = roleRepository.findByUserId(user.getId()).stream().map(Role::getName).toList();
        
        if ((userRoles.contains("MANAGER") || userRoles.contains("REVIEWER")) && id != user.getId()) {
        	throw new AccessDeniedException("Forbidden");
        }

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/update-person") 
    @PreAuthorize("hasAuthority('UPDATE_PERSON')")
    public String updatePerson(Person person, HttpSession session, @RequestParam("csrfToken") String csrfToken) throws AccessDeniedException {
    	String csrf = session.getAttribute("CSRF_TOKEN").toString();

        if (!csrf.equalsIgnoreCase(csrfToken)) {
            throw new AccessDeniedException("Forbidden"); 
        }
        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = (User)authentication.getPrincipal();
        List<String> userRoles = roleRepository.findByUserId(user.getId()).stream().map(Role::getName).toList();
        
        if ((userRoles.contains("MANAGER") || userRoles.contains("REVIEWER")) && person.getId().equals(Integer.toString(user.getId()))) {
        	throw new AccessDeniedException("Forbidden");
        }

    	personRepository.update(person);
        return "redirect:/persons/" + person.getId();
    }

    @GetMapping("/persons")
    @PreAuthorize("hasAuthority('VIEW_PERSONS_LIST')")
    public String persons(Model model) {
        model.addAttribute("persons", personRepository.getAll());
        return "persons";
    }

    @GetMapping(value = "/persons/search", produces = "application/json")
    @ResponseBody
    public List<Person> searchPersons(@RequestParam String searchTerm) throws SQLException {
        return personRepository.search(searchTerm);
    }
}
