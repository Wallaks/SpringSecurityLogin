package com.exemple.SpringSecurityLogin.repository;

import com.exemple.SpringSecurityLogin.model.Role;
import org.springframework.data.repository.CrudRepository;

public interface RoleRepository extends CrudRepository<Role, Long> {
	Role findByRole(String role);
}
