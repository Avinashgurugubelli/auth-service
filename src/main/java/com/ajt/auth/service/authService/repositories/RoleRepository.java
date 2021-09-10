package com.ajt.auth.service.authService.repositories;

import java.util.Optional;

import com.ajt.auth.service.authService.constants.ERole;
import com.ajt.auth.service.authService.models.db.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
	Optional<Role> findByName(ERole name);
}
