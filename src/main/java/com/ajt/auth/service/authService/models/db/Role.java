package com.ajt.auth.service.authService.models.db;

import com.ajt.auth.service.authService.constants.ERole;
import lombok.Data;

import javax.persistence.*;

@Data
@Entity
@Table(name = "roles")
public class Role {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer id;

	@Enumerated(EnumType.STRING)
	@Column(length = 20)
	private ERole name;

	public Role() {
	}

	public Role(ERole name) {
		this.name = name;
	}
}
