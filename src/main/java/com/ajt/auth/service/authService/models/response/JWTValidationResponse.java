package com.ajt.auth.service.authService.models.response;

public class JWTValidationResponse {
	private boolean isValid;

	public JWTValidationResponse(boolean isValid) {
		this.isValid = isValid;
	}
}
