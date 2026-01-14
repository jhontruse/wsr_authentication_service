package com.jhontruse.wsr_authentication_service.model.record;

import com.fasterxml.jackson.annotation.JsonProperty;

public record JwtResponse(
                @JsonProperty(value = "access_token") String accessToken,
                @JsonProperty(value = "AuthType") String AuthType,
                @JsonProperty(value = "refresh_token") String refreshToken) {

}
