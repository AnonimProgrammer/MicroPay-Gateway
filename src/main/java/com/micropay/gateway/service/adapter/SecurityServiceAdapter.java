package com.micropay.gateway.service.adapter;

import com.micropay.gateway.dto.AuthResponse;

public interface SecurityServiceAdapter {

    AuthResponse refreshAccessToken(String userId);
}
