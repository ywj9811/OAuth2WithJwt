package com.example.oauth2WithJwt.config.oauth2.provider;

public interface OAUth2UserInfo {
    String getProviderId();
    String getProvider();
    String getEmail();
    String getName();
}