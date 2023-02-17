package com.example.oauth2WithJwt.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Response {
    private Object result;
    private String message;
    private int code;

    public Response(int code, String message) {
        this.code = code;
        this.message = message;
    }
}
