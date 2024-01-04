package com.example.demo.model.response;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;

public class ErrorRes {
    private HttpStatus httpStatus;
    private String message;

    public ErrorRes(HttpStatus httpStatus, String message) {
        this.httpStatus = httpStatus;
        this.message = message;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public void setHttpStatus(HttpStatus httpStatus) {
        this.httpStatus = httpStatus;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
