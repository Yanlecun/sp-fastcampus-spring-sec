package com.sp.fc.web.controller;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Slf4j
public class SecurityMessage {
    private Authentication auth;
    private String message;

}
