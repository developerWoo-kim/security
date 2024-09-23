package com.gwkim.security.oauth2.core.authentication.userdetails.service;

import com.gwkim.security.oauth2.core.authentication.userdetails.SecurityUser;
import com.gwkim.security.oauth2.core.authentication.userdetails.service.form.SecurityUserSaveForm;

public interface SecurityUserUseCase {
    SecurityUser findById(String username);
    SecurityUser save(SecurityUserSaveForm userSaveForm);
}
