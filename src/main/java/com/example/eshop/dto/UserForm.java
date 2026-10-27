
package com.example.eshop.dto;

import com.example.eshop.entity.Role;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserForm {

    private Long id;

    private String username;

    private String password;

    private String fullName;

    private String email;

    private String phone;

    private String address;

    private Role role;

    private boolean enabled;
}
