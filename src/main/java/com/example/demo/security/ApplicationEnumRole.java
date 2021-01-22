package com.example.demo.security;

import com.google.common.collect.Sets;

import java.util.Set;

import static com.example.demo.security.ApplicationUserPermission.*;

public enum ApplicationEnumRole {
    STUDENT(Sets.newHashSet()),  // no permission for students so empty
    ADMIN(Sets.newHashSet(COURSE_READ,COURSE_WRITE,STUDENT_READ,STUDENT_READ)); //all permissions for admin

    private final Set<ApplicationUserPermission> permissions;

    ApplicationEnumRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }
}
