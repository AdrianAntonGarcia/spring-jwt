package com.bolsaideas.springboot.app.auth;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class SimpleGrantedAuthoritiesMixin {

    /**
     * El constructor de SimpleGrantedAuthorities no tiene constructor vacío, por lo
     * que tenemos que mapear los
     * roles del header y pasarlos al contstructor de esa clase
     * 
     * @param role
     */
    @JsonCreator
    public SimpleGrantedAuthoritiesMixin(@JsonProperty("authority") String role) {
    }

}
