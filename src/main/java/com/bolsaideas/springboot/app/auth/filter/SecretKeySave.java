package com.bolsaideas.springboot.app.auth.filter;

import javax.crypto.SecretKey;

public class SecretKeySave {
    private static SecretKey keyJwt;

    public static SecretKey getKeyJwt() {
        return keyJwt;
    }

    public static void setKeyJwt(SecretKey keyJwt) {
        SecretKeySave.keyJwt = keyJwt;
    }

}
