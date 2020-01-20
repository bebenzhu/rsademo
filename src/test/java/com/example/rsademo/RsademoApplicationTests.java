package com.example.rsademo;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

@SpringBootTest
class RsademoApplicationTests {

    @Test
    void contextLoads() throws InvalidKeySpecException, NoSuchAlgorithmException {
        String data = "高鹏辉是傻叉！！！";

        Map<String, String> keyPairMap = RSAUtils.createKeys(1024);
        //公钥
        String publicKeyStr = keyPairMap.get("publicKey");
        System.out.println("公钥:"+publicKeyStr);
        //私钥
        String privateKeyStr = keyPairMap.get("privateKey");
        System.out.println("私钥:"+privateKeyStr);

        String encryptData = RSAUtils.publicEncrypt(data, RSAUtils.getPublicKey(publicKeyStr));
        System.out.println("加密后数据:"+encryptData);

        String decryptData = RSAUtils.privateDecrypt(encryptData, RSAUtils.getPrivateKey(privateKeyStr));
        System.out.println("解密后数据:"+decryptData);
    }

}
