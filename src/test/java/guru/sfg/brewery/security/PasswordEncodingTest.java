package guru.sfg.brewery.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.DigestUtils;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class PasswordEncodingTest {
    private static final String PASSWORD = "password";


    @Test
    void noop() {
        PasswordEncoder encoder = NoOpPasswordEncoder.getInstance();
        System.out.println(encoder.encode(PASSWORD));
    }

    @Test
    void ldap() {
        PasswordEncoder encoder = new LdapShaPasswordEncoder();
        System.out.println(encoder.encode(PASSWORD));
        System.out.println(encoder.encode(PASSWORD));

        assertTrue(encoder.matches(PASSWORD, encoder.encode(PASSWORD)));
    }


    @Test
    void hashingExample() {
        System.out.println(DigestUtils.md5Digest(PASSWORD.getBytes()));
        System.out.println(DigestUtils.md5Digest(PASSWORD.getBytes()));

        String salted = PASSWORD + "Salt Vaue:";

        System.out.println(DigestUtils.md5Digest(salted.getBytes()));
        System.out.println(DigestUtils.md5Digest(salted.getBytes()));
    }
}
