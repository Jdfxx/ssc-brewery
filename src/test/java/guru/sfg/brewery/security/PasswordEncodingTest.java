package guru.sfg.brewery.security;

import org.junit.jupiter.api.Test;
import org.springframework.util.DigestUtils;

public class PasswordEncodingTest {
    private static final String PASSWORD = "password";

    @Test
    void hashingExample() {
        System.out.println(DigestUtils.md5Digest(PASSWORD.getBytes()));
        System.out.println(DigestUtils.md5Digest(PASSWORD.getBytes()));

        String salted = PASSWORD + "Salt Vaue:";

        System.out.println(DigestUtils.md5Digest(salted.getBytes()));
        System.out.println(DigestUtils.md5Digest(salted.getBytes()));
    }
}
