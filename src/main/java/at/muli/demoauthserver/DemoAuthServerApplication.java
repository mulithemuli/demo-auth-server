package at.muli.demoauthserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Basic Spring Authorization Server demo.
 * <p>
 * See README.md for more info and consult the inline comments or javadoc of the beans created here.
 */
@SpringBootApplication
public class DemoAuthServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoAuthServerApplication.class, args);
    }

}
