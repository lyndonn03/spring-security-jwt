# spring-security-jwt

A proof of concept that you can use spring security filters to validate jwts for authorization.

To test this project, use your IDE or Text Editor feature for testing, or use `./mvnw test`.

To run this project, just hit the run button on your favorite IDE or Text Editor, or use `./mvnw spring-boot:run`

I used [jjwt](https://github.com/jwtk/jjwt) dependecies to generate and validate simple tokens that has only a subject (which is the username) in its body. To see the implementation, check `JwtsBuilder.java` class.
