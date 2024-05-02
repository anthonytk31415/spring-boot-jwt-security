# spring-boot-jwt-security
A Spring Boot security flow equipped with login, authentication, and authorization using JWT tokens. In this standalone app, we create an authentication service that 

1) when the user is not logged in, registration is allowed. 
2) Once the user is logged in, we open access to a set of paths. 
3) We apply a timer for the user to maintain login before the token expires.  

We use a multi layer controller service configuration to organize the app and for separation of concerns. The two main components are: 
1) Authentication
2) Jwt

Java, Spring Boot, and Application Features: 
- Use PostgreSQL to handle security/user storage
- RestController annotaitons to build request mapping 
- JpaRepository to handle PostgreSQL 
- Beans for Dependency Injection and Data Access
- Applies the @Builder annotation to apply Builder pattern using Lombok
- Use @Data Lombok annotaiton for applyinig getters and setters 
- Applies multitude of Roles for different access


To run this: 
- you can fork the repo to your local
- set up a local instance of PostgreSQL, 
- update the application.yml file with your own settings
- run the application and send some requests to test the paths!