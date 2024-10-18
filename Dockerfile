FROM maven:3.9.9-amazoncorretto-17 AS build

COPY src /usr/app/src
COPY pom.xml /usr/app

WORKDIR /usr/app
#RUN mvn -f /usr/app/pom.xml clean package
RUN mvn -f /usr/app/pom.xml clean install -DskipTests -U
# RUN mvn -f /usr/app/pom.xml clean package
FROM openjdk:17
COPY --from=build /usr/app/target/auth-client-0.0.1-SNAPSHOT.jar .
EXPOSE 8040
#ENTRYPOINT ["java","-jar","userscrud-0.0.1-SNAPSHOT.jar"]
ENTRYPOINT ["nohup", "java","-jar","auth-client-0.0.1-SNAPSHOT.jar", "&"]