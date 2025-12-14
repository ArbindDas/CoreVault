# Use Eclipse Temurin JRE 25
FROM eclipse-temurin:25-jre-jammy
LABEL authors="arbinddas"

VOLUME /tmp
COPY target/*.jar app.jar
ENTRYPOINT ["java","-jar","/app.jar"]
