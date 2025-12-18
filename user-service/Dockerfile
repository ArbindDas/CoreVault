## Use Eclipse Temurin JRE 25
#FROM eclipse-temurin:25-jre-jammy
#LABEL authors="arbinddas"
#
#VOLUME /tmp
#COPY target/*.jar app.jar
#ENTRYPOINT ["java","-jar","/app.jar"]


# Use Eclipse Temurin JRE 25
FROM eclipse-temurin:25-jre-jammy
LABEL authors="arbinddas"

# Install curl for JWKS fetching and debugging
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

VOLUME /tmp
COPY target/*.jar app.jar
ENTRYPOINT ["java","-jar","/app.jar"]