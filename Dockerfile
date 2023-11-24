FROM maven:3-eclipse-temurin-21-alpine
WORKDIR /opt/app

# to cache dependencies
ADD pom*.xml .
RUN mvn verify --fail-never

# build final JAR
COPY . .
RUN mvn package