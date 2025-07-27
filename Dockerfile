FROM maven:3.9.6-eclipse-temurin-21-alpine AS builder
WORKDIR /app

COPY hw-5/pom.xml ./hw-5/
COPY hw-5/src ./hw-5/src

COPY ./pom.xml ./hw-5.2/
COPY ./src ./hw-5.2/src

WORKDIR /app/hw-5

RUN mvn install

WORKDIR /app/hw-5.2

RUN mvn package -DskipTests

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=builder /app/hw-5.2/target/*.jar ./app.jar