FROM arm64v8/eclipse-temurin:17.0.6_10-jdk-jammy AS builder

ENV WORK /workspace
COPY build.gradle.kts settings.gradle.kts gradlew $WORK/
COPY gradle/ $WORK/gradle
COPY ./src/ $WORK/src

WORKDIR $WORK

RUN apt-get update && apt-get install -y dos2unix
RUN dos2unix gradlew
RUN ./gradlew clean bootJar --parallel -x test --no-daemon

FROM arm64v8/eclipse-temurin:17.0.6_10-jdk-jammy

MAINTAINER dnstlr2933@gmail.com

ARG JAR_FILE=workspace/build/libs/*.jar
COPY --from=builder ${JAR_FILE} app.jar

ENTRYPOINT ["java","-jar","/app.jar"]