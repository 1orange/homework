# syntax=docker/dockerfile:1.7

# Keep the build toolchain separate from the small runtime image.  The exact
# Maven and JDK versions make local and CI builds use the same toolchain while
# leaving the vulnerable pom.xml untouched.
FROM maven:3.9.9-eclipse-temurin-17 AS build

WORKDIR /workspace
COPY pom.xml ./
RUN mvn -B -ntp dependency:go-offline
COPY src ./src
RUN mvn -B -ntp package -DskipTests

# This stage is used by the one-shot inventory-api-test Compose service.  It
# deliberately retains Maven so the host does not need a Java toolchain.
FROM build AS test
RUN groupadd --system app && useradd --system --gid app --create-home app \
    && chown -R app:app /workspace
USER app
CMD ["mvn", "-B", "-ntp", "test"]

FROM eclipse-temurin:17.0.12_7-jre-jammy AS runtime

WORKDIR /app
COPY --from=build /workspace/target/inventory-api-*.jar /app/inventory-api.jar
RUN groupadd --system app && useradd --system --gid app --create-home app \
    && chown -R app:app /app
USER app

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/inventory-api.jar"]
