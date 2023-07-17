# jwtgen

This simple tool generates JWTs for testing purposes. It is useful when you have an API that is secured using the Bearer authentication scheme with JWTs and you want to test it in different scenarios. To use the tool, visit [jwtgen.dev](jwtgen.dev).

This project uses Quarkus, the Supersonic Subatomic Java Framework.

If you want to learn more about Quarkus, please visit its website: https://quarkus.io/ .

## Running the application in dev mode

You can run your application in dev mode that enables live coding using:
```shell script
./mvnw compile quarkus:dev
```

> **_NOTE:_**  Quarkus now ships with a Dev UI, which is available in dev mode only at http://localhost:8080/q/dev/.

## Packaging and running the application

The application can be packaged using:
```shell script
./mvnw package
```
It produces the `quarkus-run.jar` file in the `target/quarkus-app/` directory.
Be aware that it’s not an _über-jar_ as the dependencies are copied into the `target/quarkus-app/lib/` directory.

The application is now runnable using `java -jar target/quarkus-app/quarkus-run.jar`.

If you want to build an _über-jar_, execute the following command:
```shell script
./mvnw package -Dquarkus.package.type=uber-jar
```

The application, packaged as an _über-jar_, is now runnable using `java -jar target/*-runner.jar`.

## Creating a native executable

You can create a native executable using: 
```shell script
./mvnw package -Pnative
```

Or, if you don't have GraalVM installed, you can run the native executable build in a container using: 
```shell script
./mvnw package -Pnative -Dquarkus.native.container-build=true
```

You can then execute your native executable with: `./target/gcloud-functions-test-1.0.0-SNAPSHOT-runner`

If you want to learn more about building native executables, please consult https://quarkus.io/guides/maven-tooling.

## Related Guides

- RESTEasy Reactive ([guide](https://quarkus.io/guides/resteasy-reactive)): A Jakarta REST implementation utilizing build time processing and Vert.x. This extension is not compatible with the quarkus-resteasy extension, or any of the extensions that depend on it.
- Google Cloud Functions HTTP ([guide](https://quarkus.io/guides/gcp-functions-http)): Write Google Cloud functions with HTTP endpoints

## Provided Code

### Google Cloud Functions HTTP Integration examples

Examples of Google Cloud HTTP functions for Quarkus written with RESTEasy (JAX-RS), Undertow (Servlet), Vert.x Web, or Funqy HTTP.

[Related guide section...](https://quarkus.io/guides/gcp-functions-http#creating-the-endpoints)

Inside the `src/main/java/org/acme/googlecloudfunctionshttp` directory, you will find examples for:

- JAX-RS (via RESTEasy): `GreetingResource.java`
- Vert.x reactive routes: `GreetingRoutes.java`
- Funqy HTTP: `GreetingFunqy`
- Servlet (via Undertow): `GreetingServlet.java`

Each of these example uses a different extension.
If you don't plan to use all those extensions, you should remove them from the `pom.xml`.

> :warning: **INCOMPATIBLE WITH DEV MODE**: Google Cloud Functions HTTP is not compatible with dev mode yet!
