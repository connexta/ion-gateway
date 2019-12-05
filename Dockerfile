FROM openjdk:11-jre-slim
LABEL maintainer=connexta
LABEL com.connexta.application.name=ion-gateway
ARG JAR_FILE
COPY ${JAR_FILE} /ion-gateway
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/ion-gateway"]
ENV JAVA_TOOL_OPTIONS "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:10050 \
-Dcom.sun.management.jmxremote \
-Dcom.sun.management.jmxremote.port=10040 \
-Dcom.sun.management.jmxremote.rmi.port=10040 \
-Dcom.sun.management.jmxremote.ssl=false \
-Dcom.sun.management.jmxremote.authenticate=false \
-Djava.rmi.server.hostname=0.0.0.0 \
-Dcom.sun.management.jmxremote.local.only=false \
-Djavax.net.debug=all \
-Djavax.net.ssl.trustStore=/certs/demoTruststore.jks \
-Djavax.net.ssl.trustStorePassword=changeit \
-Djavax.net.ssl.trustStoreType=jks \
-Djavax.net.ssl.keyStore=/certs/gateway.jks \
-Djavax.net.ssl.keyStorePassword=changeit \
-Djavax.net.ssl.keyStoreType=jks"