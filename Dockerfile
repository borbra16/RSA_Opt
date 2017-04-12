FROM ubuntu:16.04

RUN apt-get update -y && \
 apt-get install -y  maven openjdk-8-jdk

EXPOSE 8090

ADD /target/rsa-0.0.1-SNAPSHOT.war rsa-0.0.1-SNAPSHOT.war
ENTRYPOINT ["java","-jar","rsa-0.0.1-SNAPSHOT.war"]

