# One image with both programs; the command chosen at run time decides which one starts.
# Cryptographic configs and media are NOT copied into the image: they are mounted at run time
# (FAQ 4.6), so changing the configuration never needs a rebuild.

FROM eclipse-temurin:21-jdk AS build
WORKDIR /src
COPY common/ common/
COPY streamproxy/*.java streamproxy/
COPY streamserver/*.java streamserver/
RUN javac --release 21 -d /out/server streamserver/*.java common/*.java \
 && javac --release 21 -d /out/proxy streamproxy/*.java common/*.java

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /out/ /app/
# BouncyCastle, only loaded when a config uses RC6
COPY lib/ /app/lib/
# Mount points: /configs (config pairs) and /media (MP4 files)
VOLUME ["/configs", "/media"]
EXPOSE 8080 8081
