# Loopback-only Ghostcat lab

This fixture reproduces the deliberately vulnerable Tomcat lab described in
the project-referenced [Ghostcat
article](https://medium.com/@deepanshu_khanna/ghostcat-pwn-when-an-old-tomcat-vulnerability-opens-the-org-doors-62406effeed0).
It uses the historical official `tomcat:8.0-jre8` image, pinned to the image
digest validated by the project. The image contains Apache Tomcat 8.0.53 with
an unprotected AJP/1.3 connector and was validated on Linux/amd64; the archived
image may not provide other architectures.

> [!CAUTION]
> This image is obsolete and intentionally vulnerable. Run it only on a
> disposable test host. Both published ports are bound to `127.0.0.1`, and the
> container is attached to an internal Docker network. Do not change either
> boundary on an Internet-connected system.

Start the lab:

```bash
docker compose -f lab/ghostcat/compose.yaml config
docker compose -f lab/ghostcat/compose.yaml up -d
```

Generate a no-traffic plan:

```bash
bin/jerrysrevenge \
  --url http://127.0.0.1:18080 \
  --ghostcat \
  --ajp-host 127.0.0.1 \
  --ajp-port 18009
```

After reviewing and authorizing the exact plan, repeat it with `--execute`.
The default file is `WEB-INF/web.xml`; raw returned bytes are written only to
the mode-`0600` restricted evidence directory. The validation sends four HTTP
discovery requests and one AJP request, with no retry.

Stop and remove the lab container and network when finished:

```bash
docker compose -f lab/ghostcat/compose.yaml down
```

The pinned image remains in the local Docker cache. Remove it separately only
when it is no longer needed. The Compose project does not mount the repository
or a host directory into the vulnerable container.
