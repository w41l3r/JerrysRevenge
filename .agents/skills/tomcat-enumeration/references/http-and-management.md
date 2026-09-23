# HTTP, Manager, and proxy layers

Use this reference for HTTP(S), Manager/Host Manager, default applications, or reverse proxies.

## Offline analysis first

Search existing artifacts for:

- `Apache Tomcat`, `Apache-Coyote`, `org.apache.catalina`, `org.apache.coyote`, and `JasperException`;
- `JSESSIONID` and route suffixes such as `.node0`, without treating the cookie alone as proof of Tomcat;
- `Server`, `Via`, `X-Powered-By`, absolute redirects, `WWW-Authenticate` realms, and error pages;
- JAR names and versions under `WEB-INF/lib`, manifests, lockfiles, and SBOMs;
- `server.xml`, `web.xml`, `context.xml`, `tomcat-users.xml`, `setenv.*`, systemd units, and Java arguments;
- NGINX, httpd, or HAProxy configuration, especially path rules, mTLS, rewriting, normalization, `proxy_pass`, `proxy_redirect`, and forwarded headers.

Common locations are hypotheses, not guarantees: `$CATALINA_BASE/conf`, `/etc/tomcat*/`, `/var/lib/tomcat*/conf`, `/usr/share/tomcat*/etc`, and `/opt/tomcat/conf`. Packages may use symlinks and separate `CATALINA_HOME` from `CATALINA_BASE`.

## Minimum HTTP probes

The commands below are templates. Replace placeholders with literals, fix evidence files, and obtain approval before execution.

One GET request without following redirects:

```bash
curl --silent --show-error --connect-timeout 5 --max-time 15 \
  --max-redirs 0 --request GET \
  --dump-header '<EVIDENCE_HEADERS>' --output '<EVIDENCE_BODY>' \
  --write-out 'code=%{http_code} remote_ip=%{remote_ip} size=%{size_download} total=%{time_total} redirect=%{redirect_url}\n' \
  'https://<VHOST>:<PORT>/'
```

Use `--insecure` only when approval explicitly accepts bypassing TLS validation, and record that weakening. Do not use `--location` by default: a redirect may leave scope or change scheme, host, and port.

If approved, one normal nonexistent path helps distinguish the error page from real content:

```bash
curl --silent --show-error --connect-timeout 5 --max-time 15 \
  --max-redirs 0 --request GET \
  --dump-header '<EVIDENCE_HEADERS>' --output '<EVIDENCE_BODY>' \
  'https://<VHOST>:<PORT>/.well-known/tomcat-enum-404-<RUN_ID>'
```

Do not send malformed URIs, alternative encodings, or `--path-as-is` as a baseline. Those requests may cross an access control and require specific bypass-validation authorization.

## Short path matrix

Test only approved paths and count every request. One possible initial list is:

```text
/
/docs/
/examples/
/manager/
/manager/html
/manager/text
/manager/status
/manager/jmxproxy
/host-manager/
/host-manager/html
/host-manager/text
```

`/admin/` is primarily historical. Do not recurse or broadly fuzz by default. `http-enum`, Gobuster, Feroxbuster, and large lists produce many requests; request approval with the exact wordlist, extensions, concurrency, depth, total ceiling, and rate.

Interpret responses carefully:

| Response | Safe observation | Do not conclude automatically |
|---|---|---|
| `200` | the path responded | that it is the expected resource; it may be a soft 404 |
| `301/302/307/308` | redirect logic exists | that the destination is in scope or uses the correct scheme |
| `401` plus realm | an authentication challenge exists at that layer | that default credentials exist |
| `403` | some layer denied the request | whether it was proxy, mTLS, Valve, IP, role, or application |
| `404` | the responding layer declared absence | that the backend lacks the context |
| `405` plus `Allow` | the method was rejected and others were advertised | that advertised methods are exploitable |

Compare status, headers, body size and hash, cookies, latency, and page style to separate frontend and backend behavior.

## Fingerprint and version

Useful sources, in approximate strength order:

1. `version.sh`/`version.bat`, a package, or a manifest obtained through authorized local access;
2. supplied inventory, SBOM, or configuration;
3. ROOT footer, docs/release notes, or ErrorReportValve output;
4. stack traces and internal classes;
5. HTTP banners or Nmap version detection;
6. favicon, layout, cookie, and visual heuristics.

Tomcat may expose its version through ROOT pages, docs, listings, and errors, but those can be hidden or customized. Record the exact source and retain spoofing and backports as limitations.

## Manager and Host Manager

Relevant current roles include:

- `manager-gui`: HTML interface;
- `manager-status`: status;
- `manager-script`: text interface and status;
- `manager-jmx`: JMX proxy and status;
- `admin-gui`: Host Manager HTML;
- `admin-script`: Host Manager scripting.

Do not equate access to one role with access to another. A default installation grants Manager roles to no user; “default credential” lists in cheat sheets do not prove an actual configuration.

The text Manager uses `/manager/text/<command>`. `list` is read-only, but it reveals contexts, state, and sessions and creates an authenticated event. For one explicitly approved test, prefer an interactive password prompt rather than putting the value in the command:

```bash
curl --silent --show-error --connect-timeout 5 --max-time 15 \
  --user '<USERNAME>' \
  --dump-header '<RESTRICTED_HEADERS>' --output '<RESTRICTED_BODY>' \
  'https://<VHOST>:<PORT>/manager/text/list'
```

Sanitize usernames, confidential realms, cookies, and responses before reporting. Never grant GUI and script/JMX roles to the same browser workflow; text and JMX interfaces do not have the GUI's CSRF protection.

Treat these as outside default enumeration:

- `deploy`, `undeploy`, `reload`, `start`, `stop`, `save`, and session expiration;
- WAR or JSP upload;
- `set` or `invoke` through the JMX proxy;
- virtual-host, alias, or application creation/removal through Host Manager.

These operations change state and require a rollback plan and separate exploitation authorization.

## Proxy differentials

When a proxy is in front of Tomcat:

1. compare offline how each layer decodes, removes path parameters, normalizes slashes, and selects virtual hosts;
2. identify where authentication, mTLS, and allowlists are enforced;
3. treat redirects that lose HTTPS, host, or port as configuration evidence, not a confirmed bypass;
4. do not contact the backend directly unless it is explicitly in scope;
5. any URI designed to obtain divergent interpretations is a bypass test. Present exactly one variant, expected result, telemetry, and risk before requesting approval.

A proxy `403` and a Tomcat `401` on neighboring routes can reveal control boundaries, but they do not authorize bypassing those controls.
