# AJP, RMI/JMX, Jolokia, and the Java application

Use this reference when non-HTTP ports, Java management endpoints, or application behavior are in scope.

## Service discovery

Ports are clues, not identities. AJP often appears on `8009`, RMI on `1099`, and Tomcat HTTP on `8080`, but all can use arbitrary ports. An RMI registry may advertise a dynamic secondary endpoint or even a loopback address that a remote client cannot reach.

A targeted version scan is preferable to a high-rate full-port scan. This template still sends multiple probes and requires approval:

```bash
nmap -n -Pn -sT -sV --version-light --reason --open \
  -p '<PORT1>,<PORT2>,<PORT3>' \
  -oA '<EVIDENCE_PREFIX>' '<TARGET>'
```

Do not use `-sC`, `-A`, `-p-`, `--min-rate`, or broad NSE categories without reviewing every probe and obtaining approval for the volume and behavior.

## AJP

A reachable AJP port confirms protocol exposure; it does not confirm Ghostcat or the absence of a shared credential. In current versions, the AJP connector must be configured explicitly, binds to loopback by default, and has `secretRequired` set to `true`. Older systems and custom configurations differ.

After approval, use only named scripts and paths. Examples of one scripted AJP request:

```bash
nmap -n -Pn -p '<AJP_PORT>' --script ajp-auth \
  --script-args 'ajp-auth.path=/' -oN '<EVIDENCE_FILE>' '<TARGET>'
```

```bash
nmap -n -Pn -p '<AJP_PORT>' --script ajp-headers \
  --script-args 'ajp-headers.path=/' -oN '<EVIDENCE_FILE>' '<TARGET>'
```

```bash
nmap -n -Pn -p '<AJP_PORT>' --script ajp-methods \
  --script-args 'ajp-methods.path=/' -oN '<EVIDENCE_FILE>' '<TARGET>'
```

Despite Nmap's `safe` category, these operations generate traffic and can appear in firewall, IDS, and connector logs. Do not use `ajp-request` for confidential paths, `ajp-ghostcat`, or file-read/include PoCs as enumeration. Reading `WEB-INF/web.xml`, classes, configuration, or credentials through AJP is exploitation and data acquisition and requires separate authorization.

Record:

- the protocol actually identified;
- reachability from the authorized source;
- path, method, and response;
- indicators that a shared credential is required;
- known version and configuration;
- missing prerequisites for any CVE hypothesis.

## RMI and JMX

The RMI registry and JMX endpoint are separate components. Limited registry enumeration, still active and approval-dependent, can be performed with:

```bash
nmap -n -Pn -p '<RMI_REGISTRY_PORT>' --script rmi-dumpregistry \
  -oN '<EVIDENCE_FILE>' '<TARGET>'
```

Capture bound names, stub classes, and advertised `@host:port` values. Do not assume the secondary port is in scope or that an internal address may be bypassed.

Tools such as `remote-method-guesser` and `beanshooter` combine discovery with deserialization checks, MBean enumeration, and possible username/password extraction. Before using them:

1. fix the JAR version and SHA-256;
2. consult `--help` and documentation for the installed version;
3. list every subprobe in the selected mode;
4. explain that pre-auth checks may send serialized objects;
5. obtain specific approval;
6. route any discovered credential material directly to restricted storage.

Do not treat `beanshooter enum` as passive reading. Depending on the version, it checks unauthenticated access, deserialization behavior, lists MBeans, and may print values from `MemoryUserDatabaseMBean`.

Outside default enumeration:

- JMX brute force;
- writable `attr` operations, `invoke`, `deploy`, `undeploy`, `model`, `mlet`, `standard`, `stager`, or TonkaBean;
- command execution, upload/download, or shell access;
- RMI registry manipulation;
- deserialization payloads.

These operations may alter the JVM, create MBeans, trigger remote loading, or execute code.

## JMX over HTTP and Jolokia

`/manager/jmxproxy` belongs to Manager and requires `manager-jmx`. Tomcat documentation describes this as a low-level administrative interface with power comparable to root within Tomcat. A query may be read-only, while `set` and `invoke` change state.

Jolokia may appear at `/jolokia`, `/actuator/jolokia`, or a custom path. A Spring or Java application does not prove Jolokia is present. Broad MBean enumeration can expose configuration and credentials; count and approve exact endpoints before querying.

## Hosted application

Tomcat indicates a Java ecosystem, not a vulnerable library. Separate:

- container vulnerabilities;
- deployment, Manager, or connector misconfiguration;
- application or library vulnerabilities;
- combined primitives such as upload plus a known path plus deserialization.

Examine `WEB-INF/web.xml`, JARs, manifests, error messages, forms, and upload flows offline. A YAML parser on Tomcat does not prove unsafe SnakeYAML; an upload does not prove execution; `JSESSIONID` does not prove file-backed persistence.

Tests that cause DNS/HTTP callbacks, JAR or class loading, gadget chains, cookie traversal, JSP processing, or command execution are exploitation. Do not use them to “confirm quickly” during enumeration.
