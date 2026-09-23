# Research notes and provenance

This reference explains where the skill's heuristics came from. It does not replace official documentation and need not be read during every enumeration.

Passive research performed on 2026-09-22.

## Requested sources

### HTB Tabby

`https://0xdf.gitlab.io/2020/11/07/htb-tabby.html`

Integrated reminders:

- the ROOT page may disclose Manager/Host Manager, roles, and configuration paths;
- `manager-script` may exist without `manager-gui`;
- Debian/Ubuntu packages may split `/etc`, `/usr/share`, and `/var/lib` through symlinks;
- application LFI and WAR deployment are distinct from Tomcat enumeration.

### HTB Ophiuchi

`https://0xdf.gitlab.io/2021/07/03/htb-ophiuchi.html`

Integrated reminders:

- service fingerprinting may expose a version;
- `/manager` can coexist with a custom application;
- YAML deserialization is an application or library property, not an automatic consequence of Tomcat;
- callbacks and remote loading are active exploitation, not fingerprinting.

### HTB Seal

`https://0xdf.gitlab.io/2021/11/13/htb-seal.html`

Integrated reminders:

- compare NGINX and Tomcat responses, including redirects, `401`, and `403`;
- exposed configuration or repositories may explain mTLS, proxy behavior, and protected paths;
- different URL parsers create bypass risk;
- a URI constructed to cross that control is a bypass test and requires separate authorization.

### HTB Manage

`https://0xdf.gitlab.io/2025/07/29/htb-manage.html`

Integrated reminders:

- adjacent high Java ports may represent an RMI registry and a secondary JMX endpoint;
- a stub may advertise a different host or port;
- unauthenticated JMX may list MBeans, contexts, and UserDatabase data;
- specialized-tool `enum` modes may test deserialization and print credentials, so they are not passive.

### HTB Feline

`https://0xdf.gitlab.io/2021/02/20/htb-feline.html`

Integrated reminders:

- errors may expose stack traces and versions;
- CVE triage must remove local-only or DoS issues outside the objective and verify the complete prerequisite chain;
- CVE-2020-9484 depends on controlled upload/name, session persistence, path, and gadget; an old banner is insufficient.

### GitHub cheat sheets

- `https://github.com/aw-junaid/bug-bounty/blob/main/resources/cheatsheets/Tomcat%20Security%20Testing.md`
- `https://github.com/six2dez/pentest-book/blob/master/enumeration/webservices/tomcat.md`

They supplied inventories of paths, example applications, Manager, AJP, JMX, and CVEs. Integrated limitations:

- they mix discovery, brute force, and exploitation;
- lists of common credentials do not describe the current secure default;
- claims about defaults and version ranges can age;
- payloads and loops from those documents must never run automatically;
- public credential examples from write-ups were omitted from this skill.

## Primary sources used for correction

- Manager App How-To: `https://tomcat.apache.org/tomcat-11.0-doc/manager-howto.html`
- Host Manager How-To: `https://tomcat.apache.org/tomcat-11.0-doc/host-manager-howto.html`
- Security Considerations: `https://tomcat.apache.org/tomcat-11.0-doc/security-howto.html`
- AJP Connector: `https://tomcat.apache.org/tomcat-10.1-doc/config/ajp.html`
- Monitoring/JMX: `https://tomcat.apache.org/tomcat-11.0-doc/monitoring.html`
- support: `https://tomcat.apache.org/whichversion.html`
- advisories: `https://tomcat.apache.org/security.html`
- NSE documentation: `https://nmap.org/nsedoc/`
- beanshooter: `https://github.com/qtc-de/beanshooter`
- remote-method-guesser: `https://github.com/qtc-de/remote-method-guesser`

Use the branch that matches the target. The `tomcat-11.0-doc` URLs above describe current semantics and may differ from older branches.

## Methodological limitations

- HTB write-ups describe intentionally vulnerable CTF environments and do not estimate real-world prevalence.
- Published output is evidence from the authors' labs, not from the current engagement.
- Web content can change; capture access time and, when needed, the source commit or hash.
- No real target was contacted while this skill was created.
