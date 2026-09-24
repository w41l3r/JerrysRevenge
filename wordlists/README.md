# Bundled Tomcat credential candidates

`tomcat-common.txt` is the default Manager credential corpus used when
`--brute` is selected without `--wordlist`.

The list is based on:

- SecLists
  [`Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt`](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt);
- Metasploit
  [`data/wordlists/tomcat_mgr_default_userpass.txt`](https://github.com/rapid7/metasploit-framework/blob/master/data/wordlists/tomcat_mgr_default_userpass.txt);
- a small set of additional weak combinations commonly encountered in labs,
  appliances, and legacy deployments, including `tomcat:root`.

Entries are candidates for authorized validation, not claims about secure
Tomcat defaults. The file is embedded in the compiled binary so installed
builds do not depend on the source tree. Supplying `--wordlist FILE` replaces
this corpus; `--company NAME` adds deterministic organization-derived
candidates to either source. Company-derived candidates are generated in
memory, capped at 512 additions, and are not written to this directory.

The bundled corpus retains all 76 non-comment entries from the installed
SecLists source used during development and adds 37 deduplicated candidates,
for 113 total pairs.
