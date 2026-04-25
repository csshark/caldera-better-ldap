# caldera-better-ldap
Better LDAP handler that supports AD structure in companies. 

Almost 80% of companies use Active Directory (AD) implementation. MITRE Caldera does not support such environment by default - that is what made me create such handler and create enterprise-grade login handler jus like you would do this in commercial products. 

<details>
<summary><b>Show parameters how-to table</b></summary>

| Key | Description | Example | How to Use |
|-----|------------|--------|------------|
| ldap.dn | Base Distinguished Name used as the root for LDAP searches | `DC=somecompany,DC=pl` | Set this to the root of your directory tree where users are located |
| ldap.server.host | Address of the LDAP/AD server | `ad01.somecompany.pl` | Use FQDN or IP of your domain controller |
| ldap.server.port | LDAP port | `389` or `636` | Use `389` for LDAP, `636` for LDAPS |
| ldap.server.use_ssl | Enables secure LDAP (LDAPS) | `true` / `false` | Set to `true` when using LDAPS (recommended in production) |
| ldap.server.timeout | Connection timeout in seconds | `10` | Adjust depending on network latency |
| ldap.bind.user | Service account DN used for querying LDAP | `CN=CalderaService,...` | Must be a valid DN with permission to search users and groups |
| ldap.bind.password | Password for service account | `SuperSecret` | Store securely (env variable or secret manager recommended) |
| ldap.user.attribute | Attribute used to identify users | `sAMAccountName` | Common values: `sAMAccountName`, `uid`, `userPrincipalName` |
| ldap.user.search_filter | Template for LDAP search filter | `({attr}={username})` | Customize search logic; `{attr}` and `{username}` are dynamically replaced |
| ldap.group.attribute | Attribute storing group membership | `memberOf` | Usually `memberOf` in Active Directory |
| ldap.group.match | Strategy for matching groups | `contains` / `exact` / `startswith` | Controls how group names are compared |
| ldap.access_control.required_groups | Mapping of app roles to LDAP groups | `red: "CN=CalderaRED"` | Define which LDAP groups grant access and assign roles |

</details>

<details>
<summary><b>Show example yml config</b></summary>

```yml
ldap:
  dn: DC=somecompany,DC=pl

  server:
    host: ad01.somecompany.pl
    port: 389
    use_ssl: false
    timeout: 10

  bind:
    user: CN=CalderaServiceAcc,OU=FILLME,OU=FILLMEH,DC=somecompany,DC=pl
    password: SUPER_SECRET

  user:
    attribute: sAMAccountName
    search_filter: "({attr}={username})"

  group:
    attribute: memberOf
    match: contains

  access_control:
    required_groups:
      red: "CN=CalderaRED"
      blue: "CN=CalderaBLUE"
```
</details>

# Installation 

1. Clone repo
<pre><code>git clone https://github.com/csshark/caldera-better-ldap.git</code></pre>
2. Move files
<pre><code>cd caldera-better-ldap
mv ldap.py your/path/to/caldera/app/service/login_handlers/
</code></pre>
3. Ensure to change handler in your yml:
`auth.login.handler.module:` `ldap`

## Contribution & Licensing Notice
Author: csshark

This LDAP authentication module enhancement was originally developed by Robert Strzoda as an independent improvement to the existing authentication mechanism.

The code is contributed to the project as an open-source contribution and is intended to be used, modified, and distributed under the same license as the parent project.

By submitting this contribution, the author grants the project maintainers and users the right to:
- use the code in commercial and non-commercial environments
- modify and adapt the implementation
- redistribute it as part of the project or derivative works

No additional restrictions are imposed beyond those defined by the project's original license.
