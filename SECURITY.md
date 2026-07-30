# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/ifBars/UEWorkshopScanner/security/advisories/new).

Include:

- the affected UEWorkshopScanner version or commit;
- operating system and architecture;
- the smallest safe reproduction available;
- expected and observed behavior;
- whether the issue can execute code, escape a resource boundary, bypass a
  blocking rule, or incorrectly produce `allow`.

Do not attach live malware, private Workshop content, proprietary Unreal
assets, decryption keys, or licensed native libraries to a public issue.
Coordinate sample transfer privately after the report is acknowledged.

## Security-sensitive areas

Changes to these surfaces require additional review:

- `vendor/oodle_loader_safe`;
- decoder hashes and release packaging;
- retoc or repak revisions;
- chunk size and completeness handling;
- marker correlation and blocking rules;
- any future parsing of native plugins or Blueprint bytecode;
- any addition of networking, automatic downloads, or update behavior.

## Supported versions

UEWorkshopScanner is pre-release software. Security fixes are applied to the
latest source revision until the first stable release line is established.
