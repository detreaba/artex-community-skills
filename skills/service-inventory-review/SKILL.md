---
name: service-inventory-review
description: Compare a saved Nmap XML report for one deployment and network vantage with an owner's approved TCP and UDP listening ports. Use for unexpected listeners and incomplete service-inventory evidence.
---

# Compare a saved service inventory with the approved ports

Use this skill when the owner has a saved Nmap XML report and a baseline for a particular IP address. The checker reads local files using Python 3.9 or newer. Nmap records what its observation point could see at the time of the report. [Nmap XML report format](https://nmap.org/book/output-formats-xml-output.html) · [Nmap port states](https://nmap.org/book/man-port-scanning-basics.html)

## Run the example

```sh
python3 scripts/check.py < examples/gap.json
```

In the [gap example](examples/gap.json), the baseline approves TCP 443. The archived report records an additional open TCP 8443. The result flags that port even though the owner's required observation list only named TCP 443 and 8080. The [pass](examples/pass.json) example records a closed TCP 8080. The [unknown](examples/unknown.json) example lacks a conclusive individual state for that port.

## Use an owner's records

1. Start with an example and replace the two references and scope. Identify the same asset, deployment, IP address and observation vantage in the `policy` and `report` objects. Check the deployment and observation point against the archived records. The XML supplies the matching IP and completion time.
2. In `policy.required`, list the ports that the report must account for, using entries such as `tcp/443` or `udp/443`. In `policy.allowed_open`, list all approved TCP and UDP listeners for this address and vantage. An explicit empty allow-list is valid. Up to 256 entries per list are supported.
3. To read the original XML as a file, omit `report.xml` from the JSON envelope. Run the command below in the extracted skill directory.

```sh
python3 scripts/check.py --xml-file saved-report.xml < policy-and-report.json
```

Use a report up to two MiB. XML 1.x output from a successful Nmap job must identify one matching host with an up state. Named aggregate port ranges are accepted when the protocol, ports and counts agree. An anonymous count of closed ports leaves individual omitted ports unobserved. Internal DTD subsets and external identifiers are rejected. The bare document marker and stylesheet instruction present in Nmap files are accepted without loading a stylesheet. [Nmap XML schema](https://svn.nmap.org/nmap/docs/nmap.dtd)

## Write the client finding

Report the policy and observation references, asset, vantage, completion time and relevant port states. `finished_epoch` is Unix time. A `gap` is an open port outside the supplied allow-list. A `pass` means the required ports had conclusive observations and the saved report identified no unapproved open TCP or UDP port. A permitted port can be closed. Availability requires a separate service requirement.

`unknown` covers filtered, missing and conflicting observations, failed jobs and uncertain scope. When a known gap and missing observations coexist, `status` is `gap` and `coverage` is `partial`. Treat `complete_for_review` as coverage of this baseline and saved report. It cannot establish the state of ports omitted from both, other network vantages, or later deployments. An unexpected listener is a policy discrepancy. Its service identity and vulnerability status require separate evidence.

Paste the checker's JSON result into ARTEX Chat and ask it to explain the policy comparison. The output omits raw XML, application banners, command lines, scripts and unrelated hosts.
