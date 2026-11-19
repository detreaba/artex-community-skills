---
name: pillow-patch-review
description: Check whether the Pillow ImageCms native extension loaded by a deployed Python image worker includes the fix for CVE-2026-59205, using offline wheel and worker evidence.
---

# Review a Pillow image worker

Use this for CVE-2026-59205. Pillow reports affected versions through 12.2.0 and lists 12.3.0 as the first fixed release. In a rolling deployment, run one check per worker instance. A newly installed wheel can coexist with an older extension still mapped by a running worker. [Pillow advisory](https://github.com/python-pillow/Pillow/security/advisories/GHSA-9hw9-ch79-4vh6) · [Release notes](https://pillow.readthedocs.io/en/stable/releasenotes/12.3.0.html)

## Prepare the evidence

Use the structure in the [affected example](examples/gap.json). The three records describe the same component from different sources. Use redacted aliases for references.

| Record | What the owner supplies |
| --- | --- |
| `inventory` | `asset`, deployed `build`, and a `worker` instance alias that includes its start or generation. Cite the process inventory in `ref` and record the Pillow release observed in that worker’s Python environment in `version`. Set `deployment_verified` to true when the record identifies the running instance, and `origin` to `upstream` for an unmodified upstream distribution. |
| `wheel` | Cite the original wheel record in `ref`. Set `pypi_verified` to true after comparing the artifact’s SHA-256 with the digest published by PyPI for that exact wheel. Copy `name` and `version` from its `.dist-info/METADATA`. Copy `member` and the complete `sha256=…` field from the `.dist-info/RECORD` row for the native `PIL/_imagingcms` extension. Use the wheel matching the worker’s platform and Python build. |
| `native` | Cite a separate observation of `PIL._imagingcms` loaded by the same `asset`, `build` and `worker`. For `binding: "mapped_file"`, supply the 64-digit hexadecimal SHA-256 of the actual file object mapped by that process. A package directory or a hash of the file currently at a pathname can describe a replacement after an upgrade. |

An immutable deployment can use `binding: "immutable_image"`. Set `immutable_start_verified` to true only if the observation ties this worker’s start to the exact immutable image and confirms the loaded module came from its unchanged filesystem. Supply the digest of that module from the image. A desired rollout revision, a mutable mount shadowing the extension, or an older worker with the same service name leaves this binding unverified. [Fixed example](examples/pass.json) · [Wheel specification](https://packaging.python.org/en/latest/specifications/binary-distribution-format/)

## Run and interpret

Run the checker locally from the unpacked skill directory with Python 3.9 or later. The command reads the supplied record from stdin.

```sh
python3 scripts/check.py < examples/gap.json
```

In ARTEX Chat, request the checker result and its three evidence references. Report the worker, build, `patch_status` and `patch_reason`. For `affected_version`, give 12.3.0 as the first fixed release. For `vendor_fix_present`, identify the release matched by the loaded extension. For `unknown`, request the missing or conflicting observation named in the reason. In the [in-place upgrade example](examples/unknown.json), the version record shows 12.3.0 while the worker’s mapped extension has different bytes.

Reviewed affected wheels are 11.0.0, 11.1.0, 11.2.1, 11.3.0, 12.0.0, 12.1.0, 12.1.1 and 12.2.0. Reviewed fixed wheels are 12.3.0 and 13.0.0. Other releases, local or distribution builds and missing native-module evidence yield `unknown`. The `applicability` field stays `unknown` because loading ImageCms establishes only component presence. Assessing application use of its affected operation requires separate evidence. [PyPI release history](https://pypi.org/project/pillow/#history)
