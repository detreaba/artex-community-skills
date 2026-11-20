---
name: pillow-patch-review
description: Check the Pillow ImageCms wrapper and native extension used by a deployed Python worker against the upstream wheel for CVE-2026-59205.
---

# Review a Pillow image worker

Use this for CVE-2026-59205. Pillow identifies affected versions through 12.2.0 and the first fixed release as 12.3.0. The fix is in the public Python wrapper `PIL/ImageCms.py`. Its native extension helps identify the wheel loaded by one worker. A mixed package directory or an in-place upgrade can leave the two components at different releases. [Pillow advisory](https://github.com/python-pillow/Pillow/security/advisories/GHSA-9hw9-ch79-4vh6) · [Release notes](https://pillow.readthedocs.io/en/stable/releasenotes/12.3.0.html) · [Tagged wrapper](https://github.com/python-pillow/Pillow/blob/12.3.0/src/PIL/ImageCms.py)

## Prepare the evidence

Use redacted aliases for one worker generation. Both module observations must refer to that generation and to the same loaded `PIL` directory. Give that directory one unambiguous alias in both `package_dir_ref` fields. [Affected example](examples/gap.json)

| Record | What the owner supplies |
| --- | --- |
| `inventory` | `asset`, deployed `build`, and a `worker` instance alias that includes its start or generation. Cite the process inventory in `ref` and record the Pillow release observed in that worker’s Python environment in `version`. Set `deployment_verified` to true when the record identifies the running instance, and `origin` to `upstream` for an unmodified upstream distribution. |
| `wheel` | Cite the original wheel record in `ref`. Set `pypi_verified` to true after comparing the artifact’s SHA-256 with the digest published by PyPI for that exact wheel. Copy `name` and `version` from its `.dist-info/METADATA`. Copy the native `PIL/_imagingcms` member and its complete RECORD hash into `member` and `record_hash`. Copy the hash from the `PIL/ImageCms.py` row of that same RECORD into `wrapper_record_hash`. Both hashes start with `sha256=`. |
| `native` | Cite a separate observation of `PIL._imagingcms` loaded by the same `asset`, `build` and `worker`. For `binding: "mapped_file"`, supply the 64-digit hexadecimal SHA-256 of the actual file object mapped by that process. A package directory or a hash of the file currently at a pathname can describe a replacement after an upgrade. |
| `wrapper` | Cite the import observation in `ref`, identify `PIL.ImageCms` in `module`, and supply `asset`, `build`, `worker`, `package_dir_ref`, `binding` and the hexadecimal source `sha256`. Use `imported_source` only when trusted import-time evidence identifies the source bytes actually executed by this worker. A current path hash, a module name or an unverified bytecode cache leaves that question open. |

Use raw member bytes for both digests. The checker compares the wrapper against published wheel bytes for that release and native suffix. Windows wrappers in the reviewed wheels use CRLF and Linux and macOS wrappers use LF. A text-mode read can change the digest. Several older releases share identical wrapper bytes, so the independent native and wheel records are still required. On a mapped native file, the verdict relies on the import-time attestation that this worker executed the supplied wrapper bytes. [PyPI 12.3.0 files](https://pypi.org/project/pillow/12.3.0/#files) · [PyPI 13.0.0 files](https://pypi.org/project/pillow/13.0.0/#files)

A verified immutable deployment can use `binding: "immutable_image"` on both module observations. Set `native.immutable_start_verified` to true when the record ties this worker’s start and both import origins to the unchanged image. Verify that the worker executed the recorded wrapper source, including the provenance of any cached bytecode. Supply both member digests from the image. Mutable overlays, inconsistent caches, a different import directory or a desired rollout revision leave the result open. [Fixed example](examples/pass.json) · [Wheel specification](https://packaging.python.org/en/latest/specifications/binary-distribution-format/)

## Run and interpret

Run the checker locally from the unpacked skill directory with Python 3.9 or later. The command reads the supplied record from stdin.

```sh
python3 scripts/check.py < examples/gap.json
```

In ARTEX Chat, report the worker, build, `patch_status`, `patch_reason` and the four evidence references. For `affected_version`, give 12.3.0 as the first fixed release. For `vendor_fix_present`, identify the release matched by both components. For `unknown`, request the evidence named in the reason. Older native-only records remain readable and give `unknown`. In the mixed-install example, the worker has a matching fixed native extension and an older wrapper. [Mixed-install example](examples/unknown.json)

Reviewed affected wheels are 11.0.0, 11.1.0, 11.2.1, 11.3.0, 12.0.0, 12.1.0, 12.1.1 and 12.2.0. Reviewed fixed wheels are 12.3.0 and 13.0.0. Other releases and local or distribution builds yield `unknown`. The result describes the public wrapper in one worker. Application use of its operations and direct calls to the private extension require separate evidence. `applicability` stays `unknown`. [PyPI release history](https://pypi.org/project/pillow/#history)
