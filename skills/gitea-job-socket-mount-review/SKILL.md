---
name: gitea-job-socket-mount-review
description: Check whether a saved Linux Docker mount record for one Gitea Actions job container exposes the host daemon socket identified by its owner.
---

# Review a Gitea job container's socket mounts

Use this reader when an owner prohibits mounting one identified daemon socket in a Gitea Actions job container. It accepts saved administrative records and returns the evidence references and one-based mount rows behind its decision. Its scope is the recorded mounts for that job, build and capture. Service containers, the runner process, network access and later job executions require their own evidence. [Gitea job and service containers](https://docs.gitea.com/runner/jobs/) · [Docker bind mounts](https://docs.docker.com/engine/storage/bind-mounts/)

Run the reader with Python 3.9 or later. The sample contains a read-only bind of the protected object in a partial export.

```sh
python3 scripts/check.py < examples/gap.json
```

## Prepare the saved records

Use opaque identifiers and evidence references consistently across the records. Preserve the path spelling and component relationships needed for comparison. Paths in the examples are invented. If a field has been redacted, use JSON `null`. A repeated text placeholder such as `REDACTED` cannot establish identity.

| Input | Evidence it represents |
| --- | --- |
| `job` | The Gitea execution record binds `id`, `runner`, `container`, `build` and `daemon`. Put its reference in `ref`. Use the identity of the actual job container. |
| `inspect` | Wrap the saved Docker container inspection with its `ref`, `kind: "container_inspect"`, `subject: "job"`, `os: "linux"` and the associated `job`, `runner`, `build` and `daemon`. Preserve the native `Id` and `Mounts` array, including order and additional fields. If identifiers are aliased, use the same one-to-one mapping in both records. Set `coverage` to `complete` for an unfiltered array from that capture, or `partial` otherwise. An independently saved `total` is optional. A larger total establishes a partial export. A total smaller than the array makes the capture inconsistent. [Docker MountPoint fields](https://github.com/moby/moby/blob/89c5e8fd66634b6128fc4c0e6f1236e2540e46e0/api/types/container/container.go#L62-L102) |
| `policy` | Supply the owner's rule `ref` and `socket_ref` for the protected socket's identity on that `daemon` at that `inspect_ref`. Supply `socket_object` as an opaque identity for the actual filesystem object during this capture. Map equal observed objects to the same identifier, including aliases. Use the resolved host paths in `socket_paths`. Set `aliases_complete` to true only when the saved evidence accounts for alternate names and bind aliases relevant to the mounted trees. A client-machine path cannot identify an object on a different daemon host. [Daemon-side bind sources](https://docs.docker.com/engine/storage/bind-mounts/#considerations-and-constraints) |
| `backing` | A separate saved record of what the job's mounts actually presented at that instant. Include `ref`, `daemon` and `inspect_ref`. For each observed mount, copy its native `Type`, `Source` and `Destination` into `mounts`. The reader joins on those fields. A same-capture backing row missing from an otherwise complete mount array requires reconciliation. A copied Docker source string alone cannot establish the backing object. |

For a file bind or a resolved volume file, set `kind` to `file` and `object` to the identity of the file actually mounted in the job. An object retained by the mount may differ from the object currently named by the source pathname. For a directory, set `kind` to `directory` and `canonical` to the resolved effective host backing directory. Set `tree_complete` to true only when the record establishes that the source subtree is faithfully represented for this comparison, including relevant submounts, volume subpaths, propagation, masking and any additional host backing. An unresolved storage-driver location leaves a volume unassessed. A tmpfs row can use `kind: "private"` and `tree_complete: true` when the saved view establishes private backing. [Recursive bind mounts](https://docs.docker.com/engine/storage/bind-mounts/#recursive-mounts) · [Docker volume storage and drivers](https://docs.docker.com/engine/storage/volumes/)

The reader compares absolute Linux paths by whole components. For a possible parent mount, a partial array, an unknown destination or a separate mount below that destination leaves the parent unresolved. An effective file-object observation can still establish a direct match. File permissions and Docker's `RW` flag do not affect a rule prohibiting the mount itself. Limits are 1 MiB of UTF-8 JSON, 1,024 rows per mount list and 64 protected paths.

## Interpret the result

| Status | What the operator can report |
| --- | --- |
| `gap` | A listed row mounts the same protected object or a verified parent directory. Report the basis and the row number. A confirmed direct match can stand alongside other unresolved rows. [Direct read-only bind](examples/gap.json) |
| `pass` | The complete, attributed export and resolved backing exclude the protected socket from the recorded mounts. A verified empty mount array can also satisfy this rule. [Resolved sibling directory](examples/pass.json) |
| `unknown` | Use `reason` and the row-level `unresolved` list to identify the missing assignment, object, tree, alias or coverage evidence. [Volume with unresolved backing](examples/unknown.json) |

Cite the returned references alongside the result in ARTEX. Correct the JSON structure, duplicate keys or input size if the reader returns `invalid_input` with exit code 2.
