---
name: kubernetes-privileged-container-review
description: Review privileged mode in regular, init and ephemeral containers from one saved, admitted Linux Kubernetes Pod. Use for a scoped Pod Security Standards Baseline control.
---

# Review privileged mode for one Linux Pod

The PentestingEverything container assessment identifies privileged containers as a runtime-configuration review topic. The Kubernetes Baseline standard covers `securityContext.privileged` on regular, init and ephemeral containers. For this field, Baseline permits false or unset. The API defaults an unset value to false. [Repository topic](https://github.com/m14r41/PentestingEverything/blob/b48a30b97bf63f77696ff5d3c72fccd80dcf4a77/Container%20%26%20Kubernetes%20%20Assessment/README.md) · [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline) · [Kubernetes Pod API](https://kubernetes.io/docs/reference/kubernetes-api/core/pod-v1/)

Use an owner-supplied export for one persisted `apiVersion: v1`, `kind: Pod` object. Its `spec.os.name` must explicitly declare `linux`. Copy the expected cluster alias, namespace, Pod name, UID and resourceVersion to `scope`. The cluster alias in `evidence` identifies the export's source. Treat the resourceVersion as an opaque string. A recreated Pod needs a new UID and a later revision needs a new observation. [Kubernetes object identity](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#uids) · [Resource versions](https://kubernetes.io/docs/reference/using-api/api-concepts/#resource-versions)

Use `api-server-get` for a saved server read or `persisted-admission-response` for the saved final API-server Pod returned by a successful, persisted create or update. A proposed manifest, controller template, dry-run result or webhook decision leaves admission unverified. Supply an opaque `ref` for the saved export. Include only the metadata, OS and container records needed for the comparison. Omit environment values and unrelated fields.

Set `privilege_fields_complete` to true only if all entries in `spec.containers`, `spec.initContainers` and `spec.ephemeralContainers`, along with each name and original privileged setting, survived capture and redaction. The latter two lists may genuinely be absent. Kubernetes requires at least one regular container. A missing or empty regular list cannot produce a pass. Ephemeral containers can be added to a running Pod, so the recorded resourceVersion matters. [Pod API](https://kubernetes.io/docs/reference/kubernetes-api/core/pod-v1/) · [Ephemeral containers](https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/)

```sh
python3 scripts/check.py < examples/gap.json
```

The [gap example](examples/gap.json) includes a privileged ephemeral container alongside an ordinary web container. The [pass example](examples/pass.json) includes an explicitly false value and a genuinely unset field. The [partial export](examples/unknown.json) shows why a list of ordinary containers alone is insufficient. Each embedded Pod was validated against the published core/v1 schema for Kubernetes v1.35.0. [Upstream OpenAPI schema](https://github.com/kubernetes/kubernetes/blob/v1.35.0/api/openapi-spec/v3/api__v1_openapi.json)

Report `gap` for any identified container explicitly requesting privileged mode. An incomplete export can still establish this finding. Report `pass` when a complete export satisfies this single Baseline control. `unknown` covers insufficient evidence, a Windows or unspecified OS, or a mismatch in identity or revision. Correct an `invalid_input` response before reporting results. In the client report cite the evidence reference, UID, resourceVersion, container list and name. Namespace-wide admission enforcement, the runtime state of individual containers and overall Pod Security Standards compliance require separate evidence.
