---
name: s3-public-access-block-review
description: Compare a general-purpose S3 bucket's saved public-access block settings and effective owner-account settings with a documented baseline for direct bucket access.
---

# Review S3 Block Public Access settings

Use this skill when a website administrator has a saved configuration for an S3 origin and needs to check it against a documented baseline. The PentestingEverything AWS guide lists S3 bucket permissions as a review topic. The rules here come from the S3 APIs. [Repository topic](https://github.com/m14r41/PentestingEverything/blob/b48a30b97bf63f77696ff5d3c72fccd80dcf4a77/Cloud%20Pentesting/AWS/README.md#cloud-service-assessment) · [AWS Block Public Access guide](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)

## Input

Use the [gap](examples/gap.json), [pass](examples/pass.json), and [missing account evidence](examples/unknown.json) fixtures as templates. Keep aliases stable across a single review. Record the owner's `policy_ref` and the nonempty list of flags the policy requires to be enabled. A public-content deployment can have a different baseline from a private origin.

| Field | Evidence |
| --- | --- |
| `scope` | Owner-account alias, bucket alias, region and snapshot identifier. Supply `ownership_ref` for the saved inventory that identifies this bucket's owner. Use `bucket_type=general-purpose` and `access_path=direct-bucket` for this comparison. |
| `bucket_evidence` | A saved `s3api.get-public-access-block` operation for this bucket and owner in the same region and snapshot, with an opaque `ref`. The output describes bucket-level settings. [Bucket API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetPublicAccessBlock.html) |
| `account_evidence` | A saved `s3control.get-public-access-block` operation for the owner in the same region and snapshot, with its own reference. Its output includes the account's effective settings and applicable AWS Organizations inheritance. [Account API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_GetPublicAccessBlock.html) |

For a successful operation, put its saved JSON `PublicAccessBlockConfiguration` object inside `response`, as in the fixtures. Preserve boolean values. Omit any flag whose value is unavailable. For a failed operation, omit `response` and provide an error code instead. A failed call or absent record leaves that level unknown. The assessor verifies each export's origin, owner, region and capture window. AWS documents the JSON response shape for both operations. [Bucket example](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-public-access-block.html#examples) · [Account example](https://docs.aws.amazon.com/cli/latest/reference/s3control/get-public-access-block.html#examples)

```sh
python3 scripts/check.py < examples/pass.json
```

## Result

S3 combines the four settings individually across applicable levels. For each flag, a scoped `true` at either level establishes that the combined setting is enabled. Two observed `false` values establish that it is disabled. One `false` with the other level missing yields `null`. An access point can add separate restrictions, so an access-point route returns `unknown`. [AWS Block Public Access rules](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)

Report `pass` when all required flags are enabled. Report `gap` when at least one required flag is demonstrably disabled, and show any unresolved flags alongside it. `unknown` means the supplied scope, policy or evidence could not support a decision. `invalid_input` means the checker rejected the input format. Cite the bucket alias, snapshot, policy and evidence references, and list the exact flags.

Report actual data access as `unknown`. A disabled flag alone does not establish a public grant. For example, `BlockPublicPolicy` controls acceptance of new public policies, while `RestrictPublicBuckets` affects access under existing public policies. Account changes can take time to propagate across regions. These results concern the saved control-plane configuration for one bucket. [AWS flag semantics and propagation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
