---
name: zyxel-firewall-firmware-review
description: Check whether the running production firmware of one Zyxel USG FLEX H firewall includes the fix for CVE-2025-1731. Use a saved Firmware Management record tied to the physical unit and boot.
---

# Review the firmware running on a Zyxel firewall

Use the administrator's checker result to identify the patch status of one physical appliance. Zyxel's 22 April 2025 bulletin gives the affected range as “uOS V1.20 to V1.31” and identifies V1.32 as the fix. The first fixed image for the USG FLEX 200HP is `V1.32(ABXE.0)C0`. The 200H has a different model code, `ABWV`. [Zyxel advisory](https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-incorrect-permission-assignment-and-improper-privilege-management-vulnerabilities-in-usg-flex-h-series-firewalls-04-22-2025) · [V1.32 production images by model](https://community.zyxel.com/en/discussion/28988/usg-flex-h-series-v1-32patch-0-firmware-release)

## Prepare the evidence

1. Identify the physical unit and boot under review. Use a redacted per-appliance alias for `asset` and a deployment or boot reference for `build`. Repeat those fields inside `inventory` from the saved observation. Set `deployment_verified` to true only when the capture identifies that same unit and boot. Members of a high-availability pair need separate records.
2. On the saved **Maintenance → Firmware/File Manager → Firmware Management** screen, find **Firmware Status**. Transcribe its `Status`, `Model` and `Version` columns into `firmware_status` and set `source` to `firmware_management`. Use `ref` for the capture. These JSON field names wrap the screen data. Under **Cloud Firmware Information**, **Latest Version** describes an available download. It may be transcribed into the optional `cloud_latest_version` field. A staged image still needs a post-reboot Running observation. [Zyxel 1.32 guide, figure 343 and table 269](https://download.zyxel.com/USG_FLEX_50H/user_guide/USG%20FLEX%2050H_V1.32_Ed1.pdf#page=568)
3. Set `origin` to `upstream` and provide `origin_ref` when the deployment records identify the running image as a published Zyxel production build. Copy the complete version cell, including any suffix it shows. Device screens can display `V1.31(ABXE.0)` for the published `V1.31(ABXE.0)C0` build. A custom or engineering image needs its own vendor decision. [Firmware version fields](https://download.zyxel.com/USG_FLEX_50HP/user_guide_web/uOS1-40/h_FileManager.html) · [V1.31 release table](https://community.zyxel.com/en/discussion/27878/usg-flex-h-series-v1-31patch-0-firmware-release)

The checker relies on the administrator’s transcription of Status, Model and Version and the evidence cited for production origin. A displayed version alone cannot establish how an image was built. When the capture includes a Standby row, its model and hardware code must agree with the physical unit. An unreadable or conflicting Standby version gives `unknown`. A matching code establishes row consistency. The observed release and its patch status come from the Running row.

## Run and report

From the unpacked skill directory, use Python 3.9 or later to run the offline checker.

```sh
python3 scripts/check.py < examples/gap.json
```

In ARTEX, ask for the checker JSON and evidence references. Report the physical unit, boot, model, observed firmware, advisory and `patch_status`.

- `affected_version` warrants an update review. Give the model-specific first fix and request a fresh running record after the update. The example shows why an available cloud update leaves the running unit affected. [Affected fixture](examples/gap.json)
- `vendor_fix_present` confirms this fix for the observed unit and boot. `outside_affected_range` identifies a reviewed production image that predates the published range. [Fixed fixture](examples/pass.json)
- `unknown` covers missing, conflicting or unreviewed evidence. Use `patch_reason` to identify what the administrator needs. The example supplies another member's capture. [Peer mismatch fixture](examples/unknown.json)

The checker recognizes the model and production builds in the linked vendor release tables reviewed through 20 November 2026. Every conclusive result links its specific release table. Keep `applicability` unknown. Firmware evidence alone cannot establish exposure or compromise. An `invalid_input` response calls for corrected JSON.
