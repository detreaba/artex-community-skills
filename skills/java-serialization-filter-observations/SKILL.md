---
name: java-serialization-filter-observations
description: Determine whether a Java object input stream had a filter on the checks recorded in a saved OpenJDK 21 Flight Recorder export. Use for an owner-identified serving JVM and recording.
---

# Read Java serialization filter observations

Use this skill when an operator has an existing Flight Recorder recording or its JSON export and wants to know whether any recorded deserialization check ran without a filter. A JVM startup option describes configuration. The filter factory and application can select or replace the filter for each stream. OpenJDK records `filterConfigured` from the filter installed at the moment of the check. [OpenJDK event producer](https://github.com/openjdk/jdk21u/blob/5d9cac4049895a80fcdefa9bb1b81e021fdabb33/src/java.base/share/classes/java/io/ObjectInputStream.java#L1399-L1441) · [Java filter API](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/io/ObjectInputFilter.html)

## Prepare the saved evidence

To export from a local recording, run the JDK 21 command below. It reads a file. An existing JSON export can be used directly. [JFR command reference](https://docs.oracle.com/en/java/javase/21/docs/specs/man/jfr.html)

```sh
jfr print --json --events jdk.Deserialization,jdk.DataLoss,jdk.JVMInformation --stack-depth 0 saved.jfr > events.json
```

Keep the `recording.events` array and the evidence fields below. For deserialization events, keep the exact `type`, `values.filterConfigured` and `values.filterStatus`, including explicit JSON `null`. For loss events the type alone suffices. For each JVM information event keep its integer `values.pid` and timestamp string `values.jvmStartTime` until the local check finishes. Only the scope aliases, aggregate counts and decisions are returned. [JDK event fields](https://github.com/openjdk/jdk21u/blob/5d9cac4049895a80fcdefa9bb1b81e021fdabb33/src/jdk.jfr/share/classes/jdk/jfr/events/DeserializationEvent.java) · [JFR JSON layout](https://github.com/openjdk/jdk21u/blob/5d9cac4049895a80fcdefa9bb1b81e021fdabb33/src/jdk.jfr/share/classes/jdk/jfr/internal/tool/JSONWriter.java#L44-L80)

- Set `inventory.asset`, `build`, `instance` and `ref` to redacted aliases. Use a per-start JVM identity for `instance` and a reference to this one recording for `ref`. Use 1–64 ASCII letters, digits, underscores or hyphens, starting with a letter or digit.
- Set `jdk_major` to the integer `21` and `deployment_verified` to `true` only when the owner's evidence links the recording to this serving JVM generation and build. A file assembled across different processes needs separate original recordings.
- Set `export_complete` to `true` when the selected export retains every recorded deserialization check and all available loss and JVM identity records. Set `loss_events_included` to `true` when its event selection included `jdk.DataLoss` and retained every such record, even when there were zero. Use `false` for known omissions. A historical deserialization-only export can still establish a particular observed absence. [Gap fixture](examples/gap.json)

From the unpacked skill directory, run `python3 scripts/check.py < evidence.json`. The Python 3.9+ checker accepts one JSON object up to 16 MiB. For a large export, first remove the unused event fields locally. The bundled fixtures demonstrate all three outcomes.

## Interpret the result in ARTEX

Cite the asset, build, JVM generation, recording reference, event counts and `export_coverage`. One stream can generate several checks. A `jdk.DataLoss` record establishes loss inside the window and makes coverage partial. Zero recorded losses cannot establish uninterrupted capture. The recording can cover only part of the process lifetime or have an event disabled during an interval. Inconsistent or unreadable JVM identities leave attribution unknown even for an observed absence. If the recording contains no identity event, the owner's independently verified generation is required. [JDK recording metadata](https://github.com/openjdk/jdk21u/blob/5d9cac4049895a80fcdefa9bb1b81e021fdabb33/src/hotspot/share/jfr/metadata/metadata.xml)

- `filter_absent_on_recorded_check` means at least one valid event recorded `false` and a null status. Report the count even when other events had filters or the export is partial. [Mixed excerpt](examples/gap.json)
- `filter_seen_on_recorded_checks` requires a nonempty, complete and interpretable set of recorded checks. The `true` flag establishes filter presence. For a configured filter, `REJECTED` or a null status stops this check. `ALLOWED` and `UNDECIDED` allow processing to continue at this point. Filter strength and coverage of other paths require separate evidence. [Filtered checks](examples/pass.json) · [OpenJDK status handling](https://github.com/openjdk/jdk21u/blob/5d9cac4049895a80fcdefa9bb1b81e021fdabb33/src/java.base/share/classes/java/io/ObjectInputStream.java#L1424-L1441)
- `unknown` covers unbound evidence, an empty selection, or positive observations with missing coverage. A false flag paired with a non-null decision is inconsistent with OpenJDK's event producer and counts as unusable. A configured filter can return `UNDECIDED` or null. An event reporting `REJECTED` may also reflect a filter exception. [Empty export](examples/unknown.json)

The checker returns `invalid_input` for a malformed envelope or invalid JSON. Ask the operator for the local checker's output and a redacted reference when interpreting a real recording.
