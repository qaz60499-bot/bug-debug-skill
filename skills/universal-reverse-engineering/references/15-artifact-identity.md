# 15 — Artifact Identity / Fingerprint

## Purpose

Before deeper analysis, record the exact file identity. Without this, evidence from different versions, variants, architectures, or extracted layers can be mixed accidentally.

## Required fields

- Source path or acquisition note.
- SHA-256 and size.
- Container/format: PE, ELF, Mach-O, APK, AAB, IPA, DLL, SO, dylib, wasm, firmware image, archive, script bundle, etc.
- Architecture/ABI: x86, x64, arm64, arm64e, armeabi-v7a, wasm32, CLR, JVM/DEX, etc.
- Version/build if available.
- Package name, bundle ID, product name, module name, or firmware release ID.
- Signing/certificate metadata when relevant.
- Runtime/language indicators: CLR, JVM/DEX, ObjC/Swift, Go, Rust, Flutter, Electron, Unity/IL2CPP, WASM, VM.
- Extraction relationship: original container, extracted child artifact, generated database, decompiler project.
- Tool versions used for identification.

## Layered artifacts

A container may produce multiple analysis artifacts. Keep separate fingerprints for:

- original package/archive/image;
- extracted native libraries;
- DEX/IL/metadata files;
- resource bundles;
- firmware filesystem files;
- decompiler databases and analysis outputs.

## Cross-version rule

Do not compare or merge evidence until each version has its own fingerprint. A function name, offset, class path, metadata token, or resource ID from one version does not automatically apply to another.

## Minimal record

```text
Artifact ID:
Parent artifact:
Path/source:
SHA-256:
Size:
Format/container:
Architecture/ABI:
Version/build:
Package/bundle/module:
Signing metadata:
Runtime/framework indicators:
Identified by:
Notes/Unknowns:
```
