# 21 — Android Framework Routing

## Purpose

Identify the Android framework family before assigning generated code to application logic. This prevents routing errors in apps built with large frameworks, code generators, or hybrid runtimes.

## Signals to collect

- Package structure and namespace patterns.
- AndroidManifest components, permissions, providers, services, receivers, and metadata.
- Gradle/build metadata when present.
- Resource names and generated resource classes.
- DEX class families and dependency package names.
- Native libraries in `lib/<abi>/`.
- Asset layout and framework-specific files.
- WebView, Flutter, React Native, Unity, Cordova, Xamarin/.NET, or other hybrid indicators.

## Ownership split

Classify code regions as:

- framework-generated;
- third-party library;
- app-owned wrapper/glue;
- app-owned business logic;
- unknown ownership.

Ownership is an Inference unless supported by package structure, metadata, build evidence, or repeated call-chain evidence.

## Routing

- Android framework layer stays on Android route.
- Native `.so` components route to native analysis.
- Unity indicators route to Unity/IL2CPP.
- Flutter AOT or engine-specific components route through thick-client/native as needed.
- WebView or JS bundle indicators route through thick-client/protocol routes as needed.

## Required output

```text
Framework family:
Evidence:
Generated/framework layers:
App-owned candidates:
Native components:
Unknown ownership:
Next route:
```

## Negative rule

Do not treat generated lifecycle glue, resource accessors, or framework bootstrap code as app-owned logic without evidence.
