# 19 — Unity / IL2CPP Route

## Purpose

Activate this route only when Unity-specific artifact evidence is present. Do not infer Unity from C# metadata alone.

## Activation evidence

Route evidence may include:

- UnityPlayer component;
- `global-metadata.dat` or IL2CPP metadata files;
- Unity asset bundles, scenes, resources, or Unity paths;
- IL2CPP-generated native symbols or registration patterns;
- package metadata that identifies Unity runtime use.

## Evidence layers

Keep these layers separate:

1. Package/platform layer.
2. Unity resource layer.
3. Managed metadata layer.
4. IL2CPP/native address mapping layer.
5. App-owned logic inference layer.

## Workflow

1. Fingerprint the original artifact and extracted Unity/IL2CPP files.
2. Identify Unity version indicators when available.
3. Map metadata types and methods to native addresses when evidence supports it.
4. Recover high-value symbols and structures only where needed.
5. Verify decisive claims with native evidence, metadata records, resource references, or bounded runtime observations.
6. Record Unknowns where metadata is incomplete or version-mismatched.

## Negative rule

C#/.NET-like metadata without Unity-specific artifacts must stay on the `.NET` route until Unity evidence appears.
