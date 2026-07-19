# Quirt

StealthEye Quirt is the standalone UID-0 root-control daemon for Horsey. It exposes a private Unix socket at `/run/horsey/quirt.sock` and serves signed, replay-resistant operations for unrestricted owner authority.

This repository is derived from the authoritative source commit `6b4968e9443653af6636f2490bf3c4fc14da4cea` in `StealthEyeLLC/stealtheye-fix-operator` and validated by `provenance/extraction-manifest.json`.

## Requirements

- Node `v24.18.0`
- npm `11.16.0`
- TypeScript `5.9.3`
- Linux build host with `gcc`, `python3`, `tmux`, and `systemd-analyze`

## Commands

```bash
npm ci
npm run check
npm test
npm run build
npm run ci
```

## Runtime

```bash
npm run start:quirt
```

## Provenance

- Authoritative source: `StealthEyeLLC/stealtheye-fix-operator@6b4968e9443653af6636f2490bf3c4fc14da4cea`
- Evidence commit: `f103c0377c73c3831af31544d14842832516499a`
- Extraction manifest: `provenance/extraction-manifest.json`
