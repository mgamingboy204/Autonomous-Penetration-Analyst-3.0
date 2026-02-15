# Autonomous Penetration Analyst 3.0 (Phase 0 Scaffold)

This repository currently implements only **Phase 0 scaffolding** for an offline lab workflow on Kali.

## Environment
- Attacker: Kali Linux VM
- Targets: Metasploitable / DVWA on host-only network
- Offline-only operation
- Strict target whitelist enforcement

## Phase-wise setup

### Phase 0 (current)
Implemented:
- whitelist validation
- run_id generation
- run directory creation
- `status.json` progress tracking
- central logging to `logs/app.log`
- placeholder pipeline step updates

Not implemented yet:
- active scanning
- AI decisioning
- exploitation
- report generation

### Planned next phases
- **Phase 1:** recon ingestion and normalization
- **Phase 2:** AI/ML ranking and decision support
- **Phase 3:** controlled exploit orchestration (lab-only)
- **Phase 4:** report/dashboard integration

## Setup
```bash
chmod +x setup.sh
./setup.sh
```

## Run commands

### Minimal orchestrator run
```bash
python src/orchestrator.py --target 192.168.56.101
```

### Demo runner (examiner-friendly)
```bash
python scripts/demo_runner.py --target 192.168.56.101
```

### Optional full-run gate demonstration (expected to be blocked by default settings)
```bash
python src/orchestrator.py --target 192.168.56.101 --full-run --confirm-token CHANGE_ME
```

## Output structure
Each run creates:
- `runs/<run_id>/raw/`
- `runs/<run_id>/normalized/`
- `runs/<run_id>/logs/app.log`
- `runs/<run_id>/report/`
- `runs/<run_id>/status.json`
