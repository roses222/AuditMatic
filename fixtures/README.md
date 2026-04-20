# Testing Fixtures

This folder contains canonical realistic mock artifacts used for testing and validation.

## Purpose

- Keep realistic sample data separate from templates.
- Preserve templates as instructional/placeholder-only files.
- Provide a stable place for tests and manual validation assets.

## Canonical Fixture Files

- `fixtures/profiles/mock_local_watchfolder_pipeline_profile.json`
- `fixtures/profiles/mock_vsphere_watchfolder_pipeline_profile.json`
- `fixtures/json/registry_snapshots/mock_registry_snapshot.json`
- `fixtures/json/json_checklist/mock_checklist.json`
- `fixtures/json/json_result/mock_result.json`
- `fixtures/json/scan_jobs/mock_scan_job.json`
- `fixtures/workbooks/checklist/mock_audit_checklist.xlsx`
- `fixtures/workbooks/results/mock_audit_results.xlsx`

## Runtime Compatibility

The application may still read/write mock artifacts in runtime locations such as:

- `profiles/vm_profiles/`
- `JSON/*`
- `Audit Checklist/`
- `Audit Results/`

Those runtime copies can continue to exist for compatibility.
Use the files in `fixtures/` as the source-of-truth samples for testing data.
