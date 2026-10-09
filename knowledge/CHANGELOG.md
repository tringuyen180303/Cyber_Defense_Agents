## v2 — new detector learned_offhours_suspiciouscontext (all_of ['off_hours', 'suspicious_context'], weight 0.4); new detector learned_critical_iamwrite (all_of ['critical_resource', 'iam_write'], weight 0.4); first_time_resource_access weight 0.25 → 0.1; playbook PB-1: deactivate_access_key ['key_in_use_by_ci'] → rotate_access_key

- Parent: v1 · approved by: human (dashboard) · 2026-10-09T22:44:02Z
- Scorecard: recall 100%, false positives 0, avg sandbox attempts 1.00, avg events-to-detect 1.8
- **add_rule** `learned_offhours_suspiciouscontext`: new detector learned_offhours_suspiciouscontext (all_of ['off_hours', 'suspicious_context'], weight 0.4)
  - triggered by: missed rt-fast-exfil-known-network+drop-discovery, rt-fast-exfil-known-network+slow
- **add_rule** `learned_critical_iamwrite`: new detector learned_critical_iamwrite (all_of ['critical_resource', 'iam_write'], weight 0.4)
  - triggered by: missed rt-persistence-only-known-network+retarget
- **set_weight** `first_time_resource_access`: first_time_resource_access weight 0.25 → 0.1
  - triggered by: false positive benign-new-runner-range
- **add_playbook** `PB-1`: playbook PB-1: deactivate_access_key ['key_in_use_by_ci'] → rotate_access_key
  - triggered by: sandbox repair in attack-ci-key-classic

## v3 — new detector learned_firsttime_offhours (all_of ['first_time_resource', 'off_hours'], weight 0.4)

- Parent: v2 · approved by: human (dashboard) · 2026-10-09T22:44:32Z
- Scorecard: recall 100%, false positives 0, avg sandbox attempts 1.00, avg events-to-detect 2.0
- **add_rule** `learned_firsttime_offhours`: new detector learned_firsttime_offhours (all_of ['first_time_resource', 'off_hours'], weight 0.4)
  - triggered by: missed rt-fast-exfil-known-network+secrets-focus

