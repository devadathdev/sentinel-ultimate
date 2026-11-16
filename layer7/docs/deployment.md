# Layer 7 Deployment and Runtime Execution

## Docker & Seccomp Integration

When launching execution runners from Sentinel or worker containers:
1. Apply the seccomp profile:
   ```bash
   docker run --security-opt seccomp=layer7/seccomp/sentinel-default.json \
              --read-only \
              --tmpfs /tmp:size=100M,mode=1777 \
              --cpus 1.0 --memory 512m \
              sentinel-runner:latest
   ```
2. Validate the `ExecutionTicket` signature before spawning worker processes.
3. Reject any ticket whose `expires_at` timestamp has passed or whose command does not exactly match `canonical_command`.
