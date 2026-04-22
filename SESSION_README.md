# Session README — GCS FUSE CSI Driver E2E Test Development

## Who is Working On This

**Developer:** Pravin Sarana (pravin.sarana@gmail.com)  
**Working directory:** `/home/mcw/pycode/techM/workingDir/gcs-fuse-csi-driver/`  
**Cluster machine (SSH):** Cloud Shell / GKE cluster with fuse addon  
**OSS cluster:** Already set up and used for initial test runs

---

## What We Are Building

End-to-end test cases for the **GCS FUSE CSI Driver** that validate authentication and authorization behavior using **Workload Identity Federation (WIF)** and **OIDC**.

The driver mounts GCS buckets into Kubernetes pods via a gcsfuse sidecar container injected by a mutating webhook.

---

## Cluster Types

| Type | How to identify | Auth mechanism tested |
|---|---|---|
| OSS (self-managed) | `IS_OSS=true` env var | External WIF — KSA token → Google STS → GCS |
| GKE (managed) | `IS_OSS` not set or empty | Native GKE WI — KSA annotated with GSA → GSA impersonation → GCS |

---

## Key Test Files

| File | Purpose |
|---|---|
| `test/e2e/testsuites/gcsfuse_oidc_auth.go` | OIDC authentication failure tests (wrong issuer, non-existent pool) + happy path |
| `test/e2e/testsuites/workload_identity_federation.go` | WIF authorization failure tests — works on both OSS and GKE |
| `test/e2e/e2e_test.go` | Test suite registration |
| `test/e2e/utils/handler.go` | Env var constants, cluster setup, `IS_OSS` flag logic |
| `test/e2e/main.go` | CLI flags for test runner |

---

## Test Suites Added This Session

### 1. OIDC Authentication Failures (`gcsfuse_oidc_auth.go`)
Suite name: `"oidc"`

| Test | What it proves |
|---|---|
| `should successfully mount with OIDC authentication` | Happy path — WIF works end-to-end |
| `should store and retain data with OIDC authentication` | Read/write with WIF credentials |
| `should store data in implicit directory with OIDC authentication` | Directory creation via WIF |
| `should fail when OIDC ConfigMap is missing` | Pod creation fails if ConfigMap not found |
| `should fail when CSI bucket access check is enabled with OIDC authentication` | Node driver pre-flight check fails without WIF creds |
| `should fail authentication when workload identity provider is misconfigured` | Wrong issuer URI → STS `invalid_grant` → `"Error connecting to the given credential's issuer."` |
| `should fail authentication when workload identity pool or provider does not exist` | Non-existent pool → STS `invalid_target` → `"invalid_target"` in logs |

### 2. WIF Authorization Failures (`workload_identity_federation.go`)
Suite name: `"wif"` — **runs on both OSS and GKE**

| Test | What it proves |
|---|---|
| `should fail GCS access when WI principal has no storage role` | Auth succeeds, GCS returns `PermissionDenied` |
| `should fail write operations when WI principal has read-only storage role` | `objectViewer` — reads work, writes fail |
| `should fail GCS access when WI principal role is on a different bucket` | IAM on wrong bucket → `PermissionDenied` on mounted bucket |
| `should fail file operations when WI principal role is revoked mid-session` | Role revoked mid-run → writes fail after 60s wait |

---

## How Auth Branching Works in `workload_identity_federation.go`

The same 4 test cases run on both cluster types. The `setupWIAuth(configMapName)` helper checks `IS_OSS`:

```
IS_OSS=true  →  External WIF:  WIF pool + provider + credential config ConfigMap
                               principal = "principal://iam.googleapis.com/..."
                               Pod annotated with GCPWorkloadIdentityCredentialConfigMapAnnotation

IS_OSS=""    →  Native GKE WI: Create GSA dynamically, bind KSA→GSA (workloadIdentityUser)
                               Annotate KSA with iam.gke.io/gcp-service-account
                               principal = "serviceAccount:<gsa>@<project>.iam.gserviceaccount.com"
                               Pod has no credential annotation
```

---

## Key Environment Variables

| Variable | Constant | Description |
|---|---|---|
| `PROJECT` | `utils.ProjectEnvVar` | GCP project ID |
| `PROJECT_NUMBER` | `utils.ProjectNumberEnvVar` | GCP project number |
| `IS_OSS` | `utils.IsOSSEnvVar` | Set to `"true"` on OSS clusters |
| `CLUSTER_NAME` | `utils.ClusterNameEnvVar` | GKE cluster name (needed for OIDC issuer URL) |
| `CLUSTER_LOCATION` | `utils.ClusterLocationEnvVar` | GKE cluster region/zone |

`IS_OSS` is automatically set by `handler.go` when `UseGKEManagedDriver=false && SkipCSIDriverInstall=false`.

---

## Reusable Helper Functions

All in `test/e2e/testsuites/gcsfuse_oidc_auth.go` (package-level, accessible from all testsuites files):

| Function | Description |
|---|---|
| `getProjectNumber(projectID)` | Runs `gcloud projects describe` |
| `createWorkloadIdentityPool(projectID, poolID)` | Idempotent — ignores "already exists" |
| `createWorkloadIdentityProvider(projectID, poolID, providerID, issuerURI)` | Idempotent |
| `generateCredentialConfig(projectNumber, poolID, providerID)` | Returns external_account JSON |
| `getClusterOIDCIssuer(clusterName, clusterLocation, projectID)` | Constructs GKE OIDC issuer URL or reads `CLUSTER_OIDC_ISSUER` env override |
| `createServiceAccount(ctx, f, name)` | Creates K8s SA |
| `deleteServiceAccount(ctx, f, name)` | Deletes K8s SA |
| `createCredentialConfigMap(ctx, f, name, credentialConfig)` | Creates K8s ConfigMap with JSON |
| `deleteConfigMap(ctx, f, name)` | Deletes K8s ConfigMap |
| `grantBucketAccess(bucketName, principal, role)` | `gcloud storage buckets add-iam-policy-binding` |
| `revokeBucketAccess(bucketName, principal, role)` | `gcloud storage buckets remove-iam-policy-binding` |

WIF-specific helpers in `workload_identity_federation.go`:

| Function | Description |
|---|---|
| `wifGSANameForNamespace(namespace)` | Returns a ≤30-char GSA name from namespace |
| `createGSAForWIF(projectID, gsaName)` | Creates GCP Service Account, returns email |
| `deleteGSAForWIF(projectID, gsaEmail)` | Deletes GCP Service Account |
| `bindKSAToGSAForWIF(projectID, gsaEmail, namespace, ksaName)` | Grants `workloadIdentityUser` |
| `createServiceAccountWithGSAAnnotationForWIF(ctx, f, ksaName, gsaEmail)` | Creates K8s SA with GSA annotation |

---

## Important Design Decisions

1. **`SkipCSIBucketAccessCheckPrefix`** — Used in all WIF/OIDC error tests. Without it, the CSI node driver does a pre-flight bucket access check using node credentials (not pod credentials), which fails with `PermissionDenied` before gcsfuse even starts — masking the real error.

2. **No GSA needed for external WIF** — The bucket IAM binding uses `principal://iam.googleapis.com/...` (federated identity), not a GSA email. This is the key advantage of WIF over native GKE WI.

3. **Assertion strings are gcsfuse log strings** — Not HTTP status codes. Always verify exact strings by inspecting actual pod logs:
   ```bash
   kubectl logs <pod> -c gke-gcsfuse-sidecar | grep '"severity":"ERROR"'
   ```

4. **`IS_OSS` is derived, not set directly** — Set by `handler.go:200-201` when `!UseGKEManagedDriver && !SkipCSIDriverInstall`. Use `os.Getenv(utils.IsOSSEnvVar)` in test code.

5. **GSA names are dynamic** — GSAs are project-scoped (not namespace-scoped), so using a fixed name causes conflicts in parallel runs. Name is derived from namespace: `gcs-fuse-wif-<namespace[:17]>`.

---

## How to Run Tests

### OSS Cluster
```bash
export PROJECT=<project-id>
export CLUSTER_NAME=<cluster-name>
export CLUSTER_LOCATION=<cluster-region>

# WIF authorization tests
make e2e-test E2E_TEST_FOCUS='wif' E2E_TEST_GINKGO_PROCS=1 E2E_TEST_GINKGO_TIMEOUT=30m

# OIDC authentication tests
make e2e-test E2E_TEST_FOCUS='oidc' E2E_TEST_GINKGO_PROCS=1 E2E_TEST_GINKGO_TIMEOUT=30m
```

### GKE Cluster
```bash
export PROJECT=<project-id>
export CLUSTER_NAME=<cluster-name>
export CLUSTER_LOCATION=<cluster-region>
# IS_OSS is NOT set — handler.go detects GKE automatically

make e2e-test \
  --use-gke-managed-driver \
  E2E_TEST_FOCUS='wif' \
  E2E_TEST_GINKGO_PROCS=1 \
  E2E_TEST_GINKGO_TIMEOUT=30m
```

### Compile Check
```bash
cd /home/mcw/pycode/techM/workingDir/gcs-fuse-csi-driver/test
go build -o /dev/null ./e2e
```

---

## Known Issues / Gotchas

| Issue | Fix |
|---|---|
| Cloud Shell `$(gcloud config get-value project)` includes extra stderr text | `handler.go` uses `Output()` not `CombinedOutput()` at lines 111, 132 |
| `oidc` auto-added to ginkgo skip on managed driver | Line ~397 in `handler.go` commented out |
| Test file changes made locally must be copied to cluster machine | `scp test/e2e/testsuites/<file>.go <user>@<cluster>:/root/workingDir/gcs-fuse-csi-driver/test/e2e/testsuites/` |
| Case 4 (revoked mid-session) may be flaky | gcsfuse caches OAuth2 tokens; increase `time.Sleep` if needed |
| `PermissionDenied` not `PERMISSION_DENIED` | gcsfuse uses gRPC mixed-case error codes in JSON logs |

---

## Preferences

- Keep test cases in the same suite file — don't create separate files per cluster type
- Use `IsOSSEnvVar` flag to branch between OSS and GKE code paths within one suite
- Avoid unnecessary abstractions — keep helpers simple and purpose-named
- No trailing summaries in responses — user reads the diff
- Concise responses; use tables and code blocks
