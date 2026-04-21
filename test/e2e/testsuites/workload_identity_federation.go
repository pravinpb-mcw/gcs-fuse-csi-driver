/*
Copyright 2018 The Kubernetes Authors.
Copyright 2025 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package testsuites

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"local/test/e2e/specs"
	"local/test/e2e/utils"

	"github.com/googlecloudplatform/gcs-fuse-csi-driver/pkg/webhook"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/test/e2e/framework"
	e2evolume "k8s.io/kubernetes/test/e2e/framework/volume"
	storageframework "k8s.io/kubernetes/test/e2e/storage/framework"
	admissionapi "k8s.io/pod-security-admission/api"
)

const (
	wifWorkloadIdentityPoolID     = "gcs-fuse-oidc-pool"     // reuse existing pool (idempotent)
	wifWorkloadIdentityProviderID = "gcs-fuse-oidc-provider" // reuse existing provider (idempotent)
	wifServiceAccountName         = "gcs-fuse-wif-ksa"
	wifVolumeName                 = "gcs-wif-volume"
	wifMountPath                  = "/mnt/gcs"
	wifNoRoleConfigMapName        = "wif-credentials-no-role"
	wifReadOnlyConfigMapName      = "wif-credentials-readonly"
	wifWrongBucketConfigMapName   = "wif-credentials-wrong-bucket"
	wifRevokedConfigMapName       = "wif-credentials-revoked"
)

type gcsFuseCSIWIFTestSuite struct {
	tsInfo storageframework.TestSuiteInfo
}

// InitGcsFuseCSIWIFTestSuite returns gcsFuseCSIWIFTestSuite that implements TestSuite interface.
func InitGcsFuseCSIWIFTestSuite() storageframework.TestSuite {
	return &gcsFuseCSIWIFTestSuite{
		tsInfo: storageframework.TestSuiteInfo{
			Name: "wif",
			TestPatterns: []storageframework.TestPattern{
				storageframework.DefaultFsCSIEphemeralVolume,
			},
		},
	}
}

func (t *gcsFuseCSIWIFTestSuite) GetTestSuiteInfo() storageframework.TestSuiteInfo {
	return t.tsInfo
}

func (t *gcsFuseCSIWIFTestSuite) SkipUnsupportedTests(_ storageframework.TestDriver, _ storageframework.TestPattern) {
}

func (t *gcsFuseCSIWIFTestSuite) DefineTests(driver storageframework.TestDriver, pattern storageframework.TestPattern) {
	type local struct {
		config         *storageframework.PerTestConfig
		volumeResource *storageframework.VolumeResource
	}
	var l local
	ctx := context.Background()

	f := framework.NewFrameworkWithCustomTimeouts("wif", storageframework.GetDriverTimeouts(driver))
	f.NamespacePodSecurityEnforceLevel = admissionapi.LevelPrivileged

	init := func(configPrefix ...string) {
		l = local{}
		l.config = driver.PrepareTest(ctx, f)
		if len(configPrefix) > 0 {
			l.config.Prefix = configPrefix[0]
		}
		l.volumeResource = storageframework.CreateVolumeResource(ctx, driver, l.config, pattern, e2evolume.SizeRange{})
	}

	cleanup := func() {
		var cleanUpErrs []error
		cleanUpErrs = append(cleanUpErrs, l.volumeResource.CleanupResource(ctx))
		err := utilerrors.NewAggregate(cleanUpErrs)
		framework.ExpectNoError(err, "while cleaning up")
	}

	// setupWIFInfrastructure sets up the GCP WIF infrastructure (workload identity pool and provider).
	// Returns projectNumber and credentialConfig. The pool and provider are shared with the OIDC
	// test suite and created idempotently.
	setupWIFInfrastructure := func() (string, string) {
		projectID := os.Getenv(utils.ProjectEnvVar)
		gomega.Expect(projectID).NotTo(gomega.BeEmpty(), fmt.Sprintf("%s environment variable must be set", utils.ProjectEnvVar))

		ginkgo.By("Getting GCP project number")
		projectNumber := getProjectNumber(projectID)
		gomega.Expect(projectNumber).NotTo(gomega.BeEmpty(), "Failed to get project number")

		ginkgo.By("Getting cluster information")
		clusterName := os.Getenv(utils.ClusterNameEnvVar)
		clusterLocation := os.Getenv(utils.ClusterLocationEnvVar)
		gomega.Expect(clusterName).NotTo(gomega.BeEmpty(), fmt.Sprintf("%s environment variable must be set", utils.ClusterNameEnvVar))
		gomega.Expect(clusterLocation).NotTo(gomega.BeEmpty(), fmt.Sprintf("%s environment variable must be set", utils.ClusterLocationEnvVar))

		ginkgo.By(fmt.Sprintf("Creating workload identity pool: %s", wifWorkloadIdentityPoolID))
		createWorkloadIdentityPool(projectID, wifWorkloadIdentityPoolID)

		ginkgo.By("Getting cluster OIDC issuer URL")
		clusterIssuer := getClusterOIDCIssuer(clusterName, clusterLocation, projectID)
		gomega.Expect(clusterIssuer).NotTo(gomega.BeEmpty(), "Failed to get cluster OIDC issuer")

		ginkgo.By(fmt.Sprintf("Creating workload identity provider: %s", wifWorkloadIdentityProviderID))
		createWorkloadIdentityProvider(projectID, wifWorkloadIdentityPoolID, wifWorkloadIdentityProviderID, clusterIssuer)

		ginkgo.By("Generating credential configuration file")
		credentialConfig := generateCredentialConfig(projectNumber, wifWorkloadIdentityPoolID, wifWorkloadIdentityProviderID)

		return projectNumber, credentialConfig
	}

	// setupWIFKubernetesResources creates the K8s service account and ConfigMap with the credential config.
	setupWIFKubernetesResources := func(configMapName, credentialConfig string) {
		ginkgo.By(fmt.Sprintf("Creating Kubernetes service account: %s", wifServiceAccountName))
		createServiceAccount(ctx, f, wifServiceAccountName)

		ginkgo.By(fmt.Sprintf("Creating ConfigMap: %s", configMapName))
		createCredentialConfigMap(ctx, f, configMapName, credentialConfig)
	}

	// cleanupWIFKubernetesResources deletes the K8s service account and ConfigMap.
	cleanupWIFKubernetesResources := func(configMapName string) {
		deleteServiceAccount(ctx, f, wifServiceAccountName)
		deleteConfigMap(ctx, f, configMapName)
	}

	// buildWIFPrincipal returns the WIF principal URL for the test service account.
	buildWIFPrincipal := func(projectNumber string) string {
		return fmt.Sprintf(
			"principal://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/subject/system:serviceaccount:%s:%s",
			projectNumber, wifWorkloadIdentityPoolID, f.Namespace.Name, wifServiceAccountName)
	}

	// deployWIFPod creates and returns a test pod configured with WIF credential config.
	deployWIFPod := func(configMapName string) *specs.TestPod {
		tPod := specs.NewTestPodModifiedSpec(f.ClientSet, f.Namespace, true)
		tPod.SetServiceAccount(wifServiceAccountName)
		tPod.SetupVolume(l.volumeResource, wifVolumeName, wifMountPath, false)
		tPod.SetAnnotations(map[string]string{
			webhook.GCPWorkloadIdentityCredentialConfigMapAnnotation: configMapName,
		})
		tPod.Create(ctx)
		return tPod
	}

	// testCaseWIFNoStorageRole verifies that GCS access fails when the WI principal has no
	// storage role on the bucket. Authentication (WIF token exchange) succeeds; the 403 comes
	// from GCS when gcsfuse tries to access the bucket after obtaining a valid token.
	testCaseWIFNoStorageRole := func() {
		init(specs.SkipCSIBucketAccessCheckPrefix)
		defer cleanup()

		bucketName := l.volumeResource.VolSource.CSI.VolumeAttributes["bucketName"]
		gomega.Expect(bucketName).NotTo(gomega.BeEmpty(), "bucketName must be set in volume attributes")

		_, credentialConfig := setupWIFInfrastructure()
		setupWIFKubernetesResources(wifNoRoleConfigMapName, credentialConfig)
		defer cleanupWIFKubernetesResources(wifNoRoleConfigMapName)

		// Intentionally do NOT grant any bucket access.
		// Authentication will succeed but GCS will return 403 on all bucket operations.

		ginkgo.By("Deploying test pod with WIF credentials but no bucket IAM role")
		tPod := deployWIFPod(wifNoRoleConfigMapName)
		defer tPod.Cleanup(ctx)

		// gcsfuse obtains a valid GCP token via WIF but GCS rejects the bucket access
		// with HTTP 403. The error surfaces in the gcsfuse sidecar container logs.
		// Note: verify the exact log string on first run if this assertion fails:
		//   kubectl logs <pod> -c gke-gcsfuse-sidecar | grep -i "403\|permission\|PERMISSION"
		ginkgo.By("Checking that gcsfuse logs a permission denied error from GCS")
		tPod.WaitForLog(ctx, webhook.GcsFuseSidecarName, "PERMISSION_DENIED")
	}

	// testCaseWIFReadOnlyRoleWriteFails verifies that write operations fail when the WI principal
	// only has objectViewer (read-only) on the bucket. Reads succeed; writes are rejected by GCS.
	testCaseWIFReadOnlyRoleWriteFails := func() {
		init(specs.SkipCSIBucketAccessCheckPrefix)
		defer cleanup()

		bucketName := l.volumeResource.VolSource.CSI.VolumeAttributes["bucketName"]
		gomega.Expect(bucketName).NotTo(gomega.BeEmpty(), "bucketName must be set in volume attributes")

		projectNumber, credentialConfig := setupWIFInfrastructure()
		setupWIFKubernetesResources(wifReadOnlyConfigMapName, credentialConfig)
		defer cleanupWIFKubernetesResources(wifReadOnlyConfigMapName)

		principal := buildWIFPrincipal(projectNumber)

		ginkgo.By("Granting read-only (objectViewer) access to bucket")
		grantBucketAccess(bucketName, principal, "roles/storage.objectViewer")
		defer revokeBucketAccess(bucketName, principal, "roles/storage.objectViewer")

		ginkgo.By("Waiting for IAM policy propagation")
		time.Sleep(5 * time.Second)

		ginkgo.By("Deploying test pod with WIF credentials and read-only bucket access")
		tPod := deployWIFPod(wifReadOnlyConfigMapName)
		defer tPod.Cleanup(ctx)

		ginkgo.By("Checking that the pod is running")
		tPod.WaitForRunning(ctx)

		ginkgo.By("Verifying read operations succeed with objectViewer role")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName,
			fmt.Sprintf("ls %v", wifMountPath))

		ginkgo.By("Verifying write operations fail with objectViewer role")
		tPod.VerifyExecInPodFail(f, specs.TesterContainerName,
			fmt.Sprintf("echo 'write-test' > %v/wif-write-test.txt", wifMountPath), 1)
	}

	// testCaseWIFRoleOnDifferentBucket verifies that GCS access fails when the WI principal's
	// IAM role is on a different bucket than the one being mounted. The principal is authorized
	// on altBucket but the pod mounts the test bucket where it has no access.
	testCaseWIFRoleOnDifferentBucket := func() {
		init(specs.SkipCSIBucketAccessCheckPrefix)
		defer cleanup()

		bucketName := l.volumeResource.VolSource.CSI.VolumeAttributes["bucketName"]
		gomega.Expect(bucketName).NotTo(gomega.BeEmpty(), "bucketName must be set in volume attributes")

		projectID := os.Getenv(utils.ProjectEnvVar)
		projectNumber, credentialConfig := setupWIFInfrastructure()
		setupWIFKubernetesResources(wifWrongBucketConfigMapName, credentialConfig)
		defer cleanupWIFKubernetesResources(wifWrongBucketConfigMapName)

		principal := buildWIFPrincipal(projectNumber)

		// Create a separate temporary bucket and grant access only on it.
		altBucket := fmt.Sprintf("gcs-fuse-wif-alt-%s", f.Namespace.Name)
		ginkgo.By(fmt.Sprintf("Creating alternate bucket: %s", altBucket))
		createCmd := exec.Command("gcloud", "storage", "buckets", "create",
			"gs://"+altBucket, "--project="+projectID)
		if out, err := createCmd.CombinedOutput(); err != nil {
			klog.Warningf("Failed to create alternate bucket %s: %v, output: %s", altBucket, err, string(out))
		}
		defer func() {
			ginkgo.By(fmt.Sprintf("Deleting alternate bucket: %s", altBucket))
			deleteCmd := exec.Command("gcloud", "storage", "buckets", "delete",
				"gs://"+altBucket, "--quiet")
			if out, err := deleteCmd.CombinedOutput(); err != nil {
				klog.Warningf("Failed to delete alternate bucket %s: %v, output: %s", altBucket, err, string(out))
			}
		}()

		ginkgo.By(fmt.Sprintf("Granting objectUser access on alternate bucket %s (not on test bucket %s)", altBucket, bucketName))
		grantBucketAccess(altBucket, principal, "roles/storage.objectUser")
		defer revokeBucketAccess(altBucket, principal, "roles/storage.objectUser")

		ginkgo.By("Waiting for IAM policy propagation")
		time.Sleep(5 * time.Second)

		// The pod mounts the test bucket (bucketName) where the principal has no role.
		// The WI token exchange succeeds but GCS returns 403 for the test bucket.
		ginkgo.By("Deploying test pod mounting test bucket where WI principal has no access")
		tPod := deployWIFPod(wifWrongBucketConfigMapName)
		defer tPod.Cleanup(ctx)

		ginkgo.By("Checking that gcsfuse logs a permission denied error for the test bucket")
		tPod.WaitForLog(ctx, webhook.GcsFuseSidecarName, "PERMISSION_DENIED")
	}

	// testCaseWIFRoleRevokedMidSession verifies that file operations fail after the WI principal's
	// IAM role is revoked while the pod is running. The mount succeeds initially; subsequent
	// writes fail once the role is removed and the cached token expires.
	testCaseWIFRoleRevokedMidSession := func() {
		init(specs.SkipCSIBucketAccessCheckPrefix)
		defer cleanup()

		bucketName := l.volumeResource.VolSource.CSI.VolumeAttributes["bucketName"]
		gomega.Expect(bucketName).NotTo(gomega.BeEmpty(), "bucketName must be set in volume attributes")

		projectNumber, credentialConfig := setupWIFInfrastructure()
		setupWIFKubernetesResources(wifRevokedConfigMapName, credentialConfig)
		defer cleanupWIFKubernetesResources(wifRevokedConfigMapName)

		principal := buildWIFPrincipal(projectNumber)

		ginkgo.By("Granting objectUser access to bucket")
		grantBucketAccess(bucketName, principal, "roles/storage.objectUser")

		ginkgo.By("Waiting for IAM policy propagation")
		time.Sleep(5 * time.Second)

		ginkgo.By("Deploying test pod with WIF credentials and bucket access")
		tPod := deployWIFPod(wifRevokedConfigMapName)
		defer tPod.Cleanup(ctx)

		ginkgo.By("Checking that the pod is running")
		tPod.WaitForRunning(ctx)

		ginkgo.By("Verifying initial write succeeds before role revocation")
		tPod.VerifyExecInPodSucceed(f, specs.TesterContainerName,
			fmt.Sprintf("echo 'pre-revoke' > %v/wif-pre-revoke.txt", wifMountPath))

		// Revoke the IAM role immediately (not deferred — intentional mid-session revocation).
		ginkgo.By("Revoking bucket access mid-session")
		revokeBucketAccess(bucketName, principal, "roles/storage.objectUser")

		// Wait for IAM propagation. gcsfuse caches the OAuth2 token so the sleep allows
		// the token to expire or the next GCS call to pick up the revoked permissions.
		// If this test is flaky, increase the sleep to match the token cache TTL.
		ginkgo.By("Waiting for IAM revocation to propagate")
		time.Sleep(60 * time.Second)

		ginkgo.By("Verifying write fails after role revocation")
		tPod.VerifyExecInPodFail(f, specs.TesterContainerName,
			fmt.Sprintf("echo 'post-revoke' > %v/wif-post-revoke.txt", wifMountPath), 1)
	}

	ginkgo.It("should fail GCS access when WI principal has no storage role", func() {
		testCaseWIFNoStorageRole()
	})

	ginkgo.It("should fail write operations when WI principal has read-only storage role", func() {
		testCaseWIFReadOnlyRoleWriteFails()
	})

	ginkgo.It("should fail GCS access when WI principal role is on a different bucket", func() {
		testCaseWIFRoleOnDifferentBucket()
	})

	ginkgo.It("should fail file operations when WI principal role is revoked mid-session", func() {
		testCaseWIFRoleRevokedMidSession()
	})
}
