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
	"strings"
	"time"

	"local/test/e2e/specs"
	"local/test/e2e/utils"

	"github.com/googlecloudplatform/gcs-fuse-csi-driver/pkg/webhook"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
)

// wiAuthContext holds the auth-mechanism-specific values for a test case.
// On OSS clusters (IS_OSS=true), external WIF is used: principal is a federated identity URL,
// and a ConfigMap holds the credential config JSON.
// On GKE clusters, native Workload Identity is used: principal is a GSA email,
// and the KSA is annotated with iam.gke.io/gcp-service-account.
type wiAuthContext struct {
	principal     string // IAM member string used for bucket grants
	configMapName string // non-empty on OSS only (external WIF credential config)
	gsaEmail      string // non-empty on GKE only (native WI GSA)
	projectID     string // retained for GSA cleanup on GKE
}

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

	// setupWIAuth sets up authentication infrastructure and Kubernetes resources for the test.
	// On OSS clusters (IS_OSS=true): creates WIF pool/provider, credential config ConfigMap,
	// and a plain KSA. The bucket IAM principal is a federated identity URL.
	// On GKE clusters: creates a GSA, binds the KSA to it via workloadIdentityUser,
	// and creates a KSA annotated with iam.gke.io/gcp-service-account.
	// The bucket IAM principal is the GSA email.
	// configMapName is only used on OSS; it is ignored on GKE.
	setupWIAuth := func(configMapName string) wiAuthContext {
		projectID := os.Getenv(utils.ProjectEnvVar)
		gomega.Expect(projectID).NotTo(gomega.BeEmpty(), fmt.Sprintf("%s environment variable must be set", utils.ProjectEnvVar))

		if os.Getenv(utils.IsOSSEnvVar) == "true" {
			// OSS path: external WIF via credential config ConfigMap.
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

			ginkgo.By("Generating credential configuration")
			credentialConfig := generateCredentialConfig(projectNumber, wifWorkloadIdentityPoolID, wifWorkloadIdentityProviderID)

			ginkgo.By(fmt.Sprintf("Creating Kubernetes service account: %s", wifServiceAccountName))
			createServiceAccount(ctx, f, wifServiceAccountName)

			ginkgo.By(fmt.Sprintf("Creating ConfigMap: %s", configMapName))
			createCredentialConfigMap(ctx, f, configMapName, credentialConfig)

			principal := fmt.Sprintf(
				"principal://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/subject/system:serviceaccount:%s:%s",
				projectNumber, wifWorkloadIdentityPoolID, f.Namespace.Name, wifServiceAccountName)

			return wiAuthContext{
				principal:     principal,
				configMapName: configMapName,
			}
		}

		// GKE path: native Workload Identity via GSA impersonation.
		gsaName := wifGSANameForNamespace(f.Namespace.Name)
		ginkgo.By(fmt.Sprintf("Creating GCP service account: %s", gsaName))
		gsaEmail := createGSAForWIF(projectID, gsaName)

		ginkgo.By(fmt.Sprintf("Binding KSA %s to GSA %s via workloadIdentityUser", wifServiceAccountName, gsaEmail))
		bindKSAToGSAForWIF(projectID, gsaEmail, f.Namespace.Name, wifServiceAccountName)

		ginkgo.By(fmt.Sprintf("Creating annotated Kubernetes service account: %s", wifServiceAccountName))
		createServiceAccountWithGSAAnnotationForWIF(ctx, f, wifServiceAccountName, gsaEmail)

		ginkgo.By("Waiting for Workload Identity binding to propagate")
		time.Sleep(60 * time.Second)

		return wiAuthContext{
			principal: "serviceAccount:" + gsaEmail,
			gsaEmail:  gsaEmail,
			projectID: projectID,
		}
	}

	// cleanupWIAuth deletes the K8s and GCP resources created by setupWIAuth.
	cleanupWIAuth := func(authCtx wiAuthContext) {
		deleteServiceAccount(ctx, f, wifServiceAccountName)
		if authCtx.configMapName != "" {
			deleteConfigMap(ctx, f, authCtx.configMapName)
		}
		if authCtx.gsaEmail != "" {
			deleteGSAForWIF(authCtx.projectID, authCtx.gsaEmail)
		}
	}

	// deployWIFPod creates a test pod configured for the appropriate auth mechanism.
	// On OSS, the pod is annotated with the credential config ConfigMap name.
	// On GKE, no annotation is needed — native WI is picked up via the KSA annotation.
	deployWIFPod := func(authCtx wiAuthContext) *specs.TestPod {
		tPod := specs.NewTestPodModifiedSpec(f.ClientSet, f.Namespace, true)
		tPod.SetServiceAccount(wifServiceAccountName)
		tPod.SetupVolume(l.volumeResource, wifVolumeName, wifMountPath, false)
		if authCtx.configMapName != "" {
			tPod.SetAnnotations(map[string]string{
				webhook.GCPWorkloadIdentityCredentialConfigMapAnnotation: authCtx.configMapName,
			})
		}
		tPod.Create(ctx)
		return tPod
	}

	// testCaseWIFNoStorageRole verifies that GCS access fails when the WI principal has no
	// storage role on the bucket. Authentication succeeds; GCS returns PermissionDenied.
	// When the sidecar bucket access check is enabled, the check fires at mount time and
	// the pod never reaches Running — we verify the PermissionDenied mount error instead.
	testCaseWIFNoStorageRole := func() {
		init(specs.SkipCSIBucketAccessCheckPrefix)
		defer cleanup()

		bucketName := l.volumeResource.VolSource.CSI.VolumeAttributes["bucketName"]
		gomega.Expect(bucketName).NotTo(gomega.BeEmpty(), "bucketName must be set in volume attributes")

		authCtx := setupWIAuth(wifNoRoleConfigMapName)
		defer cleanupWIAuth(authCtx)

		// Intentionally do NOT grant any bucket IAM role.
		// Authentication will succeed but GCS will reject all bucket operations.

		ginkgo.By("Deploying test pod with WI credentials but no bucket IAM role")
		tPod := deployWIFPod(authCtx)
		defer tPod.Cleanup(ctx)

		if os.Getenv(utils.TestWithSidecarBucketAccessCheckEnvVar) == "true" {
			// Sidecar bucket access check fires at mount time: the pod stays Pending
			// with a PermissionDenied FailedMount event — it never reaches Running.
			ginkgo.By("Checking that the sidecar bucket access check returns PermissionDenied")
			tPod.WaitForFailedMountError(ctx, "PermissionDenied")
		} else {
			tPod.WaitForRunning(ctx)
			ginkgo.By("Checking that gcsfuse logs a permission denied error from GCS")
			tPod.WaitForLog(ctx, webhook.GcsFuseSidecarName, "PermissionDenied")
		}
	}

	// testCaseWIFReadOnlyRoleWriteFails verifies that write operations fail when the WI principal
	// only has objectViewer (read-only) on the bucket. Reads succeed; writes are rejected by GCS.
	testCaseWIFReadOnlyRoleWriteFails := func() {
		init(specs.SkipCSIBucketAccessCheckPrefix)
		defer cleanup()

		bucketName := l.volumeResource.VolSource.CSI.VolumeAttributes["bucketName"]
		gomega.Expect(bucketName).NotTo(gomega.BeEmpty(), "bucketName must be set in volume attributes")

		authCtx := setupWIAuth(wifReadOnlyConfigMapName)
		defer cleanupWIAuth(authCtx)

		ginkgo.By("Granting read-only (objectViewer) access to bucket")
		grantBucketAccess(bucketName, authCtx.principal, "roles/storage.objectViewer")
		defer revokeBucketAccess(bucketName, authCtx.principal, "roles/storage.objectViewer")

		ginkgo.By("Waiting for IAM policy propagation")
		time.Sleep(5 * time.Second)

		ginkgo.By("Deploying test pod with WI credentials and read-only bucket access")
		tPod := deployWIFPod(authCtx)
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
	// IAM role is on a different bucket than the one being mounted.
	testCaseWIFRoleOnDifferentBucket := func() {
		init(specs.SkipCSIBucketAccessCheckPrefix)
		defer cleanup()

		bucketName := l.volumeResource.VolSource.CSI.VolumeAttributes["bucketName"]
		gomega.Expect(bucketName).NotTo(gomega.BeEmpty(), "bucketName must be set in volume attributes")

		projectID := os.Getenv(utils.ProjectEnvVar)
		authCtx := setupWIAuth(wifWrongBucketConfigMapName)
		defer cleanupWIAuth(authCtx)

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
				"gs://"+altBucket, "--project="+projectID, "--quiet")
			if out, err := deleteCmd.CombinedOutput(); err != nil {
				klog.Warningf("Failed to delete alternate bucket %s: %v, output: %s", altBucket, err, string(out))
			}
		}()

		ginkgo.By(fmt.Sprintf("Granting objectUser access on alternate bucket %s (not on test bucket %s)", altBucket, bucketName))
		grantBucketAccess(altBucket, authCtx.principal, "roles/storage.objectUser")
		defer revokeBucketAccess(altBucket, authCtx.principal, "roles/storage.objectUser")

		ginkgo.By("Waiting for IAM policy propagation")
		time.Sleep(5 * time.Second)

		ginkgo.By("Deploying test pod mounting test bucket where WI principal has no access")
		tPod := deployWIFPod(authCtx)
		defer tPod.Cleanup(ctx)

		if os.Getenv(utils.TestWithSidecarBucketAccessCheckEnvVar) == "true" {
			// Sidecar bucket access check fires at mount time: the pod stays Pending
			// with a PermissionDenied FailedMount event — it never reaches Running.
			ginkgo.By("Checking that the sidecar bucket access check returns PermissionDenied")
			tPod.WaitForFailedMountError(ctx, "PermissionDenied")
		} else {
			tPod.WaitForRunning(ctx)
			ginkgo.By("Checking that gcsfuse logs a permission denied error for the test bucket")
			tPod.WaitForLog(ctx, webhook.GcsFuseSidecarName, "PermissionDenied")
		}
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

}

// wifGSANameForNamespace returns a GSA name derived from the test namespace.
// GSA names are project-scoped and limited to 30 characters.
// Prefix "gcs-fuse-wif-" is 13 chars; we use up to 17 chars of the namespace.
func wifGSANameForNamespace(namespace string) string {
	suffix := namespace
	if len(suffix) > 17 {
		suffix = suffix[:17]
	}
	return fmt.Sprintf("gcs-fuse-wif-%s", suffix)
}

// createGSAForWIF creates a Google Service Account for WIF tests and returns its email.
// Ignores "already exists" errors so tests can be re-run without prior cleanup.
func createGSAForWIF(projectID, gsaName string) string {
	gsaEmail := fmt.Sprintf("%s@%s.iam.gserviceaccount.com", gsaName, projectID)
	cmd := exec.Command("gcloud", "iam", "service-accounts", "create", gsaName,
		"--project="+projectID,
		"--display-name=GCS FUSE WIF Test GSA")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if !strings.Contains(string(output), "already exists") {
			klog.Warningf("Failed to create GSA %q: %v, output: %s", gsaName, err, string(output))
		}
	} else {
		klog.Infof("Created GSA: %s", gsaEmail)
	}
	return gsaEmail
}

// deleteGSAForWIF deletes a Google Service Account.
func deleteGSAForWIF(projectID, gsaEmail string) {
	cmd := exec.Command("gcloud", "iam", "service-accounts", "delete", gsaEmail,
		"--project="+projectID,
		"--quiet")
	output, err := cmd.CombinedOutput()
	if err != nil {
		klog.Warningf("Failed to delete GSA %q: %v, output: %s", gsaEmail, err, string(output))
	} else {
		klog.Infof("Deleted GSA: %s", gsaEmail)
	}
}

// bindKSAToGSAForWIF grants roles/iam.workloadIdentityUser on the GSA to the KSA,
// enabling the KSA to impersonate the GSA via GKE native Workload Identity.
func bindKSAToGSAForWIF(projectID, gsaEmail, namespace, ksaName string) {
	member := fmt.Sprintf("serviceAccount:%s.svc.id.goog[%s/%s]", projectID, namespace, ksaName)
	cmd := exec.Command("gcloud", "iam", "service-accounts", "add-iam-policy-binding", gsaEmail,
		"--project="+projectID,
		"--role=roles/iam.workloadIdentityUser",
		"--member="+member)
	output, err := cmd.CombinedOutput()
	if err != nil {
		klog.Errorf("Failed to bind KSA %s/%s to GSA %s: %v, output: %s", namespace, ksaName, gsaEmail, err, string(output))
		framework.Failf("Failed to bind KSA to GSA: %v", err)
	} else {
		klog.Infof("Bound KSA %s/%s to GSA %s", namespace, ksaName, gsaEmail)
	}
}

// createServiceAccountWithGSAAnnotationForWIF creates a K8s ServiceAccount annotated with the
// GSA email, enabling GKE native Workload Identity for pods running as this service account.
func createServiceAccountWithGSAAnnotationForWIF(ctx context.Context, f *framework.Framework, ksaName, gsaEmail string) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ksaName,
			Namespace: f.Namespace.Name,
			Annotations: map[string]string{
				"iam.gke.io/gcp-service-account": gsaEmail,
			},
		},
	}
	_, err := f.ClientSet.CoreV1().ServiceAccounts(f.Namespace.Name).Create(ctx, sa, metav1.CreateOptions{})
	if err != nil {
		framework.Failf("Failed to create annotated service account %s: %v", ksaName, err)
	}
	klog.Infof("Created annotated service account: %s (GSA: %s)", ksaName, gsaEmail)
}
