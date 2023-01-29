/* vi: set ts=4 sw=4 noexpandtab : */

/*
 * Copyright contributors to the IBM Security Verify Directory Operator project
 */

package e2e

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	//nolint:golint
	//nolint:revive
	. "github.com/onsi/ginkgo/v2"

	//nolint:golint
	//nolint:revive
	. "github.com/onsi/gomega"

	"github.com/ibm-security/verify-directory-operator/test/utils"
)

// constant parts of the file
const namespace = "verify-directory-operator-system"

/*****************************************************************************/

var _ = Describe("verify-directory", Ordered, func() {

	BeforeAll(func() {

		var err error

		/*
		 * Validate that the license key environment variable has been
		 * set.
		 */

		By("Validating that the LICENSE_KEY environment variable has been set.")
		if _, ok := os.LookupEnv("LICENSE_KEY"); !ok {
			err = errors.New(
					"The LICENSE_KEY environment variable has not been set.")
		}
		Expect(err).To(Not(HaveOccurred()))

		/*
		 * We need to install the certificate manager.
		 */

		By("Installing the cert-manager.")
		Expect(utils.InstallCertManager()).To(Succeed())

		/*
		 * The namespace can be created when we run make install.  However, 
		 * in this test we want ensure that the solution can run in a ns 
		 * labeled as restricted. Therefore, we create the namespace here.
		 */

		By("Creating the manager namespace.")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, _ = utils.Run(cmd)

		/*
		 * Now, let's ensure that all namespaces can raise a warning when we 
		 * apply the manifests.
		 */

		By("Labeling all namespaces to warn when we apply the manifest " +
					"if it violates the PodStandards.")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", "--all",
			"pod-security.kubernetes.io/audit=restricted",
			"pod-security.kubernetes.io/enforce-version=v1.24",
			"pod-security.kubernetes.io/warn=restricted")

		_, err = utils.Run(cmd)

		ExpectWithOffset(1, err).NotTo(HaveOccurred())

		By("Labeling to enforce the namespace where the Operator will run.")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/audit=restricted",
			"pod-security.kubernetes.io/enforce-version=v1.24",
			"pod-security.kubernetes.io/warn=restricted")
		_, err = utils.Run(cmd)

		Expect(err).To(Not(HaveOccurred()))
	})

	AfterAll(func() {
		By("Uninstalling the cert-manager.")
		utils.UninstallCertManager()

		By("Removing the manager namespace.")
		cmd := exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)

		By("Uninstalling the CRDs.")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)

		projectDir, _ := utils.GetProjectDir()

		By("Uninstalling the Verify Directory environment.")
		cmd = exec.Command(
				filepath.Join(projectDir, "test/env/setup_env.sh"),
				"clean")
		_, _ = utils.Run(cmd)
	})

	Context("Verify Directory Operator", func() {
		It("The following should run successfully.", func() {
			var controllerPodName string
			var err               error

			/*
			 * Check to see whether we should push the operator image to
			 * the 'kind' registry.
			 */

			if _, ok := os.LookupEnv("USE_KIND"); ok {
				repo := "icr.io/isvd/verify-directory-operator"
				tag  := "0.0.0"

				if v, ok := os.LookupEnv("IMAGE_TAG_BASE"); ok {
					repo = v
				}

				if v, ok := os.LookupEnv("VERSION"); ok {
					tag = v
				}

				operatorImage := fmt.Sprintf("%s:%s", repo, tag)

				By("Loading the Operator image on Kind.")
				err = utils.LoadImageToKindClusterWithName(operatorImage)
				ExpectWithOffset(1, err).NotTo(HaveOccurred())

				/*
				 * Pre-load the verify directory images as well.
				 */

				images := []string{
						"verify-directory-server", 
						"verify-directory-proxy", 
						"verify-directory-seed",
				}

				for _, name := range images {
					image := fmt.Sprintf("icr.io/isvd/%s:latest", name)
					By(fmt.Sprintf("Loading the %s image on Kind.", name))
					utils.Run(exec.Command("docker", "pull", image))
					err = utils.LoadImageToKindClusterWithName(image)
					ExpectWithOffset(1, err).NotTo(HaveOccurred())
				}
			}

			/*
			 * Install the CRDs.
			 */

			By("Installing the CRDs.")
			cmd := exec.Command("make", "install")
			_, err = utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			/*
			 * Deploy the operator controller.
			 */

			By("Deploying the operator controller.")
			cmd = exec.Command("make", "deploy")
			_, err = utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			/*
			 * Validate that the controller is running.
			 */

			By("Validating that the operator controller pod is running.")
			verifyControllerUp := func() error {

				/*
				 * Retrieve the name of the pod.
				 */

				cmd = exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}{{ " +
					"if not .metadata.deletionTimestamp }}{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)
				podOutput, err := utils.Run(cmd)
				ExpectWithOffset(2, err).NotTo(HaveOccurred())

				podNames := utils.GetNonEmptyLines(string(podOutput))
				if len(podNames) != 1 {
					return fmt.Errorf("Expected 1 controller pod to be " +
							"running, but got %d pods.", 
							len(podNames))
				}

				controllerPodName = podNames[0]

				ExpectWithOffset(2, controllerPodName).Should(
									ContainSubstring("controller-manager"))

				/*
				 * Check to see whether the pod is up and running.
				 */

				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				status, err := utils.Run(cmd)
				ExpectWithOffset(2, err).NotTo(HaveOccurred())

				if string(status) != "Running" {
					return fmt.Errorf("Controller pod is in %s status.", status)
				}

				return nil
			}
			EventuallyWithOffset(1, verifyControllerUp, 
							2 * time.Minute, 5 * time.Second).Should(Succeed())

			/*
			 * Setup the environment.
			 */

			license_key, _ := os.LookupEnv("LICENSE_KEY")
			projectDir,  _ := utils.GetProjectDir()

			By("Setting up the Verify Directory environment.")
			cmd = exec.Command(
				filepath.Join(projectDir, "test/env/setup_env.sh"),
				"init", license_key)

			_, err = utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			/*
			 * Create an instance of the Verify Directory Server.
			 */

			By("Creating an instance of the Operand(CR).")
			cmd = exec.Command("kubectl", "apply", "-f", 
					filepath.Join(projectDir,
					"config/samples/ibm_v1_ibmsecurityverifydirectory.yaml"))
			_, err = utils.Run(cmd)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			/*
			 * Validate that the instance is running.
			 */

			By("Validating that the proxy deployment is running.")
			getProxyDeploymentStatus := func() error {
				cmd = exec.Command("kubectl", "get",
					"deployment", "ibmsecurityverifydirectory-sample-proxy",
					"-o", "jsonpath={.status.readyReplicas}",
				)
				status, err := utils.Run(cmd)

				if err != nil {
					return fmt.Errorf(
							"The proxy deployment has not yet been created.")
				}

				if !strings.Contains(string(status), "1") {
					return fmt.Errorf(
								"The proxy deployment status is %s", status)
				}

				return nil
			}
			EventuallyWithOffset(1, getProxyDeploymentStatus, 
						7 * time.Minute, 15 * time.Second).Should(Succeed())

			/*
			 * Ensure that the status of the custom resource has been updated.
			 */

			By("Validating the status of the custom resource.")
			getStatus := func() error {
				cmd = exec.Command("kubectl", "get", 
					"IBMSecurityVerifyDirectory",
					"ibmsecurityverifydirectory-sample", 
					"-o", "jsonpath={.status.conditions}",
				)
				status, err := utils.Run(cmd)

				ExpectWithOffset(2, err).NotTo(HaveOccurred())

				if !strings.Contains(string(status), "Available") {
					return fmt.Errorf(
						"The status of the CR should be set to Available.")
				}
				return nil
			}
			Eventually(getStatus, 
						time.Minute, 5 * time.Second).Should(Succeed())
		})
	})
})

