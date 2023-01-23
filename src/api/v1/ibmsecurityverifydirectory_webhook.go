/* vi: set ts=4 sw=4 noexpandtab : */

/*
 * Copyright contributors to the IBM Security Verify Directory Operator project
 */

package v1

/*****************************************************************************/

import (
	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
    "sigs.k8s.io/controller-runtime/pkg/client"

	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/go-yaml/yaml"
	"github.com/go-ldap/ldap/v3"
	"github.com/ibm-security/verify-directory-operator/utils"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

/*****************************************************************************/

/*
 * The following log object is for logging in this package.
 */

var logger = logf.Log.WithName("webhook").WithName("IBMSecurityVerifyDirectory")

/*
 * The following object allows us to access the Kubernetes API.
 */

var k8s_client client.Client

/*****************************************************************************/

/*
 * The following function is used to set up the Web hook with the Manager.
 */

func (r *IBMSecurityVerifyDirectory) SetupWebhookWithManager(
					mgr ctrl.Manager) error {

    k8s_client = mgr.GetClient()

	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

/*****************************************************************************/

//+kubebuilder:webhook:path=/mutate-ibm-com-v1-ibmsecurityverifydirectory,mutating=true,failurePolicy=fail,sideEffects=None,groups=ibm.com,resources=ibmsecurityverifydirectories,verbs=create;update;delete,versions=v1,name=mibmsecurityverifydirectory.kb.io,admissionReviewVersions=v1

var _ webhook.Defaulter = &IBMSecurityVerifyDirectory{}

/*
 * The following function is used to add default values into the document.
 * This is currently a no-op for this operator.
 */

func (r *IBMSecurityVerifyDirectory) Default() {
}

/*****************************************************************************/

//+kubebuilder:webhook:path=/validate-ibm-com-v1-ibmsecurityverifydirectory,mutating=false,failurePolicy=fail,sideEffects=None,groups=ibm.com,resources=ibmsecurityverifydirectories,verbs=create;update;delete,versions=v1,name=vibmsecurityverifydirectory.kb.io,admissionReviewVersions=v1

var _ webhook.Validator = &IBMSecurityVerifyDirectory{}

/*
 * The ValidateCreate function implements a webhook.Validator so that a webhook 
 * will be registered for the type and invoked for create operations.
 */

func (r *IBMSecurityVerifyDirectory) ValidateCreate() error {

	logger.V(1).Info("Entering a function", 
				r.createLogParams("Function", "ValidateCreate")...)

	return r.validateDocument()
}

/*****************************************************************************/

/*
 * The ValidateUpdate function implements a webhook.Validator so that a webhook 
 * will be registered for the type and invoked for update operations.
 */

func (r *IBMSecurityVerifyDirectory) ValidateUpdate(old runtime.Object) error {

	logger.V(1).Info("Entering a function", 
				r.createLogParams("Function", "ValidateUpdate")...)

	/*
	 * Check to ensure that we are not currently processing this document.
	 */

	if meta.IsStatusConditionTrue(r.Status.Conditions, "InProgress") {
		return errors.New("The last update to this document is still being " +
			"processed by the operator.  Wait until the existing document " +
			"has been fully processed before attempting to update the " +
			"document.")
	}

	/*
	 * Validate the document itself.
	 */

	err := r.validateDocument()

	if err != nil {
		return err
	}

	/*
	 * Check to ensure that the document is not currently in the failing
	 * state.
	 */

	err = r.validateDocumentState()

	if err != nil {
		return err
	}

	/*
	 * Check to ensure that only valid fields have been updated in the
	 * document.
	 */

	oldDirectory, ok := old.(*IBMSecurityVerifyDirectory)

	if !ok {
		return errors.New("An internal error occurred while trying to " +
								"access the original document.")
	}

	err = r.validateDocumentUpdates(oldDirectory)

	if err != nil {
		return err
	}

	/*
	 * Validate the updates which are being made to the pods.
	 */

	err = r.validatePods()

	if err != nil {
		return err
	}

	return nil
}

/*****************************************************************************/

/*
 * The ValidateDelete function implements a webhook.Validator so that a webhook
 * will be registered for the type and invoked for delete operations.  
 */

func (r *IBMSecurityVerifyDirectory) ValidateDelete() error {

	logger.V(1).Info("Entering a function", 
				r.createLogParams("Function", "ValidateDelete")...)

	/*
	 * Ensure that we are not currently processing a document of the same
	 * name.
	 */

	if meta.IsStatusConditionTrue(r.Status.Conditions, "InProgress") {
		return errors.New("The last update to this document is still being " +
			"processed by the operator.  Wait until the existing document " +
			"has been fully processed before attempting to delete the " +
			"document.")
	}

	return nil
}

/*****************************************************************************/

func (r *IBMSecurityVerifyDirectory) validateDocument() error {
	var err error

	logger.V(1).Info("Entering a function", 
				r.createLogParams("Function", "validateDocument")...)

	/*
	 * Validate that each of the PVCs specified in the document exists.
	 */

	for _, pvcName := range r.Spec.Replicas.PVCs {
		err = r.validatePVC(pvcName)

		if err != nil {
			return err
		}
	}

	if r.Spec.Pods.Proxy.PVC != "" {
		err = r.validatePVC(r.Spec.Pods.Proxy.PVC)

		if err != nil {
			return err
		}
	}

	/*
	 * Ensure that the same PVC is not specified multiple times.
	 */

	allPVCs := make(map[string]bool)

	for _, pvcName := range r.Spec.Replicas.PVCs {
		_, ok := allPVCs[pvcName]

		if ok {
			return errors.New(fmt.Sprintf(
				"The document contains a PVC which is referenced more than " +
				"once: %s.  Each PVC in the document must be unique.", pvcName))
		} else {
			allPVCs[pvcName] = true
		}
	}

	if r.Spec.Pods.Proxy.PVC != "" {
		_, ok := allPVCs[r.Spec.Pods.Proxy.PVC]

		if ok {
			return errors.New(fmt.Sprintf(
				"The document contains a PVC which is referenced more than " +
				"once: %s.  Each PVC in the document must be unique.", 
				r.Spec.Pods.Proxy.PVC))
		}
	}

	/*
	 * Validate that each of the ConfigMaps specified in the document
	 * exists.
	 */

	maps := []IBMSecurityVerifyDirectoryConfigMapEntry {
		r.Spec.Pods.ConfigMap.Proxy,
		r.Spec.Pods.ConfigMap.Server,
	}

	for _, entry := range maps {
		err = r.validateConfigMap(entry)

		if err != nil {
			return err
		}
	}

	/*
	 * Validate the the ConfigMap's and Secrets specified within EnvFrom all
	 * exist.
	 */

	for _, envFrom := range r.Spec.Pods.EnvFrom {
		if envFrom.ConfigMapRef != nil {
			optional := envFrom.ConfigMapRef.Optional
			if optional == nil || *optional == false {
				err = r.validateConfigMap(
					IBMSecurityVerifyDirectoryConfigMapEntry {
						Name: envFrom.ConfigMapRef.LocalObjectReference.Name,
						Key:  "",
					})

				if err != nil {
					return err
				}
			}
		}

		if envFrom.SecretRef != nil {
			optional := envFrom.SecretRef.Optional
			if optional == nil || *optional == false {
				err = r.validateSecret(
								envFrom.SecretRef.LocalObjectReference.Name)

				if err != nil {
					return err
				}
			}

		}
	}

	/*
	 * Validate that the proxy ConfigMap does not contain any 
	 * serverGroups or suffixes.
	 */

	err = r.validateProxyConfigMap()

	if err != nil {
		return err
	}

	return nil
}

/*****************************************************************************/

/*
 * This function is used to validate that the specified PVC exists.
 */

func (r *IBMSecurityVerifyDirectory) validatePVC(pvcName string) (err error) {

	logger.V(1).Info("Entering a function", 
		r.createLogParams("Function", "validatePVC", "PVC.Name", pvcName)...)

	pvc := &corev1.PersistentVolumeClaim{}
	err  = k8s_client.Get(context.TODO(), client.ObjectKey{
							Namespace: r.Namespace,
							Name:      pvcName,
					}, pvc)

	logger.V(1).Info("Retrieved the PVC", 
				r.createLogParams("PVC.Name", pvcName, "PVC", pvc)...)

	if err != nil {
		if k8serrors.IsNotFound(err) {
			err = errors.New(
						fmt.Sprintf("The PVC, %s, doesn't exist!", pvcName))
		} else {
			logger.Error(err, "Failed to retieve the requsted PVC.",
					r.createLogParams("PVC", pvcName)...)
		}
	} 

	return 
}

/*****************************************************************************/

/*
 * This function is used to validate that specified ConfigMap, and optionally
 * the specified key in the ConfigMap, exists.
 */

func (r *IBMSecurityVerifyDirectory) validateConfigMap(
				entry IBMSecurityVerifyDirectoryConfigMapEntry) (err error) {

	logger.V(1).Info("Entering a function", 
		r.createLogParams("Function", "validateConfigMap", "Entry", entry)...)

	cm := &corev1.ConfigMap{}
	err = k8s_client.Get(context.TODO(), client.ObjectKey{
							Namespace: r.Namespace,
							Name:      entry.Name,
					}, cm)

	logger.V(1).Info("Retrieved the ConfigMap", 
			r.createLogParams("ConfigMap.Name", entry.Name, "ConfigMap", cm)...)

	if err != nil {
		if k8serrors.IsNotFound(err) {
			err = errors.New(
				fmt.Sprintf("The ConfigMap, %s, doesn't exist!", entry.Name))
		} else {
			logger.Error(err, "Failed to retieve the requsted ConfigMap.",
					r.createLogParams("ConfigMap", entry.Name)...)
		}
	}

	if err == nil && entry.Key != "" {
		_, ok := cm.Data[entry.Key]

		if ! ok {
			err = errors.New(
				fmt.Sprintf("The ConfigMap, %s, does not contain the %s key!",
						entry.Name, entry.Key))
		}
	}

	return 
}

/*****************************************************************************/

/*
 * This function is used to validate that the specified secret exists.
 */

func (r *IBMSecurityVerifyDirectory) validateSecret(
					secretName string) (err error) {

	logger.V(1).Info("Entering a function", 
		r.createLogParams("Function", "validateSecret", "Name", secretName)...)

	secret := &corev1.Secret{}
	err     = k8s_client.Get(context.TODO(), client.ObjectKey{
							Namespace: r.Namespace,
							Name:      secretName,
					}, secret)

	logger.V(1).Info("Retrieved the Secret", 
			r.createLogParams("Secret.Name", secretName, "Secret", secret)...)

	if err != nil {
		if k8serrors.IsNotFound(err) {
			err = errors.New(
					fmt.Sprintf("The secret, %s, doesn't exist!", secretName))
		} else {
			logger.Error(err, "Failed to retieve the requsted Secret.",
					r.createLogParams("Secret", secretName)...)
		}
	}

	return 
}

/*****************************************************************************/

/*
 * This function is used to validate the proxy ConfigMap.  It will ensure that
 * no server groups or suffixes have been defined.
 */

func (r *IBMSecurityVerifyDirectory) validateProxyConfigMap() (err error) {

	logger.V(1).Info("Entering a function", 
		r.createLogParams("Function", "validateProxyConfigMap")...)

	/*
	 * Retrieve the ConfigMap which contains the proxy configuration.
	 */

	name := r.Spec.Pods.ConfigMap.Proxy.Name
	key  := r.Spec.Pods.ConfigMap.Proxy.Key

	config := &corev1.ConfigMap{}
	err	    = k8s_client.Get(context.TODO(), client.ObjectKey{
							Namespace: r.Namespace,
							Name:      name,
					}, config)

	logger.V(1).Info("Retrieved the Proxy ConfigMap", 
			r.createLogParams("ConfigMap.Name", name, "ConfigMap", config)...)

	if err != nil {
		logger.Error(err, "Failed to retieve the requsted ConfigMap.",
					r.createLogParams("ConfigMap", name)...)

		return err
	}

	/*
	 * Parse the YAML configuration into a map.  Unfortunately it is not
	 * easy to parse YAML into a generic structure, and so after we have
	 * unmarshalled the data we want to iteratively convert the data into 
	 * a map of strings.
	 */

    var body interface{}

    if err = yaml.Unmarshal([]byte(config.Data[key]), &body); err != nil {
		logger.Error(err, "Failed to unmarshal the ConfigMap data.",
					r.createLogParams("ConfigMap", name)...)

		return err
    }

	body = utils.ConvertYaml(body)

	logger.V(1).Info("Retrieved the Proxy ConfigMap data", 
			r.createLogParams("ConfigMap.Name", name, "Data", body)...)

	/*
	 * Ensure that the server-groups and suffixes entries don't exist.
	 */

	entries := []string { "server-groups", "suffixes" }

	for _, entry := range entries {
		config := utils.GetYamlValue(body, []string{"proxy", entry}, false, 
						r.Namespace)

		if config != nil {
			err = errors.New(
				fmt.Sprintf("The proxy ConfigMap key, %s:%s, includes the " +
				"proxy.%s configuration entry. This is not allowed as this " +
				"entry will be generated by the operator.", name, key, entry))

			return err
		}
	}

	return nil
}

/*****************************************************************************/

/*
 * This function will check to ensure that the document is not currently in 
 * the failing state.
 */

func (r *IBMSecurityVerifyDirectory) validateDocumentState() (err error) {

	logger.V(1).Info("Entering a function", 
		r.createLogParams("Function", "validateDocumentState")...)

	if meta.IsStatusConditionFalse(r.Status.Conditions, "Available") {
		return errors.New(
			"The deployment is in a failing state which means that it " +
			"cannot be updated and instead must be deleted and then recreated.")
	}

	return nil
}

/*****************************************************************************/

/*
 * This function will check to ensure that only valid fields have been updated 
 * in the document.  We essentially want to ensure that none of the pod
 * configuration has been updated.
 */

func (r *IBMSecurityVerifyDirectory) validateDocumentUpdates(
		old *IBMSecurityVerifyDirectory) (err error) {

	logger.V(1).Info("Entering a function", 
		r.createLogParams("Function", "validateDocumentUpdates")...)

	if ! reflect.DeepEqual(r.Spec.Pods, old.Spec.Pods) {
		return errors.New(
			"The pod.specs entry has been changed.  If you need to modify " +
			"pod.specs you must first delete the document and then recreate " +
			"it.")
	}

	return nil
}

/*****************************************************************************/

/*
 * This function will validate that the pods are in a state which will allow
 * an update.  
 */

func (r *IBMSecurityVerifyDirectory) validatePods() (err error) {

	logger.V(1).Info("Entering a function", 
		r.createLogParams("Function", "validatePods")...)

	/*
	 * Build up the list of pods which are to be added/deleted/left-alone.
	 */

	pods    := make(map[string]string)
	podList := &corev1.PodList{}

	opts := []client.ListOption{
		client.InNamespace(r.Namespace),
		client.MatchingLabels(utils.LabelsForApp(r.Name, "")),
	}

	err = k8s_client.List(context.TODO(), podList, opts...)

	if err != nil {
		logger.Error(err, "Failed to list the pods.", r.createLogParams()...)

		return err
	} 

	logger.V(1).Info("Found existing pods", 
			r.createLogParams("List", podList.Items)...)

	for _, pod := range podList.Items {
		pods[pod.ObjectMeta.Labels[utils.PVCLabel]] = pod.GetName()
	}

	var toBeDeleted []string
	var toBeAdded   []string
	var toBeLeft    []string

	/*
	 * Create a map of the new PVCs from the document.
	 */

	var pvcs = make(map[string]bool)

	for _, pvcName := range r.Spec.Replicas.PVCs {
		pvcs[pvcName] = true
	}

	/*
	 * Work out the entries to be deleted.  This consists of the existing
	 * replicas which don't appear in the current list of replicas.  At the
	 * same time we work out which entries are to be left alone.  This will
	 * be those entries in the list of running pods which still appear in the
	 * curent document.
	 */

	for key, _:= range pods {
		if _, ok := pvcs[key]; !ok {
			toBeDeleted = append(toBeDeleted, key)
		} else {
			toBeLeft = append(toBeLeft, pods[key])
		}
	}

	/*
	 * Work out the entries to be added.  This consists of those replicas
	 * which appear in the document which are not in the existing list of
	 * replicas.
	 */

	for _, pvc := range r.Spec.Replicas.PVCs {
		if _, ok := pods[pvc]; !ok {
			toBeAdded = append(toBeAdded, pvc)
		}
	}

	logger.V(1).Info("Processed the pods", 
			r.createLogParams("ToBeDeleted", toBeDeleted, "ToBeAdded", 
					toBeAdded, "ToBeLeft", toBeLeft)...)

	/*
	 * If there are no changes to the pods we don't need to do anything
	 * extra.
	 */

	if len(toBeDeleted) == 0 && len(toBeAdded) == 0 {
		return nil
	}

	/*
	 * For each pod which is to be left-alone, validate that the pod is
	 * currently running and ready.
	 */

	for _, podName := range(toBeLeft) {
		pod := &corev1.Pod{}

		err  = k8s_client.Get(context.TODO(), client.ObjectKey{
							Namespace: r.Namespace,
							Name:      podName,
					}, pod)

		logger.V(1).Info("Retrieved the pod", 
			r.createLogParams("Pod.Name", podName, "Pod", pod)...)

		if err != nil {
			logger.Error(err, "Failed to retrieve the pod.", 
								r.createLogParams("Pod", podName)...)

			return err
		}

		if pod.Status.Phase != corev1.PodRunning || 
						!pod.Status.ContainerStatuses[0].Ready {
			return errors.New(fmt.Sprintf("The pod, %s, is not currently " +
				"ready.  You must wait until all pods are ready before " +
				"attempting to edit the document.", podName))
		}
	}

	/*
	 * If there are any pods which are to be deleted check to ensure that the
	 * pod is not currently the primary write master in the proxy.
	 */

	primaries, err := r.getPrimaryWriteMasters()

	if err != nil {
		return err
	}

	for _, pvc := range toBeDeleted {
		if _, ok := primaries[pvc]; ok {
			return errors.New(fmt.Sprintf("The pvc, %s, is currently " +
				"being used as the primary write master by the LDAP proxy. " +
				"As a result it is not currently possible to remove this " +
				"PVC.", pvc))
		}
	}

	return nil
}

/*****************************************************************************/

func (r *IBMSecurityVerifyDirectory) getPrimaryWriteMasters() (primaries map[string]bool, err error) {

	logger.V(1).Info("Entering a function", 
		r.createLogParams("Function", "getPrimaryWriteMasters")...)

	primaries = make(map[string]bool)

	/*
	 * Work out the service IP address and port for the proxy.
	 */

	service := &corev1.Service{}
	err      = k8s_client.Get(context.TODO(), client.ObjectKey{
						Namespace: r.Namespace,
						Name:      utils.GetProxyDeploymentName(r.Name),
					}, service)

	if err != nil {
		logger.Error(err, "Failed to locate the proxy service.",
					r.createLogParams()...)

		return
	}

	logger.V(1).Info("Retrieved the proxy service", 
			r.createLogParams("Service", service)...)

	address := service.Spec.ClusterIP
	port    := service.Spec.Ports[0].Port

	/*
	 * Work out some of the configuration information for the proxy.
	 */

	configMapName := utils.GetProxyConfigMapName(r.Name)

	config := &corev1.ConfigMap{}
	err	    = k8s_client.Get(context.TODO(), client.ObjectKey{
						Namespace: r.Namespace,
						Name:      configMapName }, 
					config)

	logger.V(1).Info("Retrieved the proxy ConfigMap", 
			r.createLogParams("ConfigMap", config)...)

	if err != nil {
 		logger.Error(err, "Failed to retrieve the ConfigMap",
						r.createLogParams("ConfigMap.Name", configMapName)...)

		return 
	}

	/*
	 * Parse the configuration data into a map.
	 */

    var body interface{}

    err = yaml.Unmarshal([]byte(config.Data[utils.ProxyCMKey]), &body)

	if err != nil {
		logger.Error(err, "Failed to decode the data from the ConfigMap.",
				r.createLogParams("ConfigMap.Name", configMapName,
				"ConfigMap.Key", utils.ProxyCMKey)...)

		return
    }

	logger.V(1).Info("Retrieved the proxy ConfigMap data", 
			r.createLogParams("Key", utils.ProxyCMKey, "Data", body)...)


	body      = utils.ConvertYaml(body)
	body, ok := body.(map[string]interface{})

	if ! ok {
		err = errors.New("Failed to decode the ConfigMap for the proxy.")

		logger.Error(err, "Failed to decode the data from the ConfigMap.",
				r.createLogParams("ConfigMap.Name", configMapName,
				"ConfigMap.Key", utils.ProxyCMKey)...)

		return 
	}

	/*
	 * Retrieve the data from the map.
	 */

	secure    := false
	adminDn   := "cn=root"
	adminPwd  := ""

	entry := utils.GetYamlValue(body, []string{"general","ports","ldap"}, 
						true, r.Namespace)

	if entry != nil {
		iport, ok := entry.(int)

		if ! ok {
			err = errors.New(
						"The general.ports.ldap configuration is incorrect.")

			return
		}

		if (iport == 0) {
			secure = true
		}
	}

	entry = utils.GetYamlValue(body, []string{"general","admin","dn"}, 
						true, r.Namespace)

	if entry != nil {
		adminDn = entry.(string)
	}

	entry = utils.GetYamlValue(body, []string{"general","admin","pwd"}, 
						true, r.Namespace)

	if entry == nil {
		err = errors.New("The general.admin.pwd configuration is missing.")

		return
	}

	adminPwd = entry.(string)

	/*
	 * Connect to the server.
	 */

	logger.V(1).Info("Connecting to the LDAP server", 
			r.createLogParams("Address", address, "Port", port)...)

	var l *ldap.Conn

	if secure {
		l, err = ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", address, port), 
				ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	} else {
		l, err = ldap.DialURL(fmt.Sprintf("ldap://%s:%d", address, port))
	}

	if err != nil {
		logger.Error(err, "Failed to connect to the LDAP proxy", 
					r.createLogParams()...)

		return
	}
	defer l.Close()

	/*
	 * Bind to the server.
	 */
	 
	logger.V(1).Info("Binding to the LDAP server", 
			r.createLogParams("DN", adminDn)...)

	err = l.Bind(adminDn, adminPwd)
	if err != nil {
		logger.Error(err, "Failed to bind to the LDAP proxy",
					r.createLogParams()...)

		return
	}

	/*
	 * Search the proxy to find out who the primary write master is.
	 */

	searchRequest := ldap.NewSearchRequest(
		"cn=partitions,cn=proxy,cn=monitor",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		nil,
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		logger.Error(err, 
			"Failed to locate the split information from the LDAP proxy",
			r.createLogParams()...)

		return
	}

	logger.V(1).Info("Performed a search against the LDAP server", 
			r.createLogParams("Results", sr)...)

	if len(sr.Entries) == 0 {
		err = errors.New(
			"The split information does not exist in the LDAP proxy.")

		logger.Error(err, "Entry does not exist.", r.createLogParams()...)

		return
	}

	/*
	 * Process the search results looking for any primary write masters.
	 */

	expr := fmt.Sprintf(".*ibm-slapdProxyBackendServerName=%s-(.[^,]*)", 
						strings.ToLower(r.Name))
	re   := regexp.MustCompile(expr)

	for _, entry := range(sr.Entries) {
		for _, attr := range(entry.Attributes) {
			if attr.Name == "ibm-slapdProxyCurrentServerRole" {
				if len(attr.Values) == 1 && 
								attr.Values[0] == "primarywriteserver" {
					match := re.FindStringSubmatch(entry.DN)

					if len(match) > 1 {
						primaries[match[1]] = true
					}
				}
			}
		}
	}

	logger.Info("Found primary write servers.", 
			r.createLogParams("PVC.Names", primaries)...)

	return
}

/*****************************************************************************/

/*
 * This function will create the logging parameters for a request.
 */

func (r *IBMSecurityVerifyDirectory) createLogParams(
			extras ...interface{}) []interface{} {

	params := []interface{}{
				"Deployment.Namespace", r.Namespace,
				"Deployment.Name",      r.Name,
			}

	for _, extra := range extras {
		params = append(params, extra)
	}

	return params
}
/*****************************************************************************/

