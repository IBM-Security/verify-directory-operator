/* vi: set ts=4 sw=4 noexpandtab : */

/*
 * Copyright contributors to the IBM Security Verify Directory Operator project
 */

package controllers

/*
 * This file contains the functions which are used by the controller to handle
 * the creation of the LDAP proxy.
 */

/*****************************************************************************/

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"bytes"
	"errors"
	"fmt"
	"time"
	"strings"

	"github.com/go-yaml/yaml"
	"github.com/ibm-security/verify-directory-operator/utils"

	k8syaml "sigs.k8s.io/yaml"
	ctrl    "sigs.k8s.io/controller-runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

/*****************************************************************************/

/*
 * The following function is used to deploy/redeploy the proxy.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) deployProxy(
			h *RequestHandle) (error) {

	r.Log.V(1).Info("Entering a function", 
				r.createLogParams(h, "Function", "deleteProxy")...)

	/*
	 * Retrieve the ConfigMap which contains the server configuration.  We
	 * convert the YAML representation into JSON as it is easier to process
	 * the raw JSON.  Ideally we would use native GoLang packages to process
	 * the data, but all of these packages require schemas to be defined and
	 * this would be a pain.
	 */

	json, port, err := r.getProxyJson(h)

	if err != nil {
		return err
	}

	/*
	 * Construct the full YAML configuration for the proxy.
	 */

	yaml, err := r.constructProxyYaml(h, json)

	if err != nil {
		return err
	}

	/*
	 * Save the proxy configuration map.
	 */

	updated, err := r.saveProxyConfig(h, yaml)

	if err != nil {
		return err
	}

	/*
	 * If the configuration as been updated we need to create/restart the
	 * proxy.
	 */

	if updated {
		err = r.createProxyDeployment(h, port)

		if err != nil {
			return err
		}
	}

	return nil
}

/*****************************************************************************/

/*
 * The following function is used to retrieve the base proxy configuration data
 * as a JSON string.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) getProxyJson(
			h *RequestHandle) (json string, port int32, err error) {

	r.Log.V(1).Info("Entering a function", 
				r.createLogParams(h, "Function", "getProxyJson")...)

	/*
	 * Retrieve the ConfigMap for the proxy.
	 */

	name := h.directory.Spec.Pods.ConfigMap.Proxy.Name
	key  := h.directory.Spec.Pods.ConfigMap.Proxy.Key

	config := &corev1.ConfigMap{}
	err	    = r.Get(h.ctx, 
			types.NamespacedName{Name: name, Namespace: h.directory.Namespace}, 
			config)

	if err != nil {
 		r.Log.Error(err, "Failed to retrieve the ConfigMap",
						r.createLogParams(h, "ConfigMap.Name", name)...)

		return 
	}

	r.Log.V(1).Info("Retrieved the proxy base configuration.", 
				r.createLogParams(h, "Name", name, "Data", config)...)

	/*
	 * Convert the convert map data to JSON.
	 */

	data, err := k8syaml.YAMLToJSON([]byte(config.Data[key]))

	if err != nil {
 		r.Log.Error(err, "Failed to load the ConfigMap data",
						r.createLogParams(h, "ConfigMap.Name", name,
								"ConfigMap.Key", key)...)
		h.requeueOnError = false

		return
	}

	json = string(data)

	r.Log.V(1).Info("Retrieved the proxy base data.", 
				r.createLogParams(h, "Name", name, "Key", key, "Data", json)...)

	/*
	 * Determine the port which will be used by the proxy.
	 */

	port = 9389

	/*
	 * Parse the YAML configuration into a map.  Unfortunately it is not
	 * easy to parse YAML into a generic structure, and so after we have
	 * unmarshalled the data we want to iteratively convert the data into 
	 * a map of strings.
	 */

	var body interface{}

	if err = yaml.Unmarshal([]byte(config.Data[key]), &body); err != nil {
 		r.Log.Error(err, "Failed to load the ConfigMap data",
						r.createLogParams(h, "ConfigMap.Name", name,
								"ConfigMap.Key", key)...)

		h.requeueOnError = false

		return 
	}

	body      = utils.ConvertYaml(body)
	body, ok := body.(map[string]interface{})

	if ! ok {
		h.requeueOnError = false
		
		err = errors.New("The server configuration cannot be parsed.")

		return
	}

	ldap := utils.GetYamlValue(body, []string{"general","ports","ldap"}, 
						true, h.directory.Namespace)

	r.Log.V(1).Info("Retrieved the proxy LDAP port configuration.", 
				r.createLogParams(h, "Port", ldap)...)

	if ldap != nil {
		iport, ok := ldap.(int)

		if ! ok {
			h.requeueOnError = false

			err = errors.New(
						"The general.ports.ldap configuration is incorrect.")

			return
		}

		port = int32(iport)

		if port == 0 {
			/*
			 * If the port is 0 it means that it has not been activated and
			 * so we need to use the ldaps port.
			 */

			port = 9636

			ldaps := utils.GetYamlValue(
							body, []string{"general","ports","ldaps"}, 
							true, h.directory.Namespace)

			r.Log.V(1).Info("Retrieved the proxy LDAPS port configuration.", 
				r.createLogParams(h, "Port", ldaps)...)

			if ldaps != nil {
				iport, ok := ldaps.(int)

				if ! ok {
					h.requeueOnError = false

					err = errors.New(
						"The general.ports.ldaps configuration is incorrect.")

					return
				}

				port = int32(iport)
			}
		}
	}

	return
}

/*****************************************************************************/

/*
 * The following function is used to construct the proxy configuration YAML.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) constructProxyYaml(
			h    *RequestHandle,
			json string) (yamlConfig string, err error) {

	r.Log.V(1).Info("Entering a function", 
				r.createLogParams(h, "Function", "constructProxyYaml",
						"JSON", json)...)

	/*
	 * Remove the closing '}' from the json string.
	 */

	closingIdx := strings.LastIndex(json, "}")

	if closingIdx == -1 {
 		r.Log.Error(err, "Failed to parse the proxy ConfigMap data",
			r.createLogParams(h, 
				"ConfigMap.Name", h.directory.Spec.Pods.ConfigMap.Proxy.Name,
				"ConfigMap.Key", h.directory.Spec.Pods.ConfigMap.Proxy.Key)...)

		h.requeueOnError = false

		return
	}

	json = json[0:closingIdx]

	/*
	 * Create a slice which contains each of the replica names.
	 */

	var names []string

	for _, pvcName := range h.directory.Spec.Replicas.PVCs {
		names = append(names, r.getReplicaPodName(h.directory, pvcName))
	}
	
	/*
	 * Suffixes......
	 */

	/*
	 * Construct the list of servers which will be used in the suffixes
	 * configuration.  The server configuration will be an
	 * array of entries which look like the following:
	 *    { "name": <pod> }
	 */

	var servers bytes.Buffer

	servers.WriteString("[")

	for idx, pod := range names {
		if idx != 0 {
			servers.WriteString(",")
		}

		servers.WriteString(fmt.Sprintf("{ \"name\": \"%s\" }", pod))
	}

	servers.WriteString("]")

	/*
	 * Create the suffixes entry.  It will look something like the 
	 * following:
	 *   [ { "base": "<suffix>", "name": "split_x", "servers": <servers> } ]
	 */

	var suffixes bytes.Buffer

	suffixes.WriteString("[")

	for idx, suffix := range h.config.suffixes {
		r.Log.V(1).Info("Adding a suffix to the proxy configuration.", 
				r.createLogParams(h, "Suffix", suffix)...)

		if idx != 0 {
			suffixes.WriteString(",")
		}

		entry := fmt.Sprintf(
			"{ \"base\": \"%s\", \"name\": \"split_%d\", \"servers\": %s }", 
			suffix, idx, servers.String())


		suffixes.WriteString(entry)
	}

	suffixes.WriteString("]")

	/*
	 * Server-Groups....
	 *
	 * We will have a single server group which looks like the following:
	 *  [ { "name": "proxy", "servers": [ <server> ] } ]
	 *
	 * Each server in the server group will look like the following:
	 *  { "name": <pod>, "id": <pod>, "target": <pod-addr>, \
	 *    "user" : { "dn": <dn>, "password": <pwd> } }
	 */

	var prefix string

	if h.config.secure {
		prefix = "ldaps"
	} else {
		prefix = "ldap"
	}

	var serverGroups bytes.Buffer

	serverGroups.WriteString("[ { \"name\": \"proxy\", \"servers\": [")

	for idx, pod := range names {
		r.Log.V(1).Info("Adding a server to the proxy configuration.", 
				r.createLogParams(h, "Pod", pod)...)

		if idx != 0 {
			serverGroups.WriteString(",")
		}

		entry := fmt.Sprintf(
			"{ \"name\": \"%s\", \"id\": \"%s\", \"target\": \"%s://%s:%d\", " +
			"\"user\": { \"dn\": \"%s\", \"password\": \"%s\" } }", 
			pod, pod, prefix, pod, h.config.port, 
			h.config.adminDn, h.config.adminPwd)

		serverGroups.WriteString(entry)
	}

	serverGroups.WriteString("] } ]")

	/*
	 * Now we can construct the entire JSON document.
	 */


	config := fmt.Sprintf(
				"%s, \"proxy\": { \"server-groups\": %s, \"suffixes\": %s } }",
				json, serverGroups.String(), suffixes.String())

	/*
	 * Convert the JSON document to YAML.
	 */

	yamlBytes, err := k8syaml.JSONToYAML([]byte(config))

	if err != nil {
 		r.Log.Error(err, "Failed to construct the proxy ConfigMap data",
			r.createLogParams(h, 
				"ConfigMap.Name", h.directory.Spec.Pods.ConfigMap.Proxy.Name,
				"ConfigMap.Key", h.directory.Spec.Pods.ConfigMap.Proxy.Key)...)

		h.requeueOnError = false

		return
	}

	yamlConfig = string(yamlBytes)

	r.Log.V(1).Info("Constructed the proxy configuration.", 
				r.createLogParams(h, "YAML", yamlConfig)...)

	return
}


/*****************************************************************************/

/*
 * The following function is used to save the proxy configuration map.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) saveProxyConfig(
			h    *RequestHandle,
			yaml string) (updated bool, err error) {

	r.Log.V(1).Info("Entering a function", 
				r.createLogParams(h, "Function", "saveProxyConfig",
						"YAML", yaml)...)

	name := utils.GetProxyConfigMapName(h.directory.Name)

	/*
	 * Check to see if the ConfigMap already exists.
	 */

	configMap := &corev1.ConfigMap{}
	err        = r.Get(h.ctx, 
					types.NamespacedName{
						Name:	   name,
						Namespace: h.directory.Namespace }, configMap)

	if err != nil && ! k8serrors.IsNotFound(err) {
 		r.Log.Error(err, "Failed to retrieve the proxy configuration",
			r.createLogParams(h, "ConfigMap.Name", name)...)

		return
	}

	r.Log.V(1).Info("Retrieved the existing proxy configuration.", 
				r.createLogParams(h, "ConfigMap", configMap)...)

	/*
	 * If the ConfigMap already exists we now need to see whether the
	 * configuration data has changed or not.
	 */

	if err == nil {
		if yaml == configMap.Data[utils.ProxyCMKey] {
			r.Log.V(1).Info("The proxy configuration has not changed.", 
				r.createLogParams(h)...)

			updated = false

			return
		}
	}

	/*
	 * If we get this far we know that we need to create/update the
	 * configmap.
	 */

	updated = true

	err = r.createConfigMap(h, name, utils.ProxyCMKey, yaml)

	if err != nil {
		return
	}

	return
}

/*****************************************************************************/

/*
 * The following function will create the proxy deployment if it has not already
 * been created, otherwise it will restart the deployment.  
 */

func (r *IBMSecurityVerifyDirectoryReconciler) createProxyDeployment(
			h    *RequestHandle,
			port int32) (err error) {

	r.Log.V(1).Info("Entering a function", 
				r.createLogParams(h, "Function", "createProxyDeployment",
						"Port", port)...)

	name := utils.GetProxyDeploymentName(h.directory.Name)

	/*
	 * Check to see whether the pod already exists.  If it does we just
	 * trigger a rolling restart, otherwise we create the pod.
	 */

	dep := &appsv1.Deployment{}
	err  = r.Get(h.ctx, 
					types.NamespacedName{
						Name:	   name,
						Namespace: h.directory.Namespace }, dep)

	if err != nil && ! k8serrors.IsNotFound(err) {
 		r.Log.Error(err, "Failed to retrieve the pod information",
			r.createLogParams(h, "Deployment.Name", name)...)

		return
	}

	r.Log.V(1).Info("Retrieved the existing proxy deployment details.", 
				r.createLogParams(h, "Deployment", dep)...)

	if err == nil {
		/*
		 * The deployment already exists and so we just need to perform a 
		 * rolling restart.
		 */

		patch      := client.MergeFrom(dep.DeepCopy())
		annotation := "kubectl.kubernetes.io/restartedAt"

		if dep.Spec.Template.ObjectMeta.Annotations == nil {
			dep.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
		}

		dep.Spec.Template.ObjectMeta.Annotations[annotation] = 
							time.Now().Format("20060102150405")

		r.Log.V(1).Info("Restarting the proxy deployment.", 
				r.createLogParams(h, "Deployment", dep)...)

		err = r.Patch(h.ctx, dep, patch)

		if err != nil {
			r.Log.Error(err, "Failed to restart the proxy deployment",
				r.createLogParams(h, "Deployment.Name", name)...)

			return
		}
	} else {
		configMapName := utils.GetProxyConfigMapName(h.directory.Name)
	
		/*
		 * The pod does not yet exist and so we need to create the pod now.
		 */

		imageName := fmt.Sprintf("%s/verify-directory-proxy:%s", 
					h.directory.Spec.Pods.Image.Repo, 
					h.directory.Spec.Pods.Image.Label)

		/*
		 * The port which is exported by the deployment.
		 */

		ports := []corev1.ContainerPort {{
			Name:          "ldap",
			ContainerPort: port,
			Protocol:      corev1.ProtocolTCP,
		}}

		/*
		 * The volume configuration.
		 */

		volumes := []corev1.Volume {
			{
				Name: "isvd-proxy-config",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: configMapName,
						},
						Items: []corev1.KeyToPath{{
							Key:  utils.ProxyCMKey,
							Path: utils.ProxyCMKey,
						}},
					},
				},
			},
		}

		volumeMounts := []corev1.VolumeMount {
			{
				Name:      "isvd-proxy-config",
				MountPath: "/var/isvd/config",
			},
		}

		/*
		 * Check to see if a proxy PVC has been specified.  If one has been
		 * specified we need to add this PVC to the deployment.
		 */

		if h.directory.Spec.Pods.Proxy.PVC != "" {
			volumes = append(volumes, corev1.Volume {
				Name: "isvd-proxy-data",
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
						ClaimName: h.directory.Spec.Pods.Proxy.PVC,
						ReadOnly:  false,
					},
				},
			})

			volumeMounts = append(volumeMounts, corev1.VolumeMount {
				Name:      "isvd-proxy-data",
				MountPath: "/var/isvd/data",
			})
		}

		/*
		 * Set up the environment variables.
		 */

		env := append(h.directory.Spec.Pods.Env, 
			corev1.EnvVar {
				Name: "YAML_CONFIG_FILE",
				Value: fmt.Sprintf("/var/isvd/config/%s", utils.ProxyCMKey),
			},
		)

		/*
		 * The liveness, and readiness probe definitions.
		 */

		livenessProbe := &corev1.Probe {
			InitialDelaySeconds: 2,
			PeriodSeconds:       10,
			ProbeHandler:        corev1.ProbeHandler {
				Exec: &corev1.ExecAction {
					Command: []string{
						"/sbin/health_check.sh",
						"livenessProbe",
					},
				},
			},
		}

		readinessProbe := &corev1.Probe {
			InitialDelaySeconds: 4,
			PeriodSeconds:       5,
			ProbeHandler:        corev1.ProbeHandler {
				Exec: &corev1.ExecAction {
					Command: []string{
						"/sbin/health_check.sh",
					},
				},
			},
		}

		/*
		 * Set the labels for the pod.
		 */

		labels := map[string]string{
			"app.kubernetes.io/kind":    "IBMSecurityVerifyDirectory",
			"app.kubernetes.io/cr-name": name,
		}

		/*
		 * Finalise the deployment definition.
		 */

		var replicas int32 = 1

		dep := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: h.directory.Namespace,
				Labels:    utils.LabelsForApp(h.directory.Name, name),
			},
	 		Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Selector: &metav1.LabelSelector{
					MatchLabels: labels,
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: labels,
					},
					Spec: corev1.PodSpec{
						Volumes:            volumes,
						ImagePullSecrets:   h.directory.Spec.Pods.Image.ImagePullSecrets,
						ServiceAccountName: h.directory.Spec.Pods.ServiceAccountName,
						Hostname:           name,
						Containers:         []corev1.Container{{
							Env:             env,
							EnvFrom:         h.directory.Spec.Pods.EnvFrom,
							Image:           imageName,
							ImagePullPolicy: h.directory.Spec.Pods.Image.ImagePullPolicy,
							LivenessProbe:   livenessProbe,
							Name:            name,
							Ports:           ports,
							ReadinessProbe:  readinessProbe,
							Resources:       h.directory.Spec.Pods.Resources,
							VolumeMounts:    volumeMounts,
						}},
					},
				},
			},
		}

		/*
		 * Create the deployment.
		 */

		ctrl.SetControllerReference(h.directory, dep, r.Scheme)

		r.Log.Info("Creating a new proxy deployment", 
						r.createLogParams(h, "Deployment.Name", dep.Name)...)

		r.Log.V(1).Info("Proxy deployment details.", 
				r.createLogParams(h, "Deployment", dep)...)

		err = r.Create(h.ctx, dep)

		if err != nil {
			r.Log.Error(err, "Failed to create the proxy deployment",
						r.createLogParams(h, "Deployment.Name", dep.Name)...)

			return 
		}

		/*
		 * Create the cluster service for the proxy.
		 */


		service := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: h.directory.Namespace,
				Labels:    labels,
			},
			Spec: corev1.ServiceSpec{
				Type:     corev1.ServiceTypeClusterIP,
				Selector: labels,
				Ports:    []corev1.ServicePort{{
					Name:       name,
					Protocol:   corev1.ProtocolTCP,
					Port:       port,
					TargetPort: intstr.IntOrString {
						Type:   intstr.Int,
						IntVal: port,
					},
				}},
			},
		}

		ctrl.SetControllerReference(h.directory, service, r.Scheme)

		/*
		 * Create the service.
		 */

		r.Log.Info("Creating a new service for the proxy", 
				r.createLogParams(h, "Deployment.Name", name)...)

		r.Log.V(1).Info("Proxy service details.", 
				r.createLogParams(h, "Service", service)...)

		err := r.Create(h.ctx, service)

		if err != nil {
			r.Log.Error(err, "Failed to create the service for the proxy",
				r.createLogParams(h, "Deployment.Name", name)...)

			return err
		}
	}

	return
}

/*****************************************************************************/

