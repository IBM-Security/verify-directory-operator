/* vi: set ts=4 sw=4 noexpandtab : */

/*
 * Copyright contributors to the IBM Security Verify Directory Operator project
 */

package controllers

/*
 * This file contains the functions which are used by the controller to manage
 * access to the server configuration.
 */

/*****************************************************************************/

import (
	corev1  "k8s.io/api/core/v1"

	"errors"

	"github.com/ibm-security/verify-directory-operator/utils"

	"k8s.io/apimachinery/pkg/types"

	"github.com/go-yaml/yaml"
)

/*****************************************************************************/

/*
 * The following function is used to retrieve the server configuration which 
 * is to be used by the pods.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) getServerConfig(
			h *RequestHandle) (error) {

	r.Log.V(1).Info("Entering a function", 
				r.createLogParams(h, "Function", "getServerConfig")...)

	/*
	 * Retrieve the ConfigMap which contains the server configuration.
	 */

	name := h.directory.Spec.Pods.ConfigMap.Server.Name
	key  := h.directory.Spec.Pods.ConfigMap.Server.Key

	config := &corev1.ConfigMap{}
	err	   := r.Get(h.ctx, 
			types.NamespacedName{Name: name, Namespace: h.directory.Namespace}, 
			config)

	if err != nil {
		r.Log.Error(err, "Failed to retrieve the server ConfigMap.",
				r.createLogParams(h, "Name", name)...)

		return err
	}

	r.Log.V(1).Info("Retrieved the server ConfigMap", 
				r.createLogParams(h, "Map", config)...)

	/*
	 * Parse the YAML configuration into a map.  Unfortunately it is not
	 * easy to parse YAML into a generic structure, and so after we have
	 * unmarshalled the data we want to iteratively convert the data into 
	 * a map of strings.
	 */

    var body interface{}
    if err := yaml.Unmarshal([]byte(config.Data[key]), &body); err != nil {
		h.requeueOnError = false
		return err
    }

	body      = utils.ConvertYaml(body)
	body, ok := body.(map[string]interface{})

	if ! ok {
		h.requeueOnError = false
		
		err = errors.New("The server configuration cannot be parsed.")

		r.Log.Error(err, "Failed to unmarshal the ConfigMap data.",
				r.createLogParams(h, "Name", name, "Key", key, 
									"Data", config.Data[key])...)

		return err
	}

	r.Log.V(1).Info("Processed the server ConfigMap", 
				r.createLogParams(h, "Data", body)...)

	/*
	 * Retrieve the general.ports.ldap configuration data.  
	 */

	h.config.port   = 9389
	h.config.secure = false

	ldap := utils.GetYamlValue(body, []string{"general","ports","ldap"}, 
									true, h.directory.Namespace)

	r.Log.V(1).Info("Retrieved the LDAP port configuration.", 
				r.createLogParams(h, "Port", ldap)...)

	if ldap != nil {
		iport, ok := ldap.(int)

		if ! ok {
			h.requeueOnError = false

			err = errors.New(
						"The general.ports.ldap configuration is incorrect.")

			r.Log.Error(err, "Failed to process the ConfigMap data.",
				r.createLogParams(h, "Name", name, "Key", key, 
									"Data", ldap)...)

			return err
		}

		h.config.port = int32(iport)

		if h.config.port == 0 {
			/*
			 * If the port is 0 it means that it has not been activated and
			 * so we need to use the ldaps port.
			 */

			h.config.secure = true
			h.config.port   = 9636

			ldaps := utils.GetYamlValue(
							body, []string{"general","ports","ldaps"}, 
							true, h.directory.Namespace)

			r.Log.V(1).Info("LDAP port is disabled, retrieved the LDAPS port.", 
				r.createLogParams(h, "Port", ldaps)...)

			if ldaps != nil {
				iport, ok := ldaps.(int)

				if ! ok {
					h.requeueOnError = false

					err = errors.New(
						"The general.ports.ldaps configuration is incorrect.")

					r.Log.Error(err, "Failed to process the ConfigMap data.",
						r.createLogParams(h, "Name", name, "Key", key, 
									"Data", ldaps)...)

					return err
				}

				h.config.port = int32(iport)
			}
		}
	}

	/*
	 * Retrieve the license key information.
	 */

	licenseKey := utils.GetYamlValue(body, 
						[]string{"general","license","key"}, 
						false, h.directory.Namespace)

	r.Log.V(1).Info("Retrieved the license key.", 
				r.createLogParams(h, "License.Key", licenseKey)...)

	if licenseKey == nil {
		h.requeueOnError = false

		err = errors.New("The general.license.key configuration is missing.")

		r.Log.Error(err, "Failed to process the ConfigMap data.",
						r.createLogParams(h, "Name", name, "Key", key)...)

		return err
	}

	h.config.licenseKey = licenseKey.(string)

	/*
	 * Retrieve the admin DN.
	 */

	adminDn := utils.GetYamlValue(body, []string{"general","admin","dn"}, 
						false, h.directory.Namespace)

	r.Log.V(1).Info("Retrieved the admin DN.", 
				r.createLogParams(h, "Admin.DN", adminDn)...)

	if adminDn == nil {
		h.config.adminDn = "cn=root"
	} else {
		h.config.adminDn = adminDn.(string)
	}

	/*
	 * Retrieve the admin password.
	 */

	adminPwd := utils.GetYamlValue(body, 
									[]string{"general","admin","pwd"}, 
									false, h.directory.Namespace)

	if adminPwd == nil {
		h.requeueOnError = false

		err = errors.New("The general.admin.pwd configuration is missing.")

		r.Log.Error(err, "Failed to process the ConfigMap data.",
						r.createLogParams(h, "Name", name, "Key", key)...)

		return err

	}

	h.config.adminPwd = adminPwd.(string)

	/*
	 * Retrieve the suffixes which are to be managed.  This is a little bit
	 * more complicated than the standard configuration entries as we need to
	 * extract each of the dn's from the suffixes entry.
	 */

	h.config.suffixes, err = r.getConfigSuffixes(h, body, h.directory.Namespace)

	if err != nil {
		h.requeueOnError = false

		return err
	}

	r.Log.Info("Server configuration information", 
				r.createLogParams(h, "port", h.config.port, 
							"is ssl", h.config.secure, 
							"license.key", h.config.licenseKey,
							"admin.dn", h.config.adminDn,
							"admin.pwd", "XXX",
							"suffixes", h.config.suffixes)...)

	return nil
}

/*****************************************************************************/

/*
 * Retrieve the suffixes which are being managed.  We need to extract each
 * of the DN values from the general.server.suffixes entry.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) getConfigSuffixes(
					h         *RequestHandle,
					body      interface{}, 
					namespace string) ([]string, error) {

	r.Log.V(1).Info("Entering a function", 
				r.createLogParams(h, "Function", "getConfigSuffixes")...)

	var suffixes []string

	entries := utils.GetYamlValue(body, []string{"server","suffixes"}, 
						false, namespace)

	r.Log.V(1).Info("Retrieved the server suffixes.", 
				r.createLogParams(h, "Suffixes", entries)...)

	if entries == nil {
		err := errors.New("The server.suffixes configuration is missing.")

		r.Log.Error(err, "Failed to retrieve the config suffixes.",
						r.createLogParams(h)...)


		return nil, err
	}

	/*
	 * The first thing to do is cast the yaml to the correct type.
	 */

	suffixEntries, ok := entries.([]interface{}) 

	if !ok {
		err := errors.New("The server.suffixes configuration is incorrect.")

		r.Log.Error(err, "Failed to retrieve the config suffixes.",
						r.createLogParams(h, "suffixes", suffixEntries)...)

		return nil, err
	}

	/*
	 * Now we should iterate over the suffix entries, grabbing the DN value
	 * for each entry.
	 */

	for _, entry := range suffixEntries {
		suffixEntry, ok := entry.(map[string]interface{}) 

		r.Log.V(1).Info("Processing a suffix entry.", 
				r.createLogParams(h, "Suffix", suffixEntry)...)

		if !ok {
			err := errors.New("The server.suffixes configuration is incorrect.")

			r.Log.Error(err, "Failed to retrieve the config suffixes.",
						r.createLogParams(h, "suffix", suffixEntry)...)

			return nil, err
		}

		dn := utils.GetYamlValue(suffixEntry, []string{"dn"}, false, namespace)

		r.Log.V(1).Info("Found a DN for the suffix.", 
				r.createLogParams(h, "Suffix", suffixEntry, "DN", dn)...)

		if !ok {
			err := errors.New("The server.suffixes configuration is incorrect.")

			r.Log.Error(err, "Failed to retrieve the config suffixes.",
						r.createLogParams(h, "suffix", suffixEntry, 
											"dn", dn)...)

			return nil, err
		}

		suffixes = append(suffixes, dn.(string))
	}

	return suffixes, nil
}

/*****************************************************************************/

