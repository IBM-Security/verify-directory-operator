/* vi: set ts=4 sw=4 noexpandtab : */

/*
 * Copyright contributors to the IBM Security Verify Directory Operator project
 */

package controllers

/*
 * This file contains the functions which are used by the controller to handle
 * the creation of a deployment/replica.
 */

/*****************************************************************************/

import (
)

/*****************************************************************************/

/*
 * The following function is used to deploy/redeploy the proxy.
 */

func (r *IBMSecurityVerifyDirectoryReconciler) deployProxy(
			h          *RequestHandle) (error) {

	/*
	 * Processing:
	 *   recreate the proxy configuration
	 *   if the proxy configuration has changed:
	 *     start/restart of the proxy
	 *     wait for the proxy to start
	 */

	// XXX: Proxy
	return nil
}

/*****************************************************************************/

