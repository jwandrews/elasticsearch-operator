/*
Copyright (c) 2017, UPMC Enterprises
All rights reserved.
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name UPMC Enterprises nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL UPMC ENTERPRISES BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
*/

package k8sutil

import (
	"fmt"

	"github.com/sirupsen/logrus"
	myspec "github.com/upmc-enterprises/elasticsearch-operator/pkg/apis/elasticsearchoperator/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	elasticsearchCertspath = "/elasticsearch/config/certs"
	clusterHealthURL       = "/_nodes/_local"
)

// TODO just mount the secret needed by each deployment
// DeleteDeployment deletes a deployment
func (k *K8sutil) DeleteDeployment(clusterName, namespace, deploymentType string) error {

	labelSelector := fmt.Sprintf("component=elasticsearch-%s,role=%s", clusterName, deploymentType)

	// Get list of deployments
	deployments, err := k.Kclient.AppsV1().Deployments(namespace).List(k.Context, metav1.ListOptions{LabelSelector: labelSelector})

	if err != nil {
		logrus.Error("Could not get deployments! ", err)
	}

	for _, deployment := range deployments.Items {
		//Scale the deployment down to zero (https://github.com/kubernetes/client-go/issues/91)
		deployment.Spec.Replicas = new(int32)
		deployment, err := k.Kclient.AppsV1().Deployments(namespace).Update(k.Context, &deployment, metav1.UpdateOptions{})

		if err != nil {
			logrus.Errorf("Could not scale deployment: %s ", deployment.Name)
		} else {
			logrus.Infof("Scaled deployment: %s to zero", deployment.Name)
		}

		err = k.Kclient.AppsV1().Deployments(namespace).Delete(k.Context, deployment.Name, metav1.DeleteOptions{})

		if err != nil {
			logrus.Errorf("Could not delete deployments: %s ", deployment.Name)
		} else {
			logrus.Infof("Deleted deployment: %s", deployment.Name)
		}
	}

	// Get list of ReplicaSets
	replicaSets, err := k.Kclient.AppsV1().ReplicaSets(namespace).List(k.Context, metav1.ListOptions{LabelSelector: labelSelector})

	if err != nil {
		logrus.Error("Could not get replica sets! ", err)
	}

	for _, replicaSet := range replicaSets.Items {
		err := k.Kclient.AppsV1().ReplicaSets(namespace).Delete(k.Context, replicaSet.Name, metav1.DeleteOptions{})

		if err != nil {
			logrus.Errorf("Could not delete replica sets: %s ", replicaSet.Name)
		} else {
			logrus.Infof("Deleted replica set: %s", replicaSet.Name)
		}
	}

	return nil
}

// CreateClientDeployment creates the client deployment
func (k *K8sutil) CreateClientDeployment(baseImage string, replicas *int32, javaOptions, clientJavaOptions string,
	resources myspec.Resources, imagePullSecrets []myspec.ImagePullSecrets, imagePullPolicy, serviceAccountName, clusterName, statsdEndpoint, networkHost, namespace string, useSSL *bool, affinity corev1.Affinity, annotations map[string]string) error {

	component := fmt.Sprintf("elasticsearch-%s", clusterName)
	discoveryServiceNameCluster := fmt.Sprintf("%s-%s", discoveryServiceName, clusterName)

	deploymentName := fmt.Sprintf("%s-%s", clientDeploymentName, clusterName)
	isNodeMaster := "false"
	role := "client"

	// Check if deployment exists
	deployment, err := k.Kclient.AppsV1().Deployments(namespace).Get(k.Context, deploymentName, metav1.GetOptions{})

	enableSSL := "false"
	if useSSL != nil && *useSSL {
		enableSSL = "true"
	}

	// parse javaOptions and see if client nodes are using different options
	// if using the legacy (global) java-options, then this will be applied to all nodes that dont have custom settings
	esJavaOps := ""

	if clientJavaOptions != "" {
		esJavaOps = clientJavaOptions
	} else {
		esJavaOps = javaOptions
	}

	if len(deployment.Name) == 0 {
		logrus.Infof("Deployment %s not found, creating...", deploymentName)
		clusterSecretName := fmt.Sprintf("%s-%s", secretName, clusterName)

		// Parse CPU / Memory
		limitCPU, _ := resource.ParseQuantity(resources.Limits.CPU)
		limitMemory, _ := resource.ParseQuantity(resources.Limits.Memory)
		requestCPU, _ := resource.ParseQuantity(resources.Requests.CPU)
		requestMemory, _ := resource.ParseQuantity(resources.Requests.Memory)
		scheme := corev1.URISchemeHTTP
		if useSSL != nil && *useSSL {
			scheme = corev1.URISchemeHTTPS
		}
		probe := &corev1.Probe{
			TimeoutSeconds:      30,
			InitialDelaySeconds: 10,
			FailureThreshold:    15,
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Port:   intstr.FromInt(9200),
					Path:   clusterHealthURL,
					Scheme: scheme,
				},
			},
		}
		deployment := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name: deploymentName,
				Labels: map[string]string{
					"component": component,
					"role":      role,
					"name":      deploymentName,
					"cluster":   clusterName,
				},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: replicas,
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"component": component,
							"role":      role,
							"name":      deploymentName,
							"cluster":   clusterName,
						},
						Annotations: annotations,
					},
					Spec: corev1.PodSpec{
						Affinity: &affinity,
						Containers: []corev1.Container{
							{
								Name: deploymentName,
								SecurityContext: &corev1.SecurityContext{
									Privileged: &[]bool{true}[0],
									Capabilities: &corev1.Capabilities{
										Add: []corev1.Capability{
											"IPC_LOCK",
										},
									},
								},
								Image:           baseImage,
								ImagePullPolicy: corev1.PullPolicy(imagePullPolicy),
								Env: []corev1.EnvVar{
									{
										Name: "NAMESPACE",
										ValueFrom: &corev1.EnvVarSource{
											FieldRef: &corev1.ObjectFieldSelector{
												FieldPath: "metadata.namespace",
											},
										},
									},
									{
										Name:  "CLUSTER_NAME",
										Value: clusterName,
									},
									{
										Name:  "NODE_MASTER",
										Value: isNodeMaster,
									},
									{
										Name:  "NODE_DATA",
										Value: "false",
									},
									{
										Name:  "HTTP_ENABLE",
										Value: "true",
									},
									{
										Name:  "SEARCHGUARD_SSL_TRANSPORT_ENABLED",
										Value: enableSSL,
									},
									{
										Name:  "SEARCHGUARD_SSL_HTTP_ENABLED",
										Value: enableSSL,
									},
									{
										Name:  "ES_JAVA_OPTS",
										Value: esJavaOps,
									},
									{
										Name:  "STATSD_HOST",
										Value: statsdEndpoint,
									},
									{
										Name:  "DISCOVERY_SERVICE",
										Value: discoveryServiceNameCluster,
									},
									{
										Name:  "NETWORK_HOST",
										Value: networkHost,
									},
								},
								Ports: []corev1.ContainerPort{
									{
										Name:          "transport",
										ContainerPort: 9300,
										Protocol:      corev1.ProtocolTCP,
									},
									{
										Name:          "http",
										ContainerPort: 9200,
										Protocol:      corev1.ProtocolTCP,
									},
								},
								ReadinessProbe: probe,
								LivenessProbe:  probe,
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "storage",
										MountPath: "/data",
									},
									{
										Name:      clusterSecretName,
										MountPath: elasticsearchCertspath,
									},
								},
								Resources: corev1.ResourceRequirements{
									Limits: corev1.ResourceList{
										"cpu":    limitCPU,
										"memory": limitMemory,
									},
									Requests: corev1.ResourceList{
										"cpu":    requestCPU,
										"memory": requestMemory,
									},
								},
							},
						},
						Volumes: []corev1.Volume{
							{
								Name: "storage",
								VolumeSource: corev1.VolumeSource{
									EmptyDir: &corev1.EmptyDirVolumeSource{},
								},
							},
							{
								Name: clusterSecretName,
								VolumeSource: corev1.VolumeSource{
									Secret: &corev1.SecretVolumeSource{
										SecretName: clusterSecretName,
									},
								},
							},
						},
						ImagePullSecrets: TemplateImagePullSecrets(imagePullSecrets),
					},
				},
			},
		}

		if useSSL != nil && !*useSSL {
			// Do not configure Volume and VolumeMount for certs
			volumeMounts := deployment.Spec.Template.Spec.Containers[0].VolumeMounts
			for index, volumeMount := range volumeMounts {
				if volumeMount.Name == clusterSecretName {
					if index < (len(volumeMounts) - 1) {
						volumeMounts = append(volumeMounts[:index], volumeMounts[index+1:]...)
					} else {
						volumeMounts = volumeMounts[:index]
					}
					break
				}
			}
			deployment.Spec.Template.Spec.Containers[0].VolumeMounts = volumeMounts

			volumes := deployment.Spec.Template.Spec.Volumes
			for index, volume := range volumes {
				if volume.Name == clusterSecretName {
					if index < (len(volumes) - 1) {
						volumes = append(volumes[:index], volumes[index+1:]...)
					} else {
						volumes = volumes[:index]
					}
					break
				}
			}
			deployment.Spec.Template.Spec.Volumes = volumes
		}

		if serviceAccountName != "" {
			deployment.Spec.Template.Spec.ServiceAccountName = serviceAccountName
		}

		_, err := k.Kclient.AppsV1().Deployments(namespace).Create(k.Context, deployment, metav1.CreateOptions{})

		if err != nil {
			logrus.Error("Could not create client deployment: ", err)
			return err
		}
	} else {
		if err != nil {
			logrus.Error("Could not get client deployment! ", err)
			return err
		}

		//scale replicas?
		if deployment.Spec.Replicas != replicas {
			deployment.Spec.Replicas = replicas

			if _, err := k.Kclient.AppsV1().Deployments(namespace).Update(k.Context, deployment, metav1.UpdateOptions{}); err != nil {
				logrus.Error("Could not scale deployment: ", err)
				return err
			}
		}
	}

	return nil
}

// CreateKibanaDeployment creates a deployment of Kibana
func (k *K8sutil) CreateKibanaDeployment(baseImage, clusterName, namespace string, imagePullSecrets []myspec.ImagePullSecrets, imagePullPolicy string, serviceAccountName string, useSSL *bool) error {

	replicaCount := int32(1)

	component := fmt.Sprintf("elasticsearch-%s", clusterName)

	deploymentName := fmt.Sprintf("%s-%s", kibanaDeploymentName, clusterName)

	enableSSL := "true"
	scheme := corev1.URISchemeHTTPS
	if useSSL != nil && !*useSSL {
		enableSSL = "false"
		scheme = corev1.URISchemeHTTP
	}

	// Check if deployment exists
	deployment, err := k.Kclient.AppsV1().Deployments(namespace).Get(k.Context, deploymentName, metav1.GetOptions{})
	probe := &corev1.Probe{
		TimeoutSeconds:      30,
		InitialDelaySeconds: 1,
		FailureThreshold:    10,
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Port:   intstr.FromInt(5601),
				Path:   "/", //TODO since kibana doesn't have a healthcheck url, the root is enough
				Scheme: scheme,
			},
		},
	}
	if len(deployment.Name) == 0 {
		logrus.Infof("%s not found, creating...", deploymentName)

		deployment := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name: deploymentName,
				Labels: map[string]string{
					"component": component,
					"role":      "kibana",
					"name":      deploymentName,
				},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicaCount,
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"component": component,
							"role":      "kibana",
							"name":      deploymentName,
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							corev1.Container{
								Name:            deploymentName,
								Image:           baseImage,
								ImagePullPolicy: corev1.PullPolicy(imagePullPolicy),
								Env: []corev1.EnvVar{
									corev1.EnvVar{
										Name:  "ELASTICSEARCH_URL",
										Value: GetESURL(component, useSSL),
									},
									corev1.EnvVar{
										Name:  "NODE_DATA",
										Value: "false",
									},
								},
								Ports: []corev1.ContainerPort{
									corev1.ContainerPort{
										Name:          "http",
										ContainerPort: 5601,
										Protocol:      corev1.ProtocolTCP,
									},
								},
								LivenessProbe:  probe,
								ReadinessProbe: probe,
							},
						},
						ImagePullSecrets: TemplateImagePullSecrets(imagePullSecrets),
					},
				},
			},
		}

		if *useSSL {
			// SSL config

			deployment.Spec.Template.Spec.Containers[0].Env = append(deployment.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "ELASTICSEARCH_SSL_CERTIFICATEAUTHORITIES",
					Value: fmt.Sprintf("%s/ca.pem", elasticsearchCertspath),
				},
				corev1.EnvVar{
					Name:  "SERVER_SSL_ENABLED",
					Value: enableSSL,
				},
				corev1.EnvVar{
					Name:  "SERVER_SSL_KEY",
					Value: fmt.Sprintf("%s/kibana-key.pem", elasticsearchCertspath),
				},
				corev1.EnvVar{
					Name:  "SERVER_SSL_CERTIFICATE",
					Value: fmt.Sprintf("%s/kibana.pem", elasticsearchCertspath),
				},
			)

			// Certs volume
			deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, corev1.Volume{
				Name: fmt.Sprintf("%s-%s", secretName, clusterName),
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: fmt.Sprintf("%s-%s", secretName, clusterName),
					},
				},
			})
			// Mount certs
			deployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(deployment.Spec.Template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
				Name:      fmt.Sprintf("%s-%s", secretName, clusterName),
				MountPath: elasticsearchCertspath,
			})
		}

		if serviceAccountName != "" {
			deployment.Spec.Template.Spec.ServiceAccountName = serviceAccountName
		}

		_, err := k.Kclient.AppsV1().Deployments(namespace).Create(k.Context, deployment, metav1.CreateOptions{})

		if err != nil {
			logrus.Error("Could not create kibana deployment: ", err)
			return err
		}
	} else {
		if err != nil {
			logrus.Error("Could not get kibana deployment! ", err)
			return err
		}
	}

	return nil
}

// CreateCerebroDeployment creates a deployment of Cerebro
func (k *K8sutil) CreateCerebroDeployment(baseImage, clusterName, namespace, cert string, imagePullSecrets []myspec.ImagePullSecrets, imagePullPolicy string, serviceAccountName string, useSSL *bool) error {
	replicaCount := int32(1)
	component := fmt.Sprintf("elasticsearch-%s", clusterName)
	deploymentName := fmt.Sprintf("%s-%s", cerebroDeploymentName, clusterName)

	// Check if deployment exists
	deployment, err := k.Kclient.AppsV1().Deployments(namespace).Get(k.Context, deploymentName, metav1.GetOptions{})
	probe := &corev1.Probe{
		TimeoutSeconds:      30,
		InitialDelaySeconds: 1,
		FailureThreshold:    10,
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Port:   intstr.FromInt(9000),
				Path:   "/#/connect", //TODO since cerebro doesn't have a healthcheck url, this path is enough
				Scheme: corev1.URISchemeHTTP,
			},
		},
	}
	if len(deployment.Name) == 0 {
		logrus.Infof("Deployment %s not found, creating...", deploymentName)

		deployment := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name: deploymentName,
				Labels: map[string]string{
					"component": component,
					"role":      "cerebro",
					"name":      deploymentName,
				},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicaCount,
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"component": component,
							"role":      "cerebro",
							"name":      deploymentName,
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:            deploymentName,
								Image:           baseImage,
								ImagePullPolicy: corev1.PullPolicy(imagePullPolicy),
								Command: []string{
									"bin/cerebro",
									"-Dconfig.file=/usr/local/cerebro/cfg/application.conf",
								},
								Ports: []corev1.ContainerPort{
									{
										Name:          "http",
										ContainerPort: 9000,
										Protocol:      corev1.ProtocolTCP,
									},
								},
								ReadinessProbe: probe,
								LivenessProbe:  probe,
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      cert,
										MountPath: "/usr/local/cerebro/cfg",
									},
								},
							},
						},
						Volumes: []corev1.Volume{
							{
								Name: cert,
								VolumeSource: corev1.VolumeSource{
									ConfigMap: &corev1.ConfigMapVolumeSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: cert,
										},
									},
								},
							},
						},
						ImagePullSecrets: TemplateImagePullSecrets(imagePullSecrets),
					},
				},
			},
		}

		if *useSSL {
			// Certs volume
			deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes,
				corev1.Volume{
					Name: fmt.Sprintf("%s-%s", secretName, clusterName),
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: fmt.Sprintf("%s-%s", secretName, clusterName),
						},
					},
				},
			)
			// Mount certs
			deployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(deployment.Spec.Template.Spec.Containers[0].VolumeMounts,
				corev1.VolumeMount{
					Name:      fmt.Sprintf("%s-%s", secretName, clusterName),
					MountPath: elasticsearchCertspath,
				},
			)
		}

		if serviceAccountName != "" {
			deployment.Spec.Template.Spec.ServiceAccountName = serviceAccountName
		}

		if _, err := k.Kclient.AppsV1().Deployments(namespace).Create(k.Context, deployment, metav1.CreateOptions{}); err != nil {
			logrus.Error("Could not create cerebro deployment: ", err)
			return err
		}
	} else {
		if err != nil {
			logrus.Error("Could not get cerebro deployment! ", err)
			return err
		}
	}

	return nil
}
