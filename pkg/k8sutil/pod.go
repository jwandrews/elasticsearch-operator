package k8sutil

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GetMasterNodes returns all master node pods
func (k *K8sutil) GetMasterNodes(namespace string, name string) (*v1.PodList, error) {
	return k.Kclient.CoreV1().Pods(namespace).List(k.Context, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("component=elasticsearch-%s,role=master", name),
	})
}
