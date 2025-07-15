package kubelogin

import (
	"flag"
	"fmt"

	"k8s.io/klog/v2"
)

// kubelogin uses klog which has a different log level than logrus
func SetKlogV(logLevel int32) error {
	var fs flag.FlagSet
	klog.InitFlags(&fs)
	return fs.Set("v", fmt.Sprintf("%d", logLevel))
}
