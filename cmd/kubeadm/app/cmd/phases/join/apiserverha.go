package phases

import (
	log "k8s.io/klog"
	"k8s.io/kubernetes/cmd/kubeadm/app/cmd/phases/workflow"
	pash "k8s.io/kubernetes/cmd/kubeadm/app/phases/apiserverha"
	kubeconfigutil "k8s.io/kubernetes/cmd/kubeadm/app/util/kubeconfig"
)

func NewApiserverHaPhase() workflow.Phase {
	return workflow.Phase{
		Name:   "apiserver-ha",
		Run:    runApiserverHaPhase,
		Hidden: true,
	}
}

func runApiserverHaPhase(c workflow.RunData) error {
	data := c.(JoinData)
	initCfg, err := data.InitCfg()

	if err != nil {
		log.Errorf("Get iniCfg error, %v", err)
		return err
	}

	if initCfg.ApiserverHA.Enable == false {
		// skip the apiserverHa
		log.Infof("Not open the ApiserverHa, skip the ApiServerHa")
		return nil
	}

	tlsBootstrapCfg, err := data.TLSBootstrapCfg()
	// create the client connect the realserver
	client, err := kubeconfigutil.ToClientSet(tlsBootstrapCfg)

	// modify the tlsBootstrapCfg apisever to the first clusterip
	err = pash.ModifyTlsBootstrapCfgClusterIP(initCfg.ClusterName, initCfg.ControlPlaneEndpoint, tlsBootstrapCfg)
	if err != nil {
		log.Errorf("apiserverha modify the tlsBootrapCfg error: %+v", err)
		return nil
	}

	err = pash.RunProxyContainer(data.Cfg().Discovery.BootstrapToken.APIServerEndpoint, initCfg.ApiserverHA.Image)
	if err != nil {
		log.Errorf("create the native proxy error %+v", err)
		return err
	}

	remoteLoader := &pash.RemoteLoader{
		ClientSet:      client,
		CertificateKey: data.ApiserverHaCert(),
	}

	controlPlane := false
	if data.Cfg().ControlPlane != nil {
		controlPlane = true
	}
	err = pash.BuildApiserverHaNode(initCfg.ClusterName, initCfg.ControlPlaneEndpoint,
		data.Cfg().Discovery.BootstrapToken.APIServerEndpoint,
		initCfg.ClusterConfiguration.ApiserverHA.Image, remoteLoader, controlPlane)
	if err != nil {
		log.Errorf("apiserverha write the kubeconfig and staicpod yaml fails %v", err)
		return err
	}

	return nil
}
