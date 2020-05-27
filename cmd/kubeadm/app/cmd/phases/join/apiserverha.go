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

	// write the ipvs to point to the real server
	err = pash.WriteIpvs(initCfg.ControlPlaneEndpoint, data.Cfg().Discovery.BootstrapToken.APIServerEndpoint)
	if err != nil {
		log.Errorf("write the ipvs error %v", err)
		return err
	}

	remoteLoader := &pash.RemoteLoader{
		ClientSet:      client,
		CertificateKey: data.ApiserverHaCert(),
	}
	err = pash.BuildApiserverHaNode(initCfg.ClusterName, initCfg.ControlPlaneEndpoint,
		data.Cfg().Discovery.BootstrapToken.APIServerEndpoint, initCfg.Networking.ServiceSubnet,
		initCfg.ClusterConfiguration.ApiserverHA.Image, remoteLoader)
	if err != nil {
		log.Errorf("apiserverha write the kubeconfig and staicpod yaml fails %v", err)
		return err
	}
	/*
		// create the iptable for the network.
		remoteInitConfiguration, err := configutil.FetchInitConfigurationFromCluster(client, os.Stdout, "preflight", true)
		if err != nil {
			return err
		}

		IPTablesDropBit := int32(15)
		IPTablesMasqueradeBit := int32(14)
		if remoteInitConfiguration.ComponentConfigs.Kubelet != nil &&  remoteInitConfiguration.ComponentConfigs.Kubelet.IPTablesDropBit != nil {
			IPTablesDropBit = *remoteInitConfiguration.ComponentConfigs.Kubelet.IPTablesDropBit
		}

		if remoteInitConfiguration.ComponentConfigs.Kubelet != nil &&  remoteInitConfiguration.ComponentConfigs.Kubelet.IPTablesMasqueradeBit != nil {
			IPTablesMasqueradeBit = *remoteInitConfiguration.ComponentConfigs.Kubelet.IPTablesMasqueradeBit
		}

		network := pash.NewAipserverHaNetwork(initCfg.LocalAPIEndpoint.AdvertiseAddress,
			int(IPTablesDropBit),
			int(IPTablesMasqueradeBit))
		err = network.InitNetworkUtil()
		if err != nil {
			return err
		}

		ip, _, err := net.SplitHostPort(initCfg.ControlPlaneEndpoint)
		if err != nil {
			return errors.Wrap(err, "apiserver write the ipvs fails.")
		}
		err = pash.CreateDev(ip)
		if err != nil {
			return err
		}*/

	return nil
}
