package apiserverha

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/kubernetes/cmd/kubeadm/app/cmd/options"
	cmdutil "k8s.io/kubernetes/cmd/kubeadm/app/cmd/util"
	constants "k8s.io/kubernetes/cmd/kubeadm/app/constants"
	kubeadmconstants "k8s.io/kubernetes/cmd/kubeadm/app/constants"
	kubeconfigutil "k8s.io/kubernetes/cmd/kubeadm/app/util/kubeconfig"
	"k8s.io/kubernetes/cmd/kubeadm/app/util/pkiutil"
	staticpodutil "k8s.io/kubernetes/cmd/kubeadm/app/util/staticpod"
	"k8s.io/kubernetes/pkg/kubelet/kubeletconfig/util/log"
	utilsexec "k8s.io/utils/exec"
	"os"
	"path/filepath"
	"strings"
)

var apiserverHAExample = cmdutil.Examples(`
	# Prepares the machine for serving a control plane
	kubeadm join phase control-plane-prepare --apiserver-ha-mod
	kubeadm init phase control-plane-prepare --apiserver-ha-mod
`)

const (
	ApiserverHaKubeconfContainerPath    = "/etc/kubernetes/"
	ApiserverHaConfigFileHostPath       = "/var/lib/apiserver-ha/"
	ApiserverHAProxyConfigContainerPath = "/etc/haproxy/"
)

type KubeConfigSpec struct {
	APIServer   string
	ClusterName string
	ClientName  string
	CAKey       crypto.Signer
	CACert      *x509.Certificate
}

//////////// build apiserver hs node ///////////
func BuildApiserverHaNode(clusterName, controlPlaneEndpoint, bootstrapTokenAPIServerEndpoint,
	apiserverHAImage string, loader CertsLoader, controlPlan bool) error {
	// create the kubeconfig file into disk
	kubeConfSpec, err := BuildKubeConfigSpec(clusterName, controlPlaneEndpoint, loader)
	if err != nil {
		log.Errorf("Create the Sepc fails %+v", err)
		return err
	}

	err = WriteKubeConfToDisk(kubeConfSpec)
	if err != nil {
		log.Errorf("Write the Sepc to the disk fails %+v", err)
		return err
	}

	// crate the apiserver-ha static pod
	err = BuildManifestsAndWriteToDisk(bootstrapTokenAPIServerEndpoint,
		kubeadmconstants.GetStaticPodDirectory(),
		apiserverHAImage, controlPlan)

	if err != nil {
		log.Errorf("Write the Sepc to the disk fails %v", err)
		return errors.Errorf("Create the apiserverha static pod yaml file error, %v", err)
	}

	return nil
}

func BuildManifestsAndWriteToDisk(apiserver, manifestDir, image string, controlPlan bool) error {
	spec := buildStaticPod(apiserver, image, controlPlan)

	// writes the StaticPodSpec to disk
	if err := staticpodutil.WriteStaticPodToDisk(options.ApiserverHA, manifestDir, spec); err != nil {
		return errors.Wrapf(err, "failed to create static pod manifest file for %q", options.ApiserverHA)
	}
	return nil
}

func buildStaticPod(initApiserver, image string, controlPlan bool) v1.Pod {
	args := []string{
		strings.Join([]string{"--apiServer", initApiserver}, "="),
	}

	if controlPlan {
		// if is the controlplan, the add the parma telnet the haproxy open the port
		args = append(args, strings.Join([]string{"--controlPlan", "true"}, "="))
	}

	// hostpath type for kubeconf file and /var/libe/apiserver-ha
	hostPathType := v1.HostPathDirectoryOrCreate
	volMap := make(map[string]v1.Volume)
	volMountMap := make(map[string]v1.VolumeMount)

	// create the kubeconfig file volumn and volumnMount
	kubeVol := staticpodutil.NewVolume("kubeconf", constants.KubernetesDir, &hostPathType)
	kubeVolMount := staticpodutil.NewVolumeMount("kubeconf", ApiserverHaKubeconfContainerPath, false)
	volMap["kubeconf"] = kubeVol
	volMountMap["kubeconf"] = kubeVolMount

	varVol := staticpodutil.NewVolume("config-file", ApiserverHaConfigFileHostPath, &hostPathType)
	varVolMount := staticpodutil.NewVolumeMount("config-file", ApiserverHAProxyConfigContainerPath, false)
	volMap["config-file"] = varVol
	volMountMap["config-file"] = varVolMount

	hostSocketPathType := v1.HostPathSocket
	dockerSockVol := staticpodutil.NewVolume("docker-sock-file", "/var/run/docker.sock", &hostSocketPathType)
	dockerSockVolMount := staticpodutil.NewVolumeMount("docker-sock-file", "/var/run/docker.sock", true)
	volMap["docker-sock-file"] = dockerSockVol
	volMountMap["docker-sock-file"] = dockerSockVolMount

	// mounts := getHostPathVolumesForTheControlPlane(cfg)
	private := true
	return staticpodutil.ComponentPod(v1.Container{
		Name:            options.ApiserverHA,
		Image:           image,
		ImagePullPolicy: v1.PullIfNotPresent,
		Args:            args,
		VolumeMounts:    staticpodutil.VolumeMountMapToSlice(volMountMap),
		Resources:       staticpodutil.ComponentResources("250m"),
		SecurityContext: &v1.SecurityContext{
			Privileged: &private,
		},
	}, volMap)
}

////////////// kubeconfig implements methos ////////////
func WriteKubeConfToDisk(spec *clientcmdapi.Config) error {
	kubeConfigFilePath := filepath.Join(constants.KubernetesDir, constants.ApiserverHaKubeConfigFileName)
	log.Infof("apiserver-ha kubeconfig file Path: %s", kubeConfigFilePath)
	// kubeConfigFilePath := filepath.Join(kubeadmconstants.KubernetesDir, kubeadmconstants.APIServerHAConfigFileName)
	err := kubeconfigutil.WriteToDisk(kubeConfigFilePath, spec)
	if err != nil {
		return errors.Wrapf(err, "failed to save kubeconfig file %q on disk", kubeConfigFilePath)
	}

	return nil
}

////////////// common function ////////////
func ModifyTlsBootstrapCfgClusterIP(clusterName, controlPlaneEndpoin string,
	tlsBootstrapCfg *clientcmdapi.Config) error {
	// if open the cluaster api server, then user the first cluaster ip instep the apiserver
	cluster := tlsBootstrapCfg.Clusters[clusterName]
	if cluster == nil {
		return errors.Errorf("please check the cluseterName, the cluster object is nil")
	}

	cluster.Server = ApiserverHaServiceUrl(controlPlaneEndpoin)
	return nil
}

func ApiserverHaServiceUrl(controlPlaneEndpointIPAndPort string) string {
	return fmt.Sprintf("https://%s", controlPlaneEndpointIPAndPort)
}

func GetApiserverHaControlPlan() (string, error) {
	return "127.0.0.1:8443", nil
}

////////////// build kubeConf file functions ////////////
func BuildKubeConfigSpec(clusterName, ControlPlaneEndpoint string, loader CertsLoader) (*clientcmdapi.Config, error) {
	certs, key, err := loader.Load()
	if err != nil {
		log.Errorf("load the ca and cakey from apiserver fails, msg: %+v", err)
		return nil, err
	}

	// controlPlaneEndpointIP := cfg.ControlPlaneEndpoint//pash.GetApiserverHaIP(cfg.ClusterConfiguration.Networking.ServiceSubnet, cfg.FeatureGates)
	if err != nil {
		return nil, errors.Wrap(err, "get the contolrpalnneEndpoint fails")
	}

	// use the org ca sign the new certs
	clientCertConfig := certutil.Config{
		CommonName:   options.ApiserverHA,
		Organization: []string{clusterName},
		Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCert, clientKey, err := pkiutil.NewCertAndKey(certs, key, &clientCertConfig)
	if err != nil {
		return nil, errors.Wrapf(err, "failure while creating %s client certificate", options.ApiserverHA)
	}

	encodedClientKey, err := keyutil.MarshalPrivateKeyToPEM(clientKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal private key to PEM")
	}

	controlPlaneEndpoint := ApiserverHaServiceUrl(ControlPlaneEndpoint)

	// create a kubeconfig with the client certs
	return kubeconfigutil.CreateWithCerts(
		// cfg.ControlPlaneEndpoint,
		controlPlaneEndpoint,
		clusterName,
		options.ApiserverHA,
		pkiutil.EncodeCertPEM(certs),
		encodedClientKey,
		pkiutil.EncodeCertPEM(clientCert),
	), nil
}

// 转换私有key
func trancePrivateKey(privKey interface{}) (crypto.Signer, error) {
	// Allow RSA and ECDSA formats only
	var key crypto.Signer
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		key = k
	case *ecdsa.PrivateKey:
		key = k
	default:
		return nil, errors.Errorf("the private key file is neither in RSA nor ECDSA format")
	}

	return key, nil
}

func RunProxyContainer(apiserver, img string) error {
	// docker run -it --name apiserverha --network host -v /tmp/haproxy:/var/lib/apiserverha/
	//apiserver-ha:0.1.0-alpha.1 --apiServer 192.168.3.251:6443 --mod docker
	if _, err := os.Stat(ApiserverHaConfigFileHostPath); os.IsNotExist(err) {
		// if the folder is not exist, then create the folder
		os.MkdirAll(ApiserverHaConfigFileHostPath, 0755)
	}

	out, err := utilsexec.New().Command("docker", "run", "-d", "--name", "apiserverha", "--rm",
		"--network", "host", "-v", fmt.Sprintf("%s:%s", ApiserverHaConfigFileHostPath,
			ApiserverHAProxyConfigContainerPath), img, "--apiServer", apiserver).CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "output: %s, error", string(out))
	}
	return nil
}
