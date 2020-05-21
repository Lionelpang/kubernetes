package apiserverha

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	apiserverhaApp "github.com/Lionelpang/kube-apiserver-ha/app"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/kubernetes/cmd/kubeadm/app/cmd/options"
	cmdutil "k8s.io/kubernetes/cmd/kubeadm/app/cmd/util"
	constants "k8s.io/kubernetes/cmd/kubeadm/app/constants"
	kubeadmconstants "k8s.io/kubernetes/cmd/kubeadm/app/constants"
	"k8s.io/kubernetes/cmd/kubeadm/app/features"
	"k8s.io/kubernetes/cmd/kubeadm/app/phases/copycerts"
	kubeconfigutil "k8s.io/kubernetes/cmd/kubeadm/app/util/kubeconfig"
	"k8s.io/kubernetes/cmd/kubeadm/app/util/pkiutil"
	staticpodutil "k8s.io/kubernetes/cmd/kubeadm/app/util/staticpod"
	"k8s.io/kubernetes/pkg/kubelet/kubeletconfig/util/log"
	utilnet "k8s.io/utils/net"
	"net"
	"path/filepath"
	"strings"
)

var apiserverHAExample = cmdutil.Examples(`
	# Prepares the machine for serving a control plane
	kubeadm join phase control-plane-prepare --apiserver-ha-mod
	kubeadm init phase control-plane-prepare --apiserver-ha-mod
`)

const (
	ApiserverHaKubeconfContainerPath   = "/etc/kubernetes/"
	ApiserverHaConfigFileHostPath      = "/var/lib/apiserver-ha/"
	ApiserverHaConfigFileContainerPath = "/var/lib/" + options.ApiserverHA + "/"
	ApiserverHaConfigFileName          = options.ApiserverHA + ".yaml"
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
	serviceSubnet, apiserverHAImage string, loader CertsLoader) error {
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
		serviceSubnet,
		apiserverHAImage)

	if err != nil {
		log.Errorf("Write the Sepc to the disk fails %v", err)
		return errors.Errorf("Create the apiserverha static pod yaml file error, %v", err)
	}

	return nil
}

func BuildManifestsAndWriteToDisk(apiserver, manifestDir, serviceSubnet, image string) error {
	spec := buildStaticPod(apiserver, serviceSubnet, image)

	// writes the StaticPodSpec to disk
	if err := staticpodutil.WriteStaticPodToDisk(options.ApiserverHA, manifestDir, spec); err != nil {
		return errors.Wrapf(err, "failed to create static pod manifest file for %q", options.ApiserverHA)
	}
	return nil
}

func buildStaticPod(initApiserver, serviceSubnet, image string) v1.Pod {
	args := []string{"kube-apiserver-ha", strings.Join([]string{"--apiServer", initApiserver}, "="),
		strings.Join([]string{"--apiserverHaKubeConfig", filepath.Join(ApiserverHaKubeconfContainerPath,
			constants.ApiserverHaKubeConfigFileName)}, "="),
		strings.Join([]string{"--haConfigFile",
			filepath.Join(ApiserverHaConfigFileContainerPath, ApiserverHaConfigFileName)}, "="),
		strings.Join([]string{"--serviceSubnet", serviceSubnet}, "="),
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
	varVolMount := staticpodutil.NewVolumeMount("config-file", ApiserverHaConfigFileContainerPath, false)
	volMap["config-file"] = varVol
	volMountMap["config-file"] = varVolMount

	// mounts := getHostPathVolumesForTheControlPlane(cfg)
	private := true
	return staticpodutil.ComponentPod(v1.Container{
		Name:            options.ApiserverHA,
		Image:           image,
		ImagePullPolicy: v1.PullIfNotPresent,
		Command:         args,
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

func GetApiserverHaControlPlan(serviceSubnet string, featureGates map[string]bool) (string, error) {
	// Get the service subnet CIDR
	svcSubnetCIDR, err := constants.GetKubernetesServiceCIDR(serviceSubnet,
		features.Enabled(featureGates, features.IPv6DualStack))
	if err != nil {
		return "", errors.Wrapf(err, "unable to get internal Kubernetes Service IP from the given service CIDR (%s)", serviceSubnet)
	}

	// Selects the 10th IP in service subnet CIDR range as dnsIP
	ip, err := utilnet.GetIndexedIP(svcSubnetCIDR, 1)
	if err != nil {
		return "", errors.Wrap(err, "unable to get internal Kubernetes Service IP from the given service CIDR")
	}
	return net.JoinHostPort(ip.String(), "443"), nil
}

////////////// write the ipvs functions ////////////
func WriteIpvs(virtualServer, realServer string) error {
	service := apiserverhaApp.BuildService()
	err := service.CreateVirtualServer(virtualServer)
	if err != nil {
		log.Errorf("apiserverha add the virtual server error with the ipvs: %+v", err)
		return err
	}

	err = service.CreateRealServer(virtualServer, realServer)
	if err != nil {
		log.Errorf("apiserverha add the real server error with the ipvs: %+v", err)
		return err
	}

	return nil
}

////////////// build kubeConf file functions ////////////
func BuildKubeConfigSpec(clusterName, ControlPlaneEndpoint string, loader CertsLoader) (*clientcmdapi.Config, error) {
	certs, key, err := loader.Load() // getCAAndCAKeyFromRemote(client, certificateKey)
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

func getCAAndCAKeyFromRemote(client clientset.Interface, certificateKey string) (*x509.Certificate, crypto.Signer, error) {
	secretData, err := copycerts.GetCerts(client, certificateKey)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil, errors.Errorf("Secret %q was not found in the %q Namespace. This Secret might have expired. Please, run `kubeadm init phase upload-certs --upload-certs` on a control plane to generate a new one",
				constants.KubeadmCertsSecret, metav1.NamespaceSystem)
		}
		return nil, nil, err
	}

	caCertData := secretData[constants.CACertName]
	caKeyData := secretData[constants.CAKeyName]

	// certs, err := certutil.ParseCertsPEM(caCertData)
	certs, err := certutil.ParseCertsPEM(caCertData)
	if err != nil {
		return nil, nil, fmt.Errorf("certs parseCertPEM fails.")
	}

	pemCaKeyData, err := keyutil.ParsePrivateKeyPEM(caKeyData)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Parse the key to PEM fails")
	}

	key, err := trancePrivateKey(pemCaKeyData)
	if err != nil {
		return nil, nil, errors.Wrap(err, "trance the private key fails.")
	}

	return certs[0], key, nil
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
