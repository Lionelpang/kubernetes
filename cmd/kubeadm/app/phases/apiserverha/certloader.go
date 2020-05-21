package apiserverha

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/pkg/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/kubernetes/cmd/kubeadm/app/constants"
	"k8s.io/kubernetes/cmd/kubeadm/app/phases/copycerts"
	"k8s.io/kubernetes/cmd/kubeadm/app/util/pkiutil"

	clientset "k8s.io/client-go/kubernetes"
)

type CertsLoader interface {
	Load() (*x509.Certificate, crypto.Signer, error)
}

type RemoteLoader struct {
	ClientSet      clientset.Interface
	CertificateKey string
}

type LocalLoader struct {
	CertificatesDir      string
	CACertAndKeyBaseName string
}

func (loader *RemoteLoader) Load() (*x509.Certificate, crypto.Signer, error) {
	secretData, err := copycerts.GetCerts(loader.ClientSet, loader.CertificateKey)
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

func (loader *LocalLoader) Load() (*x509.Certificate, crypto.Signer, error) {
	return pkiutil.TryLoadCertAndKeyFromDisk(loader.CertificatesDir, loader.CACertAndKeyBaseName)
}
