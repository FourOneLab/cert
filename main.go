package main

import (
	"context"
	"fmt"
	"log"

	"os"

	"github.com/spf13/cobra"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
)

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cert.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().StringVarP(&commonName, "name", "n", "default.name", "The common name of the certificate signing request")
	rootCmd.Flags().StringVarP(&signerName, "signer", "s", "default.signer", "The signer name of the certificate signing request")
	rootCmd.Flags().StringVarP(&secretName, "secret", "S", "default.certs", "The secret name to save certificates data")
}

var (
	commonName string
	signerName string
	secretName string

	namespace string
	ipAddr    string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cert",
	Short: "Auto generate certificates for kubernetes",
	Long:  `Auto generate certificates for kubernetes, and save them in kubernetes secret.`,
	Run:   run,
}

func run(cmd *cobra.Command, args []string) {
	// 1. Generate the CSR configuration
	template := CreateCertificateRequestConfiguration(commonName, ipAddr)
	// 2. Generate the private key
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		log.Fatalf("failed to generate private key, error: %v", err)
	}
	// 3. Generate the CSR content by private key
	request, err := CreateCertificateRequestContent(template, privateKey)
	if err != nil {
		log.Fatalf("failed to generate CSR content, error: %v", err)
	}
	pemRequest, err := pemEncoding(request, PEM_TYPE_CERTIFICATE_REQUEST)
	if err != nil {
		log.Fatalf("failed to encode CSR content, error: %v", err)
	}
	// 4. Create the kubernetes CertificateSigningRequest object (consider about the kubernetes version)
	csr := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("csr-%s", ipAddr),
		},
		Spec: certv1.CertificateSigningRequestSpec{
			Request:    pemRequest,
			SignerName: signerName,
			Groups: []string{
				"system:authenticated",
			},
			Usages: []certv1.KeyUsage{
				certv1.UsageKeyEncipherment,
				certv1.UsageDigitalSignature,
				certv1.UsageServerAuth,
			},
		},
	}
	kubeconfig, err := restclient.InClusterConfig()
	if err != nil {
		log.Fatalf("failed to get kubeconfig, error: %v", err)
	}
	kubeconfig.UserAgent = "k8s-cert-manager"
	client, err := kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		log.Fatalf("failed to create client, error: %v", err)
	}
	ctx := context.Background()
	csr, err = client.CertificatesV1().CertificateSigningRequests().
		Create(ctx, csr, metav1.CreateOptions{})
	if err != nil {
		log.Fatalf("failed to create CSR, error: %v", err)
	}
	// 5. Approve the CertificateSigningRequest object
	csr, err = client.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, csr.GetName(), csr, metav1.UpdateOptions{})
	if err != nil {
		log.Fatalf("failed to update CSR, error: %v", err)
	}
	// 6. Get the certificate from the CertificateSigningRequest object .Status.Certificate
	cert := csr.Status.Certificate
	certPEM, err := pemEncoding(cert, PEM_TYPE_CERTIFICATE)
	if err != nil {
		log.Fatalf("failed to encode certificate, error: %v", err)
	}
	keyPEM, err := pemKeyEncoding(privateKey)
	if err != nil {
		log.Fatalf("failed to encode private key, error: %v", err)
	}
	// 7. Get the CA from the kubeconfig object
	ca := kubeconfig.DeepCopy().CAData
	// 8. Save the certificate and the private key to a kubernetes secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace, // from kubernetes downward API
		},
		Data: map[string][]byte{
			"cert.pem": certPEM,
			"key.pem":  keyPEM,
			"ca.pem":   ca,
		},
	}
	if _, err := client.CoreV1().Secrets("").Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		log.Fatalf("failed to create secret, error: %v", err)
	}
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func main() {
	ipAddr = os.Getenv(POD_IP)
	namespace = os.Getenv(NAMESPACE)

	Execute()
}
