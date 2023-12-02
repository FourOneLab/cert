package main

import (
	"fmt"
	"log"
	"time"

	"os"

	"github.com/spf13/cobra"
	certv1 "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cert.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().StringVarP(&commonName, "name", "n", "example", "The common name of the certificate signing request")
	rootCmd.Flags().StringVarP(&signerName, "signer", "s", "example.com/signer-name", "The signer name of the certificate signing request")
	rootCmd.Flags().StringVarP(&secretName, "secret", "S", "my-certificate", "The secret name to save certificates data")
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
	log.Println("Generating CSR configuration")

	// 2. Generate the private key
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		log.Fatalf("failed to generate private key, error: %v", err)
	}
	log.Println("Generating private key")

	// 3. Generate the CSR content by private key
	request, err := CreateCertificateRequestContent(template, privateKey)
	if err != nil {
		log.Fatalf("failed to generate CSR content, error: %v", err)
	}
	log.Println("Generating CSR content")

	pemRequest, err := pemEncoding(request, PEM_TYPE_CERTIFICATE_REQUEST)
	if err != nil {
		log.Fatalf("failed to encode CSR content, error: %v", err)
	}
	log.Println("PEM encoding CSR content")

	// 4. Create the kubernetes CertificateSigningRequest object (consider about the kubernetes version)
	// KUBECONFIG Environment Variable just used for debug.
	kubeconfig, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		log.Fatalf("failed to get kubeconfig, error: %v", err)
	}
	kubeconfig.UserAgent = "k8s-cert-manager"
	log.Println("Build configuration from flags")

	client, err := kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		log.Fatalf("failed to create client, error: %v", err)
	}
	log.Println("New kubernetes client")

	csrName := fmt.Sprintf("csr-%s", ipAddr)
	ctx := cmd.Context()
	oldCSR, err := client.CertificatesV1().CertificateSigningRequests().Get(ctx, csrName, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		log.Fatalf("failed to get CSR, error: %v", err)
	}
	if oldCSR != nil {
		if err := client.CertificatesV1().CertificateSigningRequests().Delete(ctx, csrName, metav1.DeleteOptions{}); err != nil {
			log.Fatalf("failed to delete CSR, error: %v", err)
		}
	}
	log.Println("Checking if the old CSR exists")

	csr := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: csrName,
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
	csr, err = client.CertificatesV1().CertificateSigningRequests().Create(ctx, csr, metav1.CreateOptions{})
	if err != nil {
		log.Fatalf("failed to create CSR, error: %v", err)
	}
	log.Println("Create the new CSR")

	// 5. Approve the CertificateSigningRequest object
	csr.Status.Conditions = append(csr.Status.Conditions, v1.CertificateSigningRequestCondition{
		Type:           v1.CertificateApproved,
		Reason:         "Cert generator approved",
		Message:        "This CSR was approved by cert generator",
		Status:         "True",
		LastUpdateTime: metav1.Now(),
	})
	csr, err = client.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, csr.GetName(), csr, metav1.UpdateOptions{})
	if err != nil {
		log.Fatalf("failed to update CSR, error: %v", err)
	}

	stop := make(chan struct{})
	wait.Until(func() {
		log.Println("wait until certificate generated")
		csr, err = client.CertificatesV1().CertificateSigningRequests().Get(ctx, csrName, metav1.GetOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			log.Printf("failed to get CSR, error: %v", err)
		}
		if len(csr.Status.Certificate) != 0 {
			log.Println("Certificate generated")
			stop <- struct{}{}
		}
	}, 10*time.Second, stop)

	// 6. Get the certificate from the CertificateSigningRequest object .Status.Certificate
	certPEM, err := pemEncoding(csr.Status.DeepCopy().Certificate, PEM_TYPE_CERTIFICATE)
	if err != nil {
		log.Fatalf("failed to encode certificate, error: %v", err)
	}
	log.Println("PEM encoding certificate")

	keyPEM, err := pemKeyEncoding(privateKey)
	if err != nil {
		log.Fatalf("failed to encode private key, error: %v", err)
	}
	log.Println("PEM encoding private key")

	// 7. Get the CA from the kubeconfig object
	log.Println(kubeconfig)
	ca := kubeconfig.DeepCopy().CAData
	// 8. Save the certificate and the private key to a kubernetes secret
	oldSecret, err := client.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		log.Fatalf("failed to get secret, error: %v", err)
	}
	if oldSecret != nil {
		if err := client.CoreV1().Secrets(namespace).Delete(ctx, secretName, metav1.DeleteOptions{}); err != nil {
			log.Fatalf("failed to delete secret, error: %v", err)
		}
	}

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
	if _, err := client.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
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
