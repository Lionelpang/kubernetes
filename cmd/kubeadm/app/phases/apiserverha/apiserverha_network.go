package apiserverha

import (
	"fmt"
	"github.com/pkg/errors"
	"k8s.io/klog"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utilexec "k8s.io/utils/exec"
	utilnet "k8s.io/utils/net"
	"net"
	"runtime"
)

const (
	// KubeMarkMasqChain is the mark-for-masquerade chain
	// TODO: clean up this logic in kube-proxy
	KubeMarkMasqChain utiliptables.Chain = "KUBE-MARK-MASQ"

	// KubeMarkDropChain is the mark-for-drop chain
	KubeMarkDropChain utiliptables.Chain = "KUBE-MARK-DROP"

	// KubePostroutingChain is kubernetes postrouting rules
	KubePostroutingChain utiliptables.Chain = "KUBE-POSTROUTING"

	// KubeFirewallChain is kubernetes firewall rules
	KubeFirewallChain utiliptables.Chain = "KUBE-FIREWALL"
)

type ApiserverHaNetwork interface {
	InitNetworkUtil()
}

type apiserverHaNetwork struct {
	iptClient             utiliptables.Interface
	iptablesDropBit       int
	iptablesMasqueradeBit int
}

func NewAipserverHaNetwork(nodeIP string, iptablesDropBit, iptablesMasqueradeBit int) *apiserverHaNetwork {
	sysType := runtime.GOOS

	if sysType != "linux" {
		return nil
	}

	parsedNodeIP := net.ParseIP(nodeIP)
	protocol := utiliptables.ProtocolIpv4
	if utilnet.IsIPv6(parsedNodeIP) {
		klog.Infof("IPv6 node IP (%s), assume IPv6 operation", nodeIP)
		protocol = utiliptables.ProtocolIpv6
	}
	iptClient := utiliptables.New(utilexec.New(), protocol)

	return &apiserverHaNetwork{
		iptClient:             iptClient,
		iptablesDropBit:       iptablesDropBit,
		iptablesMasqueradeBit: iptablesMasqueradeBit,
	}
}

// Write the iptable rule into the iptables
func (ahn *apiserverHaNetwork) InitNetworkUtil() error {
	if ahn.iptablesMasqueradeBit < 0 || ahn.iptablesMasqueradeBit > 31 {
		klog.Errorf("invalid iptables-masquerade-bit %v not in [0, 31]", ahn.iptablesMasqueradeBit)
		return errors.Errorf("invalid iptables-masquerade-bit %v not in [0, 31]", ahn.iptablesMasqueradeBit)
	}

	if ahn.iptablesDropBit < 0 || ahn.iptablesDropBit > 31 {
		klog.Errorf("invalid iptables-drop-bit %v not in [0, 31]", ahn.iptablesDropBit)
		return errors.Errorf("invalid iptables-masquerade-bit %v not in [0, 31]", ahn.iptablesMasqueradeBit)
	}

	if ahn.iptablesDropBit == ahn.iptablesMasqueradeBit {
		klog.Errorf("iptables-masquerade-bit %v and iptables-drop-bit %v must be different", ahn.iptablesMasqueradeBit, ahn.iptablesDropBit)
		return errors.Errorf("iptables-masquerade-bit %v and iptables-drop-bit %v must be different", ahn.iptablesMasqueradeBit, ahn.iptablesDropBit)

	}

	// Setup KUBE-MARK-DROP rules
	dropMark := getIPTablesMark(ahn.iptablesDropBit)
	if _, err := ahn.iptClient.EnsureChain(utiliptables.TableNAT, KubeMarkDropChain); err != nil {
		klog.Errorf("Failed to ensure that %s chain %s exists: %v", utiliptables.TableNAT, KubeMarkDropChain, err)
		return errors.Errorf("Failed to ensure that %s chain %s exists: %v", utiliptables.TableNAT, KubeMarkDropChain, err)
	}
	if _, err := ahn.iptClient.EnsureRule(utiliptables.Append, utiliptables.TableNAT, KubeMarkDropChain, "-j", "MARK", "--set-xmark", dropMark); err != nil {
		klog.Errorf("Failed to ensure marking rule for %v: %v", KubeMarkDropChain, err)
		return errors.Errorf("Failed to ensure marking rule for %v: %v", KubeMarkDropChain, err)
	}
	if _, err := ahn.iptClient.EnsureChain(utiliptables.TableFilter, KubeFirewallChain); err != nil {
		klog.Errorf("Failed to ensure that %s chain %s exists: %v", utiliptables.TableFilter, KubeFirewallChain, err)
		return errors.Errorf("Failed to ensure that %s chain %s exists: %v", utiliptables.TableFilter, KubeFirewallChain, err)
	}
	if _, err := ahn.iptClient.EnsureRule(utiliptables.Append, utiliptables.TableFilter, KubeFirewallChain,
		"-m", "comment", "--comment", "kubernetes firewall for dropping marked packets",
		"-m", "mark", "--mark", dropMark,
		"-j", "DROP"); err != nil {
		klog.Errorf("Failed to ensure rule to drop packet marked by %v in %v chain %v: %v", KubeMarkDropChain, utiliptables.TableFilter, KubeFirewallChain, err)
		return errors.Errorf("Failed to ensure rule to drop packet marked by %v in %v chain %v: %v", KubeMarkDropChain, utiliptables.TableFilter, KubeFirewallChain, err)
	}
	if _, err := ahn.iptClient.EnsureRule(utiliptables.Prepend, utiliptables.TableFilter, utiliptables.ChainOutput, "-j", string(KubeFirewallChain)); err != nil {
		klog.Errorf("Failed to ensure that %s chain %s jumps to %s: %v", utiliptables.TableFilter, utiliptables.ChainOutput, KubeFirewallChain, err)
		return errors.Errorf("Failed to ensure that %s chain %s jumps to %s: %v", utiliptables.TableFilter, utiliptables.ChainOutput, KubeFirewallChain, err)
	}
	if _, err := ahn.iptClient.EnsureRule(utiliptables.Prepend, utiliptables.TableFilter, utiliptables.ChainInput, "-j", string(KubeFirewallChain)); err != nil {
		klog.Errorf("Failed to ensure that %s chain %s jumps to %s: %v", utiliptables.TableFilter, utiliptables.ChainInput, KubeFirewallChain, err)
		return errors.Errorf("Failed to ensure that %s chain %s jumps to %s: %v", utiliptables.TableFilter, utiliptables.ChainInput, KubeFirewallChain, err)
	}

	// Setup KUBE-MARK-MASQ rules
	masqueradeMark := getIPTablesMark(ahn.iptablesMasqueradeBit)
	if _, err := ahn.iptClient.EnsureChain(utiliptables.TableNAT, KubeMarkMasqChain); err != nil {
		klog.Errorf("Failed to ensure that %s chain %s exists: %v", utiliptables.TableNAT, KubeMarkMasqChain, err)
		return errors.Errorf("Failed to ensure that %s chain %s exists: %v", utiliptables.TableNAT, KubeMarkMasqChain, err)
	}
	if _, err := ahn.iptClient.EnsureChain(utiliptables.TableNAT, KubePostroutingChain); err != nil {
		klog.Errorf("Failed to ensure that %s chain %s exists: %v", utiliptables.TableNAT, KubePostroutingChain, err)
		return errors.Errorf("Failed to ensure that %s chain %s exists: %v", utiliptables.TableNAT, KubeMarkMasqChain, err)
	}
	if _, err := ahn.iptClient.EnsureRule(utiliptables.Append, utiliptables.TableNAT, KubeMarkMasqChain, "-j", "MARK", "--set-xmark", masqueradeMark); err != nil {
		klog.Errorf("Failed to ensure marking rule for %v: %v", KubeMarkMasqChain, err)
		return errors.Errorf("Failed to ensure marking rule for %v: %v", KubeMarkMasqChain, err)
	}
	if _, err := ahn.iptClient.EnsureRule(utiliptables.Prepend, utiliptables.TableNAT, utiliptables.ChainPostrouting,
		"-m", "comment", "--comment", "kubernetes postrouting rules", "-j", string(KubePostroutingChain)); err != nil {
		klog.Errorf("Failed to ensure that %s chain %s jumps to %s: %v", utiliptables.TableNAT, utiliptables.ChainPostrouting, KubePostroutingChain, err)
		return errors.Errorf("Failed to ensure that %s chain %s jumps to %s: %v", utiliptables.TableNAT, utiliptables.ChainPostrouting, KubePostroutingChain, err)
	}
	// Establish the masquerading rule.
	// NB: THIS MUST MATCH the corresponding code in the iptables and ipvs
	// modes of kube-proxy
	masqRule := []string{
		"-m", "comment", "--comment", "kubernetes service traffic requiring SNAT",
		"-m", "mark", "--mark", masqueradeMark,
		"-j", "MASQUERADE",
	}
	if ahn.iptClient.HasRandomFully() {
		masqRule = append(masqRule, "--random-fully")
		klog.Info("Using `--random-fully` in the MASQUERADE rule for iptables")
	} else {
		klog.Info("Not using `--random-fully` in the MASQUERADE rule for iptables because the local version of iptables does not support it")
	}
	if _, err := ahn.iptClient.EnsureRule(utiliptables.Append, utiliptables.TableNAT, KubePostroutingChain, masqRule...); err != nil {
		klog.Errorf("Failed to ensure SNAT rule for packets marked by %v in %v chain %v: %v", KubeMarkMasqChain, utiliptables.TableNAT, KubePostroutingChain, err)
		return errors.Errorf("Failed to ensure SNAT rule for packets marked by %v in %v chain %v: %v", KubeMarkMasqChain, utiliptables.TableNAT, KubePostroutingChain, err)
	}

	return nil
}

// getIPTablesMark returns the fwmark given the bit
func getIPTablesMark(bit int) string {
	value := 1 << uint(bit)
	return fmt.Sprintf("%#08x/%#08x", value, value)
}
