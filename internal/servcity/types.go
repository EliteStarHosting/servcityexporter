package servcity

// The types below mirror the ServCity User API's documented response
// schemas (https://servcity.org/uapi/swagger.yml). Boolean config fields
// use pointers so the collector can distinguish "field absent from this
// account/response" from "field present and false" rather than silently
// treating both as false.

// AccountLimits is the response of GET /user/limits.
type AccountLimits struct {
	AllowedRemainingProxies int      `json:"allowedRemainingProxies"`
	AuthorizedTargetSubnets []string `json:"authorizedTargetSubnets"`
}

// AuthorizedIPs is the response of GET /ddos/getAllowedIps.
type AuthorizedIPs struct {
	AuthorizedIPs []string `json:"authorizedIps"`
}

// AllowedProxiesList is the response of GET /minecraft/getAllowedProxies.
type AllowedProxiesList struct {
	AllowedProxies []string `json:"allowedProxies"`
}

// Config is the DDoS protection config for one IP, from
// GET /ddos/config/{IP}. Field names/casing match the upstream JSON
// verbatim (e.g. "very_strict", not "veryStrict").
type Config struct {
	Nulled         *bool `json:"nulled"`
	ConntrackTCP   *bool `json:"conntrack_tcp"`
	ConntrackUDP   *bool `json:"conntrack_udp"`
	Strict         *bool `json:"strict"`
	VeryStrict     *bool `json:"very_strict"`
	DropUDPAmp     *bool `json:"drop_udp_amp"`
	SynfloodFilter *bool `json:"synflood_filter"`
	PcapOnAttack   *bool `json:"pcap_on_attack"`
	Symmetric      *bool `json:"symmetric"`
	Whitelisted    *bool `json:"whitelisted"`
	BlockNewConn   *bool `json:"block_new_conn"`
	DefaultL7      *bool `json:"default_l7"`
	LearningMode   *bool `json:"learning_mode"`
	FirewallEnable *bool `json:"firewall_enable"`
	WhitelistUDP   *bool `json:"whitelist_udp"`
	DynamicFilter  *bool `json:"dynamic_filter"`
}

// BoolFields returns every present boolean field as (config-field-name,
// value), for driving a generic gauge-per-toggle exporter loop instead of
// one hand-written metric per field.
func (c Config) BoolFields() map[string]bool {
	out := map[string]bool{}
	add := func(name string, v *bool) {
		if v != nil {
			out[name] = *v
		}
	}
	add("nulled", c.Nulled)
	add("conntrack_tcp", c.ConntrackTCP)
	add("conntrack_udp", c.ConntrackUDP)
	add("strict", c.Strict)
	add("very_strict", c.VeryStrict)
	add("drop_udp_amp", c.DropUDPAmp)
	add("synflood_filter", c.SynfloodFilter)
	add("pcap_on_attack", c.PcapOnAttack)
	add("symmetric", c.Symmetric)
	add("whitelisted", c.Whitelisted)
	add("block_new_conn", c.BlockNewConn)
	add("default_l7", c.DefaultL7)
	add("learning_mode", c.LearningMode)
	add("firewall_enable", c.FirewallEnable)
	add("whitelist_udp", c.WhitelistUDP)
	add("dynamic_filter", c.DynamicFilter)
	return out
}

// TunnelConf describes one WireGuard-style tunnel. Fully documented by the
// upstream spec, used both as an element of GetTunnelsReply and as the
// base of the tunnel-creation reply.
type TunnelConf struct {
	PublicKey         string   `json:"public_key"`
	UUID              string   `json:"uuid"`
	PresharedKey      string   `json:"preshared_key"`
	AllowedIPs        []string `json:"allowed_ips"`
	LastHandshakeTime string   `json:"last_handshake_time"`
	ReceiveBytes      *int64   `json:"receive_bytes"`
	TransmitBytes     *int64   `json:"transmit_bytes"`
}

// GetTunnelsReply is the response of GET /tunnel.
type GetTunnelsReply struct {
	AccountTunnels []TunnelConf `json:"account_tunnels"`
}

// ProxyConf is a Minecraft proxy's configuration, from
// GET /minecraft/proxy/{uuid}.
type ProxyConf struct {
	DstIP                 string `json:"dstIp"`
	DstPort               int    `json:"dstPort"`
	DontSendProxyProtocol bool   `json:"dontSendProxyProtocol"`
	DialTimeoutMessage    string `json:"dialTimeoutMessage"`
}

// ProxyPortConf is the response of GET /minecraft/proxy/{proxyID}/port.
type ProxyPortConf struct {
	BedrockPort int `json:"bedrockPort"`
	JavaPort    int `json:"javaPort"`
}
