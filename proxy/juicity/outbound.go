package juicity

import (
	"context"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	juicity "github.com/exclavenetwork/sing-juicity"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/network"

	"github.com/exclavenetwork/exclave-core/v5/app/proxyman/outbound"
	"github.com/exclavenetwork/exclave-core/v5/common"
	"github.com/exclavenetwork/exclave-core/v5/common/buf"
	"github.com/exclavenetwork/exclave-core/v5/common/bytespool"
	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/common/session"
	"github.com/exclavenetwork/exclave-core/v5/common/singbridge"
	"github.com/exclavenetwork/exclave-core/v5/common/uuid"
	"github.com/exclavenetwork/exclave-core/v5/proxy"
	"github.com/exclavenetwork/exclave-core/v5/transport"
	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
	v2tls "github.com/exclavenetwork/exclave-core/v5/transport/internet/tls"
)

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}

var (
	_ proxy.Outbound                    = (*Outbound)(nil)
	_ proxy.ClosableOutbound            = (*Outbound)(nil)
	_ proxy.OutboundWithInterfaceUpdate = (*Outbound)(nil)
)

type Outbound struct {
	baseAddr     net.Address
	ports        []uint16
	hopInterval  time.Duration
	options      juicity.ClientOptions
	client       *juicity.Client
	clientAccess sync.Mutex
	portIndex    int
	lastHop      time.Time
	currentPort  uint16
}

// parsePortList 解析 "443" / "3000-3100" / "3000,3005,3010"
func parsePortList(s string, fallback uint16) []uint16 {
	s = strings.TrimSpace(s)
	if s == "" {
		if fallback == 0 {
			return nil
		}
		return []uint16{fallback}
	}
	var out []uint16
	seen := map[uint16]struct{}{}
	add := func(p uint16) {
		if p == 0 {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			ab := strings.SplitN(part, "-", 2)
			if len(ab) != 2 {
				continue
			}
			a, err1 := strconv.ParseUint(strings.TrimSpace(ab[0]), 10, 16)
			b, err2 := strconv.ParseUint(strings.TrimSpace(ab[1]), 10, 16)
			if err1 != nil || err2 != nil || a == 0 || b == 0 {
				continue
			}
			if a > b {
				a, b = b, a
			}
			// 范围过大时抽样，避免上万端口占内存（可选上限）
			if b-a > 4096 {
				b = a + 4096
			}
			for p := a; p <= b; p++ {
				add(uint16(p))
			}
		} else {
			p, err := strconv.ParseUint(part, 10, 16)
			if err != nil {
				continue
			}
			add(uint16(p))
		}
	}
	if len(out) == 0 {
		if fallback == 0 {
			return nil
		}
		return []uint16{fallback}
	}
	return out
}

func NewClient(ctx context.Context, config *ClientConfig) (*Outbound, error) {
	fallback := uint16(config.Port)
	ports := parsePortList(config.GetHopPorts(), fallback)
	if len(ports) == 0 {
		return nil, newError("no valid port configured")
	}

	idx := 0
	if len(ports) > 1 {
		idx = rand.Intn(len(ports))
	}

	o := &Outbound{
		baseAddr:    config.Address.AsAddress(),
		ports:       ports,
		hopInterval: time.Duration(config.GetHopInterval()) * time.Second,
		portIndex:   idx,
		currentPort: ports[idx],
	}

	uid, err := uuid.ParseHexDashString(config.Uuid)
	if err != nil {
		return nil, newError("invalid uuid")
	}

	dest := o.serverDestination()
	o.options = juicity.ClientOptions{
		Context:       ctx,
		ServerAddress: singbridge.ToSocksAddr(dest),
		UUID:          uid,
		Password:      config.Password,
	}
	return o, nil
}

func (o *Outbound) serverDestination() net.Destination {
	return net.Destination{
		Address: o.baseAddr,
		Port:    net.Port(o.currentPort),
		Network: net.Network_UDP,
	}
}

func (o *Outbound) maybeHopLocked() {
	// 单端口或未设置间隔：不跳跃
	if o.hopInterval <= 0 || len(o.ports) <= 1 {
		return
	}
	if !o.lastHop.IsZero() && time.Since(o.lastHop) < o.hopInterval {
		return
	}
	o.portIndex = (o.portIndex + 1) % len(o.ports)
	o.currentPort = o.ports[o.portIndex]
	o.lastHop = time.Now()
	if o.client != nil {
		_ = o.client.CloseWithError(os.ErrClosed)
		o.client = nil
	}
	dest := o.serverDestination()
	o.options.ServerAddress = singbridge.ToSocksAddr(dest)
	newError("juicity port hop: switched to ", dest.NetAddr()).AtInfo().WriteToLog()
}

func (o *Outbound) getClient(ctx context.Context, dialer internet.Dialer) (*juicity.Client, error) {
	o.clientAccess.Lock()
	defer o.clientAccess.Unlock()

	o.maybeHopLocked()

	if o.client != nil {
		return o.client, nil
	}
	handler, ok := dialer.(*outbound.Handler)
	if !ok {
		panic("dialer is not *outbound.Handler")
	}
	if handler.MuxEnabled() {
		return nil, newError("mux enabled")
	}
	if handler.TransportLayerEnabled() {
		return nil, newError("transport layer enabled")
	}
	streamSettings := handler.StreamSettings()
	if streamSettings == nil || streamSettings.SecurityType != "exclave.core.transport.internet.tls.Config" {
		return nil, newError("tls not enabled")
	}
	tlsSettings, ok := streamSettings.SecuritySettings.(*v2tls.Config)
	if !ok {
		return nil, newError("tls not enabled")
	}
	dest := o.serverDestination()
	options := o.options
	options.ServerAddress = singbridge.ToSocksAddr(dest)
	options.TLSConfig = singbridge.NewTLSConfigWrapper(ctx, tlsSettings, v2tls.WithDestination(dest), v2tls.WithNextProto("h3"))
	options.Dialer = singbridge.NewQUICDialerWrapper(dialer)
	client, err := juicity.NewClient(options)
	if err != nil {
		return nil, err
	}
	o.client = client
	if o.lastHop.IsZero() {
		o.lastHop = time.Now()
	}
	return client, nil
}

func (o *Outbound) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	client, err := o.getClient(ctx, dialer)
	if err != nil {
		return err
	}

	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified")
	}
	destination := outbound.Target

	newError("tunneling request to ", destination, " via ", o.serverDestination().NetAddr()).WriteToLog(session.ExportIDToError(ctx))

	if destination.Network == net.Network_TCP {
		serverConn, err := client.DialConn(ctx, singbridge.ToSocksAddr(destination))
		if err != nil {
			return err
		}

		var firstPayload []byte
		if reader, ok := link.Reader.(buf.TimeoutReader); ok {
			if mb, _ := reader.ReadMultiBufferTimeout(proxy.FirstPayloadTimeout); mb != nil {
				length := mb.Len()
				firstPayload = bytespool.Alloc(length)
				mb, _ = buf.SplitBytes(mb, firstPayload)
				firstPayload = firstPayload[:length]
				buf.ReleaseMulti(mb)
			}
		}
		_, err = serverConn.Write(firstPayload)
		if firstPayload != nil {
			bytespool.Free(firstPayload)
		}
		if err != nil {
			serverConn.Close()
			return singbridge.ReturnError(err)
		}
		return singbridge.ReturnError(bufio.CopyConn(ctx, singbridge.NewPipeConnWrapper(link), serverConn))
	}

	serverConn, err := client.ListenPacket(ctx, singbridge.ToSocksAddr(destination))
	if err != nil {
		return err
	}
	return singbridge.ReturnError(bufio.CopyPacketConn(ctx, singbridge.NewPacketConnWrapper(link, destination), serverConn.(network.PacketConn)))
}

func (o *Outbound) InterfaceUpdate() {
	_ = o.Close()
}

func (o *Outbound) Close() error {
	o.clientAccess.Lock()
	client := o.client
	o.client = nil
	o.clientAccess.Unlock()
	if client != nil {
		client.CloseWithError(os.ErrClosed)
	}
	return nil
}
