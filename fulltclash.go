package main

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/inbound"
	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/component/nat"
	"github.com/Dreamacro/clash/component/resolver"
	"github.com/Dreamacro/clash/constant"
	icontext "github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/listener/mixed"
	"github.com/Dreamacro/clash/listener/socks"
	"golang.org/x/crypto/chacha20poly1305"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	controlPort string
	proxyPort   string
)

func init() {
	flag.StringVar(&controlPort, "c", "", "set control port\t设置控制端口")
	flag.StringVar(&proxyPort, "p", "", "set proxy port\t设置代理端口并开始监听，多个端口之间以|进行分隔")
	flag.Parse()

}
func main() {
	if controlPort == "" {
		fmt.Printf("Invalid control-port value")
		return
	}
	if proxyPort == "" {
		fmt.Printf("Invalid proxy-port value")
		return
	}
	portSlice := strings.Split(proxyPort, "|")
	portSliceLen := len(portSlice)
	fmt.Println("接收到的端口数量:", portSliceLen)

	if portSliceLen < 1 {
		fmt.Printf("No proxy port available")
		return
	}
	if portSliceLen > 128 {
		fmt.Printf("setProxy index must be range in 0~ 127, current index is %d\n", portSliceLen)
		return
	}
	for _i, _port := range portSlice {
		_addr := "127.0.0.1:" + _port
		go startclashMixed(_addr, _i)
	}

	addr := "127.0.0.1:" + controlPort
	sockControl(addr)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

////go:embed rootCA.crt
//var FullTClashRootCa []byte

//go:embed build.key
var BUILDTOKEN []byte // Change this to your own key and nonce
var rawcfgs = make([]*RawConfig, 128)
var (
	natTable   = nat.New()
	udpTimeout = 60 * time.Second
	// lock for recreate function
	mixedMux sync.Mutex
)

// 这是默认的 nonce,实际上这是不安全的做法，nonce应该是随机一次性的，但是我为了方便把它固定了。
var nonce = []byte("012345678912")

type RawConfig struct {
	Proxy map[string]any `yaml:"proxies"`
}

type RawConfig2 struct {
	Proxy   map[string]any `yaml:"proxies"`
	Index   int            `yaml:"index"`
	Command string         `yaml:"command"`
	PingURL string         `yaml:"pingurl"`
}

func sha25632bytes(data []byte) []byte {
	SHA256 := sha256.New()
	SHA256.Write(data)
	digest := SHA256.Sum(nil)
	hexDigest := hex.EncodeToString(digest)
	output := hexDigest[:32]
	return []byte(output)
}
func sockControl(addr string) {
	// Listen on a socket address
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	fmt.Printf("已开始在 %s 进行socket监听\n", addr)
	for {
		// Accept a connection from a client
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		//fmt.Printf("data incoming from %s \n", conn.RemoteAddr())
		// Handle the connection in a goroutine
		go handleConnection(conn)
	}
}
func decryptData(encryptdata []byte) []byte {
	if len(encryptdata) < 16 {
		return nil
	}
	aead, err := chacha20poly1305.New(sha25632bytes(BUILDTOKEN))
	if err != nil {
		//log.Printf("error: %s", err.Error())
	}

	plaintext, err := aead.Open(nil, nonce, encryptdata, nil)
	if err != nil {
		log.Println(err)
		return nil
	}
	return plaintext
}
func handleConnection(conn net.Conn) {
	defer conn.Close()
	//nonce = []byte("123456789012")
	tempconf := RawConfig2{
		Proxy:   nil,
		Index:   -1,
		Command: "",
		PingURL: "",
	}

	// Read data from the client
	buf, err := io.ReadAll(conn)
	if err != nil {
		fmt.Println("发生错误")
		log.Println(err)
		return
	}
	plaintext := decryptData(buf)
	if plaintext == nil {
		return
	}
	err = yaml.Unmarshal(plaintext, &tempconf)
	if err != nil {
		errstr := err.Error()
		log.Printf("error: %s\n", errstr)
		return
	}
	if tempconf.Command == "" {
		log.Printf("invaild command")
		return
	} else if tempconf.Command == "setproxy" {
		setProxy(&tempconf)
	} else if tempconf.Command == "urltest" {
		if tempconf.PingURL == "" {
			return
		}
		delay := myURLTest(tempconf.PingURL, tempconf.Index)
		_, err2 := conn.Write([]byte(strconv.Itoa(int(delay))))
		if err2 != nil {
			log.Printf("error: %s", err2.Error())
			return
		}
		log.Printf("delay: %d", delay)
	} else {
		log.Println("unknown command!")
		return
	}

}

func myURLTest(pingURL string, index int) uint16 {
	if !checkIndex(index) {
		return 0
	}
	proxy, err := adapter.ParseProxy(rawcfgs[index].Proxy)
	if err != nil {
		fmt.Printf("error: %s \n", err.Error())
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	delay, err := proxy.URLTest(ctx, pingURL, nil, 0)
	if ctx.Err() != nil {
		return 0
	}

	if err != nil || delay == 0 {
		fmt.Printf("error: %s \n", err.Error())
		return delay
	}
	return delay
}

func startclashMixed(rawaddr string, index int) {
	addr := rawaddr
	tcpQueue := make(chan constant.ConnContext, 256)
	udpQueue := make(chan constant.PacketAdapter, 32)
	mixedListener, mixedUDPLister := CreateListenerMixed(addr, tcpQueue, udpQueue, index)
	defer mixedListener.Close()
	defer mixedUDPLister.Close()
	if index == 0 {
		numUDPWorkers := 4
		if num := runtime.GOMAXPROCS(0); num > numUDPWorkers {
			numUDPWorkers = num
		}
		for i := 0; i < numUDPWorkers; i++ {
			go func() {
				for conn1 := range udpQueue {
					if conn, ok := conn1.(*inbound.PacketAdapter); ok {
						handleUDPConn(conn, index)
					} else {
						fmt.Println("Failed to convert conn1 to *inbound.PacketAdapter")
					}
				}
			}()
		}
	}
	for conn2 := range tcpQueue {
		go handleTCPConn(conn2, index)
	}
}
func CreateListenerMixed(rawaddr string, tcpIn chan<- constant.ConnContext, udpIn chan<- constant.PacketAdapter, index int) (*mixed.Listener, *socks.UDPListener) {
	addr := rawaddr
	mixedMux.Lock()
	defer mixedMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			fmt.Printf("Start Mixed(http+socks) server error: %s\n", err.Error())
		}
	}()

	mixedListener, err := mixed.New(addr, tcpIn)
	if err != nil {
		return nil, nil
	}
	var mixedUDPLister *socks.UDPListener
	if index == 0 {
		mixedUDPLister, err = socks.NewUDP(addr, udpIn)
		if err != nil {
			return nil, nil
		}
	}

	fmt.Printf("Mixed(http+socks) proxy listening at: %s\n", mixedListener.Address())
	return mixedListener, mixedUDPLister
}

func handleUDPConn(packet *inbound.PacketAdapter, index int) {
	metadata := packet.Metadata()
	if !metadata.Valid() {
		fmt.Printf("[Metadata] not valid: %#v", metadata)
		return
	}

	// make a fAddr if request ip is fakeip
	var fAddr netip.Addr
	if resolver.IsExistFakeIP(metadata.DstIP) {
		fAddr = metadata.DstIP.Unmap()
	}

	// local resolve UDP dns
	if !metadata.Resolved() {
		ips, err := resolver.LookupIP(context.Background(), metadata.Host)
		if err != nil {
			return
		} else if len(ips) == 0 {
			return
		}
		metadata.DstIP = ips[0]
	}

	key := packet.LocalAddr().String()

	handle := func() bool {
		pc, _ := natTable.Get(key)
		if pc != nil {
			err := handleUDPToRemote(packet, pc, metadata)
			if err != nil {
				return false
			}
			return true
		}
		return false
	}

	if handle() {
		return
	}

	lockKey := key + "-lock"
	cond, loaded := natTable.GetOrCreateLock(lockKey)

	go func() {
		if loaded {
			cond.L.Lock()
			cond.Wait()
			handle()
			cond.L.Unlock()
			return
		}

		defer func() {
			natTable.Delete(lockKey)
			cond.Broadcast()
		}()

		pCtx := icontext.NewPacketConnContext(metadata)
		rawcfg := rawcfgs[index]
		if rawcfg == nil {
			fmt.Println("Null pointer reference. Connection break down!")
			return
		}
		if rawcfg.Proxy == nil {
			fmt.Println("Null pointer reference. Connection break down!")
			return
		}
		proxy, err := adapter.ParseProxy(rawcfg.Proxy)
		//proxy, rule, err := resolveMetadata(pCtx, metadata)
		if err != nil {
			fmt.Printf("[UDP] Parse metadata failed: %s", err.Error())
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), constant.DefaultUDPTimeout)
		defer cancel()
		rawPc, err := proxy.ListenPacketContext(ctx, metadata.Pure())
		if err != nil {
			fmt.Printf(
				"[UDP] dial %s %s --> %s error: %s\n",
				proxy.Name(),
				metadata.SourceAddress(),
				metadata.RemoteAddress(),
				err.Error(),
			)
			return
		}
		pCtx.InjectPacketConn(rawPc)
		//pc := statistic.NewUDPTracker(rawPc, statistic.DefaultManager, metadata, nil, 0, 0, false)

		oAddr := metadata.DstIP.Unmap()
		go handleUDPToLocal(packet.UDPPacket, rawPc, key, oAddr, fAddr)

		natTable.Set(key, rawPc, nil)
		handle()
	}()
}
func handleUDPToLocal(packet constant.UDPPacket, pc net.PacketConn, key string, oAddr, fAddr netip.Addr) {
	buf := pool.Get(pool.UDPBufferSize)
	defer pool.Put(buf)
	defer natTable.Delete(key)
	defer pc.Close()

	for {
		err := pc.SetReadDeadline(time.Now().Add(udpTimeout))
		if err != nil {
			return
		}
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}

		fromUDPAddr := from.(*net.UDPAddr)
		if fAddr.IsValid() {
			fromAddr, _ := netip.AddrFromSlice(fromUDPAddr.IP)
			fromAddr = fromAddr.Unmap()
			if oAddr == fromAddr {
				fromUDPAddr.IP = fAddr.AsSlice()
			}
		}

		_, err = packet.WriteBack(buf[:n], fromUDPAddr)
		if err != nil {
			return
		}
	}
}
func handleUDPToRemote(packet constant.UDPPacket, pc constant.PacketConn, metadata *constant.Metadata) error {
	defer packet.Drop()

	addr := metadata.UDPAddr()
	if addr == nil {
		return errors.New("udp addr invalid")
	}

	if _, err := pc.WriteTo(packet.Data(), addr); err != nil {
		return err
	}
	// reset timeout
	err := pc.SetReadDeadline(time.Now().Add(udpTimeout))
	if err != nil {
		return err
	}

	return nil
}
func handleTCPConn(connCtx constant.ConnContext, index int) {
	metadata := connCtx.Metadata()
	rawcfg := rawcfgs[index]
	if rawcfg == nil {
		fmt.Println("Null pointer reference. Connection break down!")
		return
	}
	if rawcfg.Proxy == nil {
		fmt.Println("Null pointer reference. Connection break down!")
		return
	}
	proxy, err := adapter.ParseProxy(rawcfg.Proxy)
	if err != nil {
		fmt.Printf("error: %s \n", err.Error())
		return
	}
	if proxy == nil {
		fmt.Println("Null pointer reference. Connection break down!")
		return
	}
	//fmt.Printf("request incoming from %s to %s, using %s , index: %d\n", metadata.SourceAddress(), metadata.RemoteAddress(), proxy.Name(), index)
	ctx, cancel := context.WithTimeout(context.Background(), constant.DefaultTCPTimeout)
	defer cancel()
	remoteConn, err := proxy.DialContext(ctx, metadata)
	if err != nil {
		fmt.Printf(
			"[TCP] dial %s %s --> %s error: %s\n",
			proxy.Name(),
			metadata.SourceAddress(),
			metadata.RemoteAddress(),
			err.Error(),
		)
		return
	}
	defer remoteConn.Close()
	N.Relay(connCtx.Conn(), remoteConn)
}

func checkIndex(index int) bool {
	if index >= 128 || index < 0 {
		log.Printf("setProxy index must be range in 0~ 127, current index is %d\n", index)
		return false
	}
	return true
}
func setProxy(tempconf *RawConfig2) {
	if !checkIndex(tempconf.Index) {
		return
	}
	if len(rawcfgs) < 128 {
		log.Println("init rawconfigs")
		for i := 0; i < 128; i++ {
			rawcfgs = append(rawcfgs, &RawConfig{Proxy: map[string]any{}})
		}
	}
	rawcfgs[tempconf.Index] = &RawConfig{Proxy: tempconf.Proxy}
	//log.Printf("set proxy success! index: %d\n", tempconf.Index)
}
