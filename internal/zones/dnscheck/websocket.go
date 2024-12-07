package dnscheck

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/brianshea2/addr.tools/internal/dnsutil"
	"github.com/gorilla/websocket"
	"github.com/miekg/dns"
)

const (
	// if buffer is full, additional dns requests will not be sent to the watcher
	WebsocketWatcherBufferLength = 500
	WebsocketWatcherMaxLife      = 2 * time.Minute
	WebsocketCloseWait           = time.Second
	WebsocketWriteWait           = time.Second
)

type WebsocketWatcherMessage struct {
	req    *dns.Msg
	raddr  net.Addr
	cstate *tls.ConnectionState
	time   uint32
}

func (msg *WebsocketWatcherMessage) MarshalJSON() ([]byte, error) {
	var r struct {
		Time                  uint32 `json:"time"`
		Proto                 string `json:"proto"`
		RemoteIp              string `json:"remoteIp"`
		RemotePort            string `json:"remotePort"`
		MsgText               string `json:"msgText"`
		IsEdns0               bool   `json:"isEdns0,omitempty"`
		UDPSize               uint16 `json:"udpSize,omitempty"`
		ClientSubnet          string `json:"clientSubnet,omitempty"`
		TLSVersion            string `json:"tlsVersion,omitempty"`
		TLSCipherSuite        string `json:"tlsCipherSuite,omitempty"`
		TLSServerName         string `json:"tlsServerName,omitempty"`
		TLSNegotiatedProtocol string `json:"tlsNegotiatedProtocol,omitempty"`
		TLSDidResume          bool   `json:"tlsDidResume,omitempty"`
	}
	r.Time = msg.time
	r.Proto = dnsutil.GetAddrProtocol(msg.raddr, msg.cstate)
	r.RemoteIp, r.RemotePort, _ = net.SplitHostPort(msg.raddr.String())
	r.MsgText = msg.req.String()
	if opt := msg.req.IsEdns0(); opt != nil {
		r.IsEdns0 = true
		r.UDPSize = opt.UDPSize()
		for _, o := range opt.Option {
			if o.Option() == dns.EDNS0SUBNET {
				subnet := o.(*dns.EDNS0_SUBNET)
				r.ClientSubnet = fmt.Sprintf("%s/%d", subnet.Address, subnet.SourceNetmask)
				break
			}
		}
	}
	if msg.cstate != nil {
		r.TLSVersion = tls.VersionName(msg.cstate.Version)
		r.TLSCipherSuite = tls.CipherSuiteName(msg.cstate.CipherSuite)
		r.TLSServerName = msg.cstate.ServerName
		r.TLSNegotiatedProtocol = msg.cstate.NegotiatedProtocol
		r.TLSDidResume = msg.cstate.DidResume
	}
	return json.Marshal(r)
}

type WebsocketWatcher struct {
	ch chan *WebsocketWatcherMessage
}

func NewWebsocketWatcher() *WebsocketWatcher {
	return &WebsocketWatcher{
		ch: make(chan *WebsocketWatcherMessage, WebsocketWatcherBufferLength),
	}
}

func (ws *WebsocketWatcher) Send(req *dns.Msg, remoteAddr net.Addr, connState *tls.ConnectionState) {
	select {
	case ws.ch <- &WebsocketWatcherMessage{req, remoteAddr, connState, uint32(time.Now().Unix())}:
	default:
		// buffer is full or watcher is done (nil ch)
	}
}

func (ws *WebsocketWatcher) WriteLoop(ctx context.Context, conn *websocket.Conn) {
	defer func() {
		ws.ch = nil
	}()
	done := ctx.Done()
	for {
		select {
		case <-done:
			return
		default:
		}
		select {
		case <-done:
			return
		case msg := <-ws.ch:
			conn.WriteJSON(msg)
		}
	}
}

type WebsocketHandler struct {
	*websocket.Upgrader
	WatcherHub
}

func (h *WebsocketHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	watcherId := req.PathValue("watcher")
	// validate request
	if len(watcherId) == 0 || !websocket.IsWebSocketUpgrade(req) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// accept websocket request, defer close
	conn, err := h.Upgrade(w, req, nil)
	if err != nil {
		// Upgrade replies to the client with an HTTP error
		return
	}
	defer conn.Close()
	// check if watcher already exists
	if h.IsRegistered(watcherId) {
		conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(4000, "watcher already exists"),
			time.Now().Add(WebsocketWriteWait),
		)
		return
	}
	// add watcher, defer delete
	watcher := NewWebsocketWatcher()
	err = h.Register(watcherId, watcher)
	if err != nil {
		// probably too many current watchers
		log.Printf("[error] WatcherHub.SetWatcher: %v", err)
		conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, ""),
			time.Now().Add(WebsocketWriteWait),
		)
		return
	}
	defer h.Unregister(watcherId)
	// set websocket options
	conn.EnableWriteCompression(true)
	conn.SetCompressionLevel(6)
	conn.SetReadLimit(512)
	// setup context
	ctx, cancel := context.WithDeadline(req.Context(), time.Now().Add(WebsocketWatcherMaxLife))
	defer cancel()
	// gracefully close websocket at end of context unless canceling early
	stopClose := context.AfterFunc(ctx, func() {
		conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(WebsocketWriteWait),
		)
		time.Sleep(WebsocketCloseWait) // grace period to receive close message back from client
		conn.Close()
	})
	defer stopClose()
	// write loop
	go watcher.WriteLoop(ctx, conn)
	// read loop
	for {
		_, _, err := conn.NextReader()
		if err != nil {
			return
		}
	}
}
