// hkextun.go - Tunnel setup using an established xsnet.Conn

// Copyright (c) 2017-2019 Russell Magee
// Licensed under the terms of the MIT license (see LICENSE.mit in this
// distribution)
//
// golang implementation by Russ Magee (rmagee_at_gmail.com)

package xsnet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"blitter.com/go/xs/logger"
)

type (
	// Tunnels
	// --
	// 1. client is given (lport, remhost, rport) by local user
	// 2. client sends [CSOTunReq:rport] to server
	// client=> [CSOTunReq:rport] =>remhost
	//
	// remhost starts worker to receive/send data using rport
	// remhost replies to client with rport to acknowledge tun is ready
	// client<= [CSOTunAck:rport] <=remhost
	//   ... or if rhost rport refuses connection, sends
	//   [CSOTunRefused:rport]
	//
	// client starts worker to receive/send data using lport
	// ... client disconnects: sends remhost [CSOTunClose:rport]
	// ... or server disconnects: sends client [CSOTunClose:lport]
	//     server at any time sends [CSOTunRefused:rport] if daemon died
	// --

	// TunEndpoint [securePort:peer:dataPort]
	TunEndpoint struct {
		Rport     uint16    // Names are from client's perspective
		Lport     uint16    // ... ie., RPort is on server, LPort is on client
		Peer      string    //net.Addr
		Died      bool      // set by client upon receipt of a CSOTunDisconn
		KeepAlive uint32    // must be reset by client to keep server dial() alive
		Ctl       chan rune //See TunCtl_* consts
		Data      chan []byte
	}
)

func (hc *Conn) CollapseAllTunnels(client bool) {
	for k, t := range *hc.tuns {
		var tunDst bytes.Buffer
		binary.Write(&tunDst, binary.BigEndian, t.Lport)
		binary.Write(&tunDst, binary.BigEndian, t.Rport)
		if client {
			hc.WritePacket(tunDst.Bytes(), CSOTunHangup)
		} else {
			hc.WritePacket(tunDst.Bytes(), CSOTunDisconn)
		}
		delete(*hc.tuns, k)
	}
}

func (hc *Conn) InitTunEndpoint(lp uint16, p string /* net.Addr */, rp uint16) {
	hc.Lock()
	defer hc.Unlock()
	if (*hc.tuns) == nil {
		(*hc.tuns) = make(map[uint16]*TunEndpoint)
	}
	if (*hc.tuns)[rp] == nil {
		var addrs []net.Addr
		if p == "" {
			addrs, _ = net.InterfaceAddrs()
			p = addrs[0].String()
		}
		(*hc.tuns)[rp] = &TunEndpoint{ /*Status: CSOTunSetup,*/ Peer: p,
			Lport: lp, Rport: rp, Data: make(chan []byte, 1),
			Ctl: make(chan rune, 1)}
		logger.LogDebug(fmt.Sprintf("InitTunEndpoint [%d:%s:%d]", lp, p, rp))
	} else {
		logger.LogDebug(fmt.Sprintf("InitTunEndpoint [reusing] %v", (*hc.tuns)[rp]))
		if (*hc.tuns)[rp].Data == nil {
			// When re-using a tunnel it will have its
			// data channel removed on closure. Re-create it
			(*hc.tuns)[rp].Data = make(chan []byte, 1)
		}
		(*hc.tuns)[rp].KeepAlive = 0
		(*hc.tuns)[rp].Died = false
	}
	return
}

func (hc *Conn) StartClientTunnel(lport, rport uint16) {
	hc.InitTunEndpoint(lport, "", rport)

	go func() {
		var wg sync.WaitGroup

		for cmd := range (*hc.tuns)[rport].Ctl {
			if cmd == 'a' {
				l, e := net.Listen("tcp4", fmt.Sprintf(":%d", lport))
				if e != nil {
					logger.LogDebug(fmt.Sprintf("[ClientTun] Could not get lport %d! (%s)", lport, e))
				} else {
					logger.LogDebug(fmt.Sprintf("[ClientTun] Listening for client tunnel port %d", lport))

					for {
						c, e := l.Accept() // blocks until new conn
						// If tunnel is being re-used, re-init it
						if (*hc.tuns)[rport] == nil {
							hc.InitTunEndpoint(lport, "", rport)
						}
						// ask server to dial() its side, rport
						var tunDst bytes.Buffer
						binary.Write(&tunDst, binary.BigEndian, lport)
						binary.Write(&tunDst, binary.BigEndian, rport)
						hc.WritePacket(tunDst.Bytes(), CSOTunSetup)

						if e != nil {
							logger.LogDebug(fmt.Sprintf("[ClientTun] Accept() got error(%v), hanging up.", e))
						} else {
							logger.LogDebug(fmt.Sprintf("[ClientTun] Accepted tunnel client %v", (*hc.tuns)[rport]))

							// outside client -> tunnel lport
							wg.Add(1)
							go func() {
								defer func() {
									if c.Close() != nil {
										logger.LogDebug("[ClientTun] worker A: conn c already closed")
									} else {
										logger.LogDebug("[ClientTun] worker A: closed conn c")
									}
									wg.Done()
								}()

								logger.LogDebug("[ClientTun] worker A: starting")

								var tunDst bytes.Buffer
								binary.Write(&tunDst, binary.BigEndian, lport)
								binary.Write(&tunDst, binary.BigEndian, rport)
								for {
									rBuf := make([]byte, 1024)
									//Read data from c, encrypt/write via hc to client(lport)
									c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
									n, e := c.Read(rBuf)
									if e != nil {
										if e == io.EOF {
											logger.LogDebug(fmt.Sprintf("[ClientTun] worker A: lport Disconnected: shutting down tunnel %v", (*hc.tuns)[rport]))
											// if Died was already set, server-side already is gone.
											if hc.TunIsAlive(rport) {
												hc.WritePacket(tunDst.Bytes(), CSOTunHangup)
											}
											hc.ShutdownTun(rport) // FIXME: race-C
											break
										} else if strings.Contains(e.Error(), "i/o timeout") {
											if !hc.TunIsAlive(rport) {
												logger.LogDebug(fmt.Sprintf("[ClientTun] worker A: timeout: Server side died, hanging up %v", (*hc.tuns)[rport]))
												hc.ShutdownTun(rport)
												break
											}
										} else {
											logger.LogDebug(fmt.Sprintf("[ClientTun] worker A: Read error from lport of tun %v\n%s", (*hc.tuns)[rport], e))
											if hc.TunIsAlive(rport) {
												hc.WritePacket(tunDst.Bytes(), CSOTunHangup)
											}
											hc.ShutdownTun(rport)
											break
										}
									}
									if n > 0 {
										rBuf = append(tunDst.Bytes(), rBuf[:n]...)
										_, de := hc.WritePacket(rBuf[:n+4], CSOTunData)
										if de != nil {
											logger.LogDebug(fmt.Sprintf("[ClientTun] worker A: Error writing to tunnel %v, %s]\n", (*hc.tuns)[rport], de))
											break
										}
									}
								}
								logger.LogDebug("[ClientTun] worker A: exiting")
							}()

							// tunnel lport -> outside client (c)
							wg.Add(1)
							go func() {
								defer func() {
									if c.Close() != nil {
										logger.LogDebug("[ClientTun] worker B: conn c already closed")
									} else {
										logger.LogDebug("[ClientTun] worker B: closed conn c")
									}
									wg.Done()
								}()

								logger.LogDebug("[ClientTun] worker B: starting")

								for {
									bytes, ok := <-(*hc.tuns)[rport].Data // FIXME: race-C w/ShutdownTun calls
									if ok {
										c.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
										_, e := c.Write(bytes)
										if e != nil {
											logger.LogDebug(fmt.Sprintf("[ClientTun] worker B: lport conn closed"))
											break
										}
									} else {
										logger.LogDebug(fmt.Sprintf("[ClientTun] worker B: Channel was closed?"))
										break
									}
								}
								logger.LogDebug("[ClientTun] worker B: exiting")
							}()

						} // end Accept() worker block
						wg.Wait()

						// When both workers have exited due to a disconnect or other
						// condition, it's safe to remove the tunnel descriptor.
						logger.LogDebug("[ClientTun] workers exited")
						hc.ShutdownTun(rport)
					} // end for-accept
				} // end Listen() block
			}
		} // end t.Ctl for
	}()
}

func (hc *Conn) AgeTunnel(endp uint16) uint32 {
	hc.Lock()
	defer hc.Unlock()
	(*hc.tuns)[endp].KeepAlive += 1
	return (*hc.tuns)[endp].KeepAlive
}

func (hc *Conn) ResetTunnelAge(endp uint16) {
	hc.Lock()
	defer hc.Unlock()
	(*hc.tuns)[endp].KeepAlive = 0
}

func (hc *Conn) TunIsNil(endp uint16) bool {
	hc.Lock()
	defer hc.Unlock()
	return (*hc.tuns)[endp] == nil
}

func (hc *Conn) TunIsAlive(endp uint16) bool {
	hc.Lock()
	defer hc.Unlock()
	return !(*hc.tuns)[endp].Died
}

func (hc *Conn) MarkTunDead(endp uint16) {
	hc.Lock()
	defer hc.Unlock()
	(*hc.tuns)[endp].Died = true
}

func (hc *Conn) ShutdownTun(endp uint16) {
	hc.Lock()
	defer hc.Unlock()
	if (*hc.tuns)[endp] != nil {
		(*hc.tuns)[endp].Died = true
		if (*hc.tuns)[endp].Data != nil {
			close((*hc.tuns)[endp].Data)
			(*hc.tuns)[endp].Data = nil
		}
	}
	delete((*hc.tuns), endp)
}

func (hc *Conn) StartServerTunnel(lport, rport uint16) {
	hc.InitTunEndpoint(lport, "", rport)
	var err error

	go func() {
		var wg sync.WaitGroup

		//
		// worker to age server tunnel and kill it if keepalives
		// stop from client
		//
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				time.Sleep(100 * time.Millisecond)
				if hc.TunIsNil(rport) {
					logger.LogDebug("[ServerTun] worker A: Client endpoint removed.")
					break
				}
				age := hc.AgeTunnel(rport)
				if age > 25 {
					hc.MarkTunDead(rport)
					logger.LogDebug("[ServerTun] worker A: Client died, hanging up.")
					break
				}
			}
		}()

		for cmd := range (*hc.tuns)[rport].Ctl {
			var c net.Conn
			logger.LogDebug(fmt.Sprintf("[ServerTun] got Ctl '%c'.", cmd))
			if cmd == 'd' {
				// if re-using tunnel, re-init it
				if hc.TunIsNil(rport) {
					hc.InitTunEndpoint(lport, "", rport)
				}
				logger.LogDebug("[ServerTun] dialling...")
				c, err = net.Dial("tcp4", fmt.Sprintf(":%d", rport))
				if err != nil {
					logger.LogDebug(fmt.Sprintf("[ServerTun] Dial() error for tun %v: %s", (*hc.tuns)[rport], err))
					var resp bytes.Buffer
					binary.Write(&resp, binary.BigEndian /*lport*/, uint16(0))
					binary.Write(&resp, binary.BigEndian, rport)
					hc.WritePacket(resp.Bytes(), CSOTunRefused)
				} else {
					logger.LogDebug(fmt.Sprintf("[ServerTun] Tunnel Opened - %v", (*hc.tuns)[rport]))
					var resp bytes.Buffer
					binary.Write(&resp, binary.BigEndian, lport)
					binary.Write(&resp, binary.BigEndian, rport)
					logger.LogDebug(fmt.Sprintf("[ServerTun] Writing CSOTunSetupAck %v", (*hc.tuns)[rport]))
					hc.WritePacket(resp.Bytes(), CSOTunSetupAck)

					//
					// worker to read data from the rport (to encrypt & send to client)
					//
					wg.Add(1)
					go func() {
						defer func() {
							logger.LogDebug("[ServerTun] worker A: deferred hangup")
							if c.Close() != nil {
								logger.LogDebug("[ServerTun] workerA: conn c already closed")
							}
							wg.Done()
						}()

						logger.LogDebug("[ServerTun] worker A: starting")

						var tunDst bytes.Buffer
						binary.Write(&tunDst, binary.BigEndian, (*hc.tuns)[rport].Lport)
						binary.Write(&tunDst, binary.BigEndian, (*hc.tuns)[rport].Rport)
						for {
							rBuf := make([]byte, 1024)
							// Read data from c, encrypt/write via hc to client(lport)
							c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
							n, e := c.Read(rBuf)
							if e != nil {
								if e == io.EOF {
									logger.LogDebug(fmt.Sprintf("[ServerTun] worker A: rport Disconnected: shutting down tunnel %v", (*hc.tuns)[rport]))
									if hc.TunIsAlive(rport) {
										hc.WritePacket(tunDst.Bytes(), CSOTunDisconn)
									}
									hc.ShutdownTun(rport) // FIXME: race-A
									break
								} else if strings.Contains(e.Error(), "i/o timeout") {
									if !hc.TunIsAlive(rport) {
										logger.LogDebug(fmt.Sprintf("[ServerTun] worker A: timeout: Server side died, hanging up %v", (*hc.tuns)[rport]))
										hc.ShutdownTun(rport) // FIXME: race-B
										break
									}
								} else {
									logger.LogDebug(fmt.Sprintf("[ServerTun] worker A: Read error from rport of tun %v: %s", (*hc.tuns)[rport], e))
									if hc.TunIsAlive(rport) {
										hc.WritePacket(tunDst.Bytes(), CSOTunDisconn)
									}
									hc.ShutdownTun(rport) // FIXME: race-C
									break
								}
							}
							if n > 0 {
								rBuf = append(tunDst.Bytes(), rBuf[:n]...)
								hc.WritePacket(rBuf[:n+4], CSOTunData)
							}
						}
						logger.LogDebug("[ServerTun] worker A: exiting")
					}()

					// worker to read data from client (already decrypted) & fwd to rport
					wg.Add(1)
					go func() {
						defer func() {
							logger.LogDebug("[ServerTun] worker B: deferred hangup")
							if c.Close() != nil {
								logger.LogDebug("[ServerTun] worker B: conn c already closed")
							}
							wg.Done()
						}()

						logger.LogDebug("[ServerTun] worker B: starting")
						for {
							rData, ok := <-(*hc.tuns)[rport].Data // FIXME: race-A, race-B, race-C (w/ShutdownTun() calls)
							if ok {
								c.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
								_, e := c.Write(rData)
								if e != nil {
									logger.LogDebug(fmt.Sprintf("[ServerTun] worker B: ERROR writing to rport conn"))
									break
								}
							} else {
								logger.LogDebug(fmt.Sprintf("[ServerTun] worker B: Channel was closed?"))
								break
							}
						}
						logger.LogDebug("[ServerTun] worker B: exiting")
					}()
					wg.Wait()
				} // end if Dialled successfully
				delete((*hc.tuns), rport)
			}
		} // t.Ctl read loop
		logger.LogDebug("[ServerTun] Tunnel exiting t.Ctl read loop - channel closed??")
	}()
}
