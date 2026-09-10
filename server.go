package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

const (
	socks5Version = 0x05
	cmdConnect    = 0x01
	atypIPv4      = 0x01
	atypDomain    = 0x03
	atypIPv6      = 0x04
)

type Server struct {
    listenAddr string
    pool       *ProxyPool
    authUser   string
    authPass   string
}

func NewServer(listenAddr string, pool *ProxyPool, authUser, authPass string) *Server {
    return &Server{
        listenAddr: listenAddr,
        pool:       pool,
        authUser:   authUser,
        authPass:   authPass,
    }
}


func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("listen failed: %w", err)
	}
	log.Printf("[server] SOCKS5 proxy listening on %s", s.listenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[server] accept error: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
    defer conn.Close()

    // 1. SOCKS5 握手阶段
    buf := make([]byte, 512)
    n, err := conn.Read(buf)
    if err != nil || n < 2 || buf[0] != socks5Version {
        return
    }

    // 如果配置了账号密码，强制要求用户名密码认证 (0x02)
    if s.authUser != "" && s.authPass != "" {
        conn.Write([]byte{socks5Version, 0x02})

        // 读取客户端发送的认证信息 (RFC 1929)
        n, err = conn.Read(buf)
        if err != nil || n < 5 || buf[0] != 0x01 {
            return
        }
        uLen := int(buf[1])
        if n < 2+uLen+1 {
            return
        }
        user := string(buf[2 : 2+uLen])
        pLen := int(buf[2+uLen])
        if n < 2+uLen+1+pLen {
            return
        }
        pass := string(buf[3+uLen : 3+uLen+pLen])

        // 校验账密
        if user != s.authUser || pass != s.authPass {
            conn.Write([]byte{0x01, 0x01}) // 认证失败，切断
            return
        }
        conn.Write([]byte{0x01, 0x00}) // 认证成功，放行
    } else {
        // 未配置账密时免密通过
        conn.Write([]byte{socks5Version, 0x00})
    }

    // 2. 读取连接请求
    n, err = conn.Read(buf)
	if err != nil || n < 7 || buf[1] != cmdConnect {
		s.sendReply(conn, 0x07) // command not supported
		return
	}

	// Parse target address
	targetAddr, err := parseTarget(buf[:n])
	if err != nil {
		s.sendReply(conn, 0x04) // host unreachable
		return
	}

	// 3. Use current proxy, switch on failure
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		var upstream Proxy
		var ok bool
		if i == 0 {
			upstream, ok = s.pool.Current()
		} else {
			upstream, ok = s.pool.SwitchNext()
		}
		if !ok {
			log.Printf("[server] no proxies available")
			s.sendReply(conn, 0x01) // general failure
			return
		}

		remote, err := dialViaSOCKS5(upstream, targetAddr, 10*time.Second)
		if err != nil {
			log.Printf("[server] upstream %s failed: %v, switching...", upstream.Addr(), err)
			continue
		}

		// Success
		s.sendReply(conn, 0x00)
		relay(conn, remote)
		return
	}

	s.sendReply(conn, 0x01) // general failure after retries
}

func (s *Server) sendReply(conn net.Conn, status byte) {
	// Minimal SOCKS5 reply: ver, status, rsv, atyp(ipv4), addr(0.0.0.0), port(0)
	conn.Write([]byte{socks5Version, status, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
}

// parseTarget extracts the target address from a SOCKS5 connect request.
func parseTarget(buf []byte) (string, error) {
	if len(buf) < 7 {
		return "", fmt.Errorf("request too short")
	}

	var host string
	var portOffset int

	switch buf[3] {
	case atypIPv4:
		if len(buf) < 10 {
			return "", fmt.Errorf("ipv4 request too short")
		}
		host = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
		portOffset = 8
	case atypDomain:
		domainLen := int(buf[4])
		if len(buf) < 5+domainLen+2 {
			return "", fmt.Errorf("domain request too short")
		}
		host = string(buf[5 : 5+domainLen])
		portOffset = 5 + domainLen
	case atypIPv6:
		if len(buf) < 22 {
			return "", fmt.Errorf("ipv6 request too short")
		}
		ip := net.IP(buf[4:20])
		host = ip.String()
		portOffset = 20
	default:
		return "", fmt.Errorf("unsupported address type: %d", buf[3])
	}

	port := int(buf[portOffset])<<8 | int(buf[portOffset+1])
	return fmt.Sprintf("%s:%d", host, port), nil
}

// dialViaSOCKS5 connects to target through an upstream SOCKS5 proxy.
func dialViaSOCKS5(upstream Proxy, target string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", upstream.Addr(), timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))

	// SOCKS5 greeting
	conn.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return nil, err
	}
	if buf[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("not socks5")
	}

	// Parse target host:port
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	// Build connect request
	req := []byte{0x05, 0x01, 0x00}

	// Check if host is an IP
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, atypIPv4)
			req = append(req, ip4...)
		} else {
			req = append(req, atypIPv6)
			req = append(req, ip...)
		}
	} else {
		// Domain name
		req = append(req, atypDomain, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port&0xff))

	conn.Write(req)

	// Read reply
	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil || n < 2 || resp[1] != 0x00 {
		conn.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("upstream connect failed, status: %d", resp[1])
	}

	// Clear deadline for relay
	conn.SetDeadline(time.Time{})
	return conn, nil
}

// relay copies data bidirectionally between two connections.
func relay(left, right net.Conn) {
	defer left.Close()
	defer right.Close()

	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		// Try half-close if supported
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}

	go cp(left, right)
	go cp(right, left)
	<-done
}
