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
	log.Printf("[server] SOCKS5 代理已启动并在 %s 监听 (单端口智能分流)", s.listenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[server] accept 异常: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	// 1. SOCKS5 握手认证阶段
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != socks5Version {
		return
	}

	if s.authUser != "" && s.authPass != "" {
		conn.Write([]byte{socks5Version, 0x02})

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

		if user != s.authUser || pass != s.authPass {
			conn.Write([]byte{0x01, 0x01})
			return
		}
		conn.Write([]byte{0x01, 0x00})
	} else {
		conn.Write([]byte{socks5Version, 0x00})
	}

	// 2. 读取目标请求
	n, err = conn.Read(buf)
	if err != nil || n < 7 || buf[1] != cmdConnect {
		s.sendReply(conn, 0x07)
		return
	}

	targetAddr, err := parseTarget(buf[:n])
	if err != nil {
		s.sendReply(conn, 0x04)
		return
	}

	// 3. 提取目标 Host 并进行智能域名规则分流
	host, _, err := net.SplitHostPort(targetAddr)
	if err != nil {
		host = targetAddr
	}

	category := "Default"
	if s.pool != nil && s.pool.ruleManager != nil {
		category = s.pool.ruleManager.Match(host)
	}

	// 4. 从匹配的分类专属池中获取节点并转发（失败时自动重试与剔除）
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		var upstream Proxy
		var ok bool
		if i == 0 {
			upstream, ok = s.pool.GetForCategory(category)
		} else {
			// 重试时顺延切换下一个
			upstream, ok = s.pool.SwitchNextForCategory(category)
		}
		if !ok {
			log.Printf("[server] [%s] 分流池无可用节点", category)
			s.sendReply(conn, 0x01)
			return
		}

		remote, err := dialViaSOCKS5(upstream, targetAddr, 10*time.Second)
		if err != nil {
			log.Printf("[server] [%s] 节点 %s 连通失败 (%v)，剔除并切换下一个...", category, upstream.Addr(), err)
			s.pool.RemoveCurrentForCategory(category)
			continue
		}

		// 转发成功
		s.sendReply(conn, 0x00)
		relay(conn, remote)
		return
	}

	s.sendReply(conn, 0x01)
}

func (s *Server) sendReply(conn net.Conn, status byte) {
	conn.Write([]byte{socks5Version, status, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
}

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

func dialViaSOCKS5(upstream Proxy, target string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", upstream.Addr(), timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))

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

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, atypIPv4)
			req = append(req, ip4...)
		} else {
			req = append(req, atypIPv6)
			req = append(req, ip...)
		}
	} else {
		req = append(req, atypDomain, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port&0xff))

	conn.Write(req)

	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil || n < 2 || resp[1] != 0x00 {
		conn.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("upstream connect failed, status: %d", resp[1])
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

func relay(left, right net.Conn) {
	defer left.Close()
	defer right.Close()

	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}

	go cp(left, right)
	go cp(right, left)
	<-done
}
