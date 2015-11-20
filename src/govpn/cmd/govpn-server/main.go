/*
GoVPN -- simple secure free software virtual private network daemon
Copyright (C) 2014-2015 Sergey Matveev <stargrave@stargrave.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Simple secure, DPI/censorship-resistant free software VPN daemon.
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/stargrave/govpn/src/govpn"
)

var (
	bindAddr = flag.String("bind", "[::]:1194", "Bind to address")
	proto    = flag.String("proto", "udp", "Protocol to use: udp, tcp or all")
	confPath = flag.String("conf", "peers.json", "Path to configuration JSON")
	stats    = flag.String("stats", "", "Enable stats retrieving on host:port")
	proxy    = flag.String("proxy", "", "Enable HTTP proxy on host:port")
	mtu      = flag.Int("mtu", 1452, "MTU for outgoing packets")
	egdPath  = flag.String("egd", "", "Optional path to EGD socket")
)

func main() {
	flag.Parse()
	timeout := time.Second * time.Duration(govpn.TimeoutDefault)
	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Lshortfile)
	log.Println(govpn.VersionGet())

	govpn.MTU = *mtu
	confInit()
	knownPeers = govpn.KnownPeers(make(map[string]**govpn.Peer))

	if *egdPath != "" {
		log.Println("Using", *egdPath, "EGD")
		govpn.EGDInit(*egdPath)
	}

	switch *proto {
	case "udp":
		startUDP()
	case "tcp":
		startTCP()
	case "all":
		startUDP()
		startTCP()
	default:
		log.Fatalln("Unknown protocol specified")
	}

	termSignal := make(chan os.Signal, 1)
	signal.Notify(termSignal, os.Interrupt, os.Kill)

	hsHeartbeat := time.Tick(timeout)
	go func() { <-hsHeartbeat }()

	log.Println("Max MTU on TAP interface:", govpn.TAPMaxMTU())
	if *stats != "" {
		log.Println("Stats are going to listen on", *stats)
		statsPort, err := net.Listen("tcp", *stats)
		if err != nil {
			log.Fatalln("Can not listen on stats port:", err)
		}
		go govpn.StatsProcessor(statsPort, &knownPeers)
	}
	if *proxy != "" {
		go proxyStart()
	}
	log.Println("Server started")

	var needsDeletion bool
MainCycle:
	for {
		select {
		case <-termSignal:
			break MainCycle
		case <-hsHeartbeat:
			now := time.Now()
			hsLock.Lock()
			for addr, hs := range handshakes {
				if hs.LastPing.Add(timeout).Before(now) {
					log.Println("Deleting handshake state", addr)
					hs.Zero()
					delete(handshakes, addr)
				}
			}
			peersLock.Lock()
			peersByIdLock.Lock()
			kpLock.Lock()
			for addr, ps := range peers {
				ps.peer.BusyR.Lock()
				needsDeletion = ps.peer.LastPing.Add(timeout).Before(now)
				ps.peer.BusyR.Unlock()
				if needsDeletion {
					log.Println("Deleting peer", ps.peer)
					delete(peers, addr)
					delete(knownPeers, addr)
					delete(peersById, *ps.peer.Id)
					go govpn.ScriptCall(
						confs[*ps.peer.Id].Down,
						ps.tap.Name,
					)
					ps.terminator <- struct{}{}
				}
			}
			hsLock.Unlock()
			peersLock.Unlock()
			peersByIdLock.Unlock()
			kpLock.Unlock()
		}
	}
}
