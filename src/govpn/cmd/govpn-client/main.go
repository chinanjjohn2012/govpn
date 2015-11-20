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

// Simple secure, DPI/censorship-resistant free software VPN daemon client.
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
	remoteAddr  = flag.String("remote", "", "Remote server address")
	proto       = flag.String("proto", "udp", "Protocol to use: udp or tcp")
	ifaceName   = flag.String("iface", "tap0", "TAP network interface")
	verifierRaw = flag.String("verifier", "", "Verifier")
	keyPath     = flag.String("key", "", "Path to passphrase file")
	upPath      = flag.String("up", "", "Path to up-script")
	downPath    = flag.String("down", "", "Path to down-script")
	stats       = flag.String("stats", "", "Enable stats retrieving on host:port")
	proxyAddr   = flag.String("proxy", "", "Use HTTP proxy on host:port")
	proxyAuth   = flag.String("proxy-auth", "", "user:password Basic proxy auth")
	mtu         = flag.Int("mtu", 1452, "MTU for outgoing packets")
	timeoutP    = flag.Int("timeout", 60, "Timeout seconds")
	noisy       = flag.Bool("noise", false, "Enable noise appending")
	cpr         = flag.Int("cpr", 0, "Enable constant KiB/sec out traffic rate")
	egdPath     = flag.String("egd", "", "Optional path to EGD socket")

	conf        *govpn.PeerConf
	tap         *govpn.TAP
	timeout     int
	firstUpCall bool = true
	knownPeers  govpn.KnownPeers
	idsCache    govpn.CipherCache
)

func main() {
	flag.Parse()
	timeout = *timeoutP
	var err error
	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Lshortfile)

	govpn.MTU = *mtu

	if *egdPath != "" {
		log.Println("Using", *egdPath, "EGD")
		govpn.EGDInit(*egdPath)
	}

	verifier, err := govpn.VerifierFromString(*verifierRaw)
	if err != nil {
		log.Fatalln(err)
	}
	priv := verifier.PasswordApply(govpn.StringFromFile(*keyPath))
	conf = &govpn.PeerConf{
		Id:       verifier.Id,
		Timeout:  time.Second * time.Duration(timeout),
		Noise:    *noisy,
		CPR:      *cpr,
		Verifier: verifier,
		DSAPriv:  priv,
	}
	idsCache = govpn.NewCipherCache([]govpn.PeerId{*verifier.Id})
	log.Println(govpn.VersionGet())

	tap, err = govpn.TAPListen(*ifaceName)
	if err != nil {
		log.Fatalln("Can not listen on TAP interface:", err)
	}

	log.Println("Max MTU on TAP interface:", govpn.TAPMaxMTU())
	if *stats != "" {
		log.Println("Stats are going to listen on", *stats)
		statsPort, err := net.Listen("tcp", *stats)
		if err != nil {
			log.Fatalln("Can not listen on stats port:", err)
		}
		go govpn.StatsProcessor(statsPort, &knownPeers)
	}

	termSignal := make(chan os.Signal, 1)
	signal.Notify(termSignal, os.Interrupt, os.Kill)

MainCycle:
	for {
		timeouted := make(chan struct{})
		rehandshaking := make(chan struct{})
		termination := make(chan struct{})
		if *proxyAddr != "" {
			*proto = "tcp"
		}
		switch *proto {
		case "udp":
			go startUDP(timeouted, rehandshaking, termination)
		case "tcp":
			if *proxyAddr != "" {
				go proxyTCP(timeouted, rehandshaking, termination)
			} else {
				go startTCP(timeouted, rehandshaking, termination)
			}
		default:
			log.Fatalln("Unknown protocol specified")
		}
		select {
		case <-termSignal:
			log.Fatalln("Finishing")
			termination <- struct{}{}
			break MainCycle
		case <-timeouted:
			break MainCycle
		case <-rehandshaking:
		}
		close(timeouted)
		close(rehandshaking)
		close(termination)
	}
	govpn.ScriptCall(*downPath, *ifaceName)
}
