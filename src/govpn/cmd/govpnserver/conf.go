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

package govpnserver

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"time"

	"github.com/stargrave/govpn/src/govpn"
)

var (
	confs    map[govpn.PeerId]*govpn.PeerConf
	idsCache govpn.CipherCache
)

func confRead(confPath *string) map[govpn.PeerId]*govpn.PeerConf {
	data, err := ioutil.ReadFile(*confPath)
	if err != nil {
		log.Fatalln("Unable to read configuration:", err)
	}
	confsRaw := new(map[string]govpn.PeerConf)
	err = json.Unmarshal(data, confsRaw)
	if err != nil {
		log.Fatalln("Unable to parse configuration:", err)
	}

	confs := make(map[govpn.PeerId]*govpn.PeerConf, len(*confsRaw))
	for name, pc := range *confsRaw {
		verifier, err := govpn.VerifierFromString(pc.VerifierRaw)
		if err != nil {
			log.Fatalln("Unable to decode the key:", err.Error(), pc.VerifierRaw)
		}
		conf := govpn.PeerConf{
			Verifier: verifier,
			Id:       verifier.Id,
			Name:     name,
			Up:       pc.Up,
			Down:     pc.Down,
			Noise:    pc.Noise,
			CPR:      pc.CPR,
		}
		if pc.TimeoutInt <= 0 {
			pc.TimeoutInt = govpn.TimeoutDefault
		}
		conf.Timeout = time.Second * time.Duration(pc.TimeoutInt)
		confs[*verifier.Id] = &conf
	}
	return confs
}

func confRefresh(confPath *string) {
	confs = confRead(confPath)
	ids := make([]govpn.PeerId, 0, len(confs))
	for peerId, _ := range confs {
		ids = append(ids, peerId)
	}
	idsCache.Update(ids)
}

func confInit(confPath *string) {
	RefreshRate := time.Minute //zhangjie change 2015.11.20

	idsCache = govpn.NewCipherCache(nil)
	confRefresh(confPath)
	go func() {
		for {
			time.Sleep(RefreshRate)
			confRefresh(confPath)
		}
	}()
}
