package types

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"time"
)

//BanOrder is what is generated from a SignalOccurence : it describes what action to take
//it is in-memory only and never touches the DB. It will be turned into one or several "parser.BanApplication"
type BanOrder struct {
	MeasureSource string    /*api,local*/
	MeasureType   string    /*ban,slow,captcha*/
	Scope         string    /*ip,multi_ip,as,country*/
	TargetAS      int       /*if non-empty, applies to this AS*/
	TargetASName  string    /*if non-empty, applies to this AS*/
	TargetRange   net.IPNet /*if non-empty, applies to this IP*/
	TargetIP      net.IP    /*if non-empty, applies to this range*/
	TargetCountry string
	Until         time.Time /*when would the measure expire*/
	TxtTarget     string
	Reason        string
}

//OrderToApplications turns one ban order into a list of actual bans (BanApplication).
//it is for example in charge of converting ip ranges to integer ranges for db backend
func OrderToApplications(ordr *BanOrder) ([]BanApplication, error) {
	var bas []BanApplication
	var ba BanApplication
	/*
		 pseudo-code for as/country scope would be :
		  - fetch ranges of AS/Country
		  - for ipnet := range Country.Ranges {
			  ba.append(...)
		  	  }
	*/

	ba.MeasureType = ordr.MeasureType
	ba.MeasureSource = ordr.MeasureSource
	ba.Until = ordr.Until
	ba.Reason = ordr.Reason
	ba.TargetAS = ordr.TargetAS
	ba.TargetASName = ordr.TargetASName

	ba.TargetCN = ordr.TargetCountry
	if ordr.Scope == "ip" {
		ba.StartIp = IP2Int(ordr.TargetIP)
		ba.EndIp = IP2Int(ordr.TargetIP)
		ba.IpText = ordr.TargetIP.String()
		bas = append(bas, ba)
	} else if ordr.Scope == "range" {
		ba.StartIp = IP2Int(ordr.TargetRange.IP)
		ba.EndIp = IP2Int(LastAddress(&ordr.TargetRange))
		ba.IpText = ordr.TargetRange.String()
		bas = append(bas, ba)
	} else {
		log.Fatalf("only 'ip' and 'range' scopes are supported.")
	}
	return bas, nil
}

//OvflwToOrder: Transform an overflow (SignalOccurence) and a Profile into a BanOrder
func OvflwToOrder(sig SignalOccurence, prof Profile) (*BanOrder, error, error) {
	var ordr BanOrder
	var warn error

	//Identify remediation type
	if prof.Remediation.Ban {
		ordr.MeasureType = "ban"
	} else if prof.Remediation.Slow {
		ordr.MeasureType = "slow"
	} else if prof.Remediation.Captcha {
		ordr.MeasureType = "captcha"
	} else {
		/*if the profil has no remediation, no order */
		return nil, nil, fmt.Errorf("no remediation")
	}
	ordr.MeasureSource = "local"
	ordr.Reason = sig.Scenario
	//Identify scope
	v, ok := sig.Labels["scope"]
	if !ok {
		//if remediation_scope isn't specified, it's IP
		v = "ip"
	}
	ordr.Scope = v
	asn, err := strconv.Atoi(sig.Source.AutonomousSystemNumber)
	if err != nil {
		warn = fmt.Errorf("invalid as number : %s : %s", sig.Source.AutonomousSystemNumber, err)
	}
	ordr.TargetAS = asn
	ordr.TargetASName = sig.Source.AutonomousSystemOrganization
	ordr.TargetIP = sig.Source.Ip
	ordr.TargetRange = sig.Source.Range
	ordr.TargetCountry = sig.Source.Country
	switch v {
	case "range":
		ordr.TxtTarget = ordr.TargetRange.String()
	case "ip":
		ordr.TxtTarget = ordr.TargetIP.String()
	case "as":
		ordr.TxtTarget = fmt.Sprintf("ban as %d (unsupported)", ordr.TargetAS)
	case "country":
		ordr.TxtTarget = fmt.Sprintf("ban country %s (unsupported)", ordr.TargetCountry)
	default:
		log.Errorf("Unknown remediation scope '%s'", sig.Labels["remediation_Scope"])
		return nil, fmt.Errorf("unknown remediation scope"), nil
	}
	//Set deadline
	ordr.Until = sig.Stop_at.Add(prof.Remediation.TimeDuration)
	return &ordr, nil, warn
}
