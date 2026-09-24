// PROMETHEUS Web — Predictive Real-time Omniscient Monitoring, Emulation,
// Threat Hunting & Engagement Unified System
// Browser-based military-grade cyber operations platform for Darknode
// Copyright (c) 2026 Darknode-Official. All rights reserved.

var _pmIntervals = null;
export function cleanupPrometheus() {
  if (_pmIntervals) { _pmIntervals.forEach(function(id) { clearInterval(id); }); _pmIntervals = null; }
}

export function renderPrometheus(main) {
  cleanupPrometheus();

  var esc = function(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function(c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

  // ============================================================================
  // INFRASTRUCTURE NODES — 155+ nodes across 8 sectors
  // ============================================================================
  var INFRA_NODES = [
    // ---- POWER_GRID sector (20 nodes) ----
    {id:'PG01',name:'Reactor Alpha Nuclear Plant',sector:'POWER_GRID',type:'nuclear',status:'online',ip:'10.1.1.1',deps:[],criticality:10,population:4200000},
    {id:'PG02',name:'Reactor Bravo Nuclear Plant',sector:'POWER_GRID',type:'nuclear',status:'online',ip:'10.1.1.2',deps:[],criticality:10,population:3800000},
    {id:'PG03',name:'Solar Array West',sector:'POWER_GRID',type:'solar',status:'online',ip:'10.1.2.1',deps:[],criticality:6,population:950000},
    {id:'PG04',name:'Solar Array East',sector:'POWER_GRID',type:'solar',status:'online',ip:'10.1.2.2',deps:[],criticality:6,population:870000},
    {id:'PG05',name:'Wind Farm North',sector:'POWER_GRID',type:'wind',status:'online',ip:'10.1.3.1',deps:[],criticality:5,population:620000},
    {id:'PG06',name:'Wind Farm Coastal',sector:'POWER_GRID',type:'wind',status:'online',ip:'10.1.3.2',deps:[],criticality:5,population:540000},
    {id:'PG07',name:'Substation Metro-1',sector:'POWER_GRID',type:'substation',status:'online',ip:'10.1.4.1',deps:['PG01','PG03'],criticality:9,population:2100000},
    {id:'PG08',name:'Substation Metro-2',sector:'POWER_GRID',type:'substation',status:'online',ip:'10.1.4.2',deps:['PG02','PG04'],criticality:9,population:1900000},
    {id:'PG09',name:'Substation Industrial',sector:'POWER_GRID',type:'substation',status:'online',ip:'10.1.4.3',deps:['PG01','PG05'],criticality:8,population:1500000},
    {id:'PG10',name:'Substation Rural-A',sector:'POWER_GRID',type:'substation',status:'online',ip:'10.1.4.4',deps:['PG06'],criticality:6,population:320000},
    {id:'PG11',name:'Transmission Line Alpha',sector:'POWER_GRID',type:'transmission',status:'online',ip:'10.1.5.1',deps:['PG07','PG08'],criticality:9,population:3500000},
    {id:'PG12',name:'Transmission Line Bravo',sector:'POWER_GRID',type:'transmission',status:'online',ip:'10.1.5.2',deps:['PG09','PG10'],criticality:8,population:1800000},
    {id:'PG13',name:'Transmission Line Charlie',sector:'POWER_GRID',type:'transmission',status:'online',ip:'10.1.5.3',deps:['PG07'],criticality:7,population:1200000},
    {id:'PG14',name:'Grid Control Center Primary',sector:'POWER_GRID',type:'control',status:'online',ip:'10.1.6.1',deps:['PG11','PG12','TC03'],criticality:10,population:8000000},
    {id:'PG15',name:'Grid Control Center Backup',sector:'POWER_GRID',type:'control',status:'standby',ip:'10.1.6.2',deps:['PG13','TC04'],criticality:9,population:8000000},
    {id:'PG16',name:'SCADA Gateway North',sector:'POWER_GRID',type:'scada',status:'online',ip:'10.1.7.1',deps:['PG14','TC03'],criticality:9,population:5000000},
    {id:'PG17',name:'SCADA Gateway South',sector:'POWER_GRID',type:'scada',status:'online',ip:'10.1.7.2',deps:['PG14','TC04'],criticality:9,population:4500000},
    {id:'PG18',name:'Battery Storage Facility',sector:'POWER_GRID',type:'storage',status:'online',ip:'10.1.8.1',deps:['PG07'],criticality:7,population:1800000},
    {id:'PG19',name:'Hydroelectric Dam',sector:'POWER_GRID',type:'hydro',status:'online',ip:'10.1.9.1',deps:[],criticality:8,population:2200000},
    {id:'PG20',name:'Demand Response Controller',sector:'POWER_GRID',type:'control',status:'online',ip:'10.1.10.1',deps:['PG14','PG16','PG17'],criticality:7,population:6000000},
    // ---- WATER sector (18 nodes) ----
    {id:'WT01',name:'Central Water Treatment Plant',sector:'WATER',type:'treatment',status:'online',ip:'10.2.1.1',deps:['PG07','TC03'],criticality:10,population:3500000},
    {id:'WT02',name:'North Water Treatment Plant',sector:'WATER',type:'treatment',status:'online',ip:'10.2.1.2',deps:['PG09','TC04'],criticality:9,population:1800000},
    {id:'WT03',name:'Pumping Station Alpha',sector:'WATER',type:'pump',status:'online',ip:'10.2.2.1',deps:['PG07','WT01'],criticality:8,population:2000000},
    {id:'WT04',name:'Pumping Station Bravo',sector:'WATER',type:'pump',status:'online',ip:'10.2.2.2',deps:['PG08','WT01'],criticality:8,population:1700000},
    {id:'WT05',name:'Pumping Station Charlie',sector:'WATER',type:'pump',status:'online',ip:'10.2.2.3',deps:['PG09','WT02'],criticality:7,population:900000},
    {id:'WT06',name:'Reservoir Primary',sector:'WATER',type:'reservoir',status:'online',ip:'10.2.3.1',deps:['WT03'],criticality:8,population:3000000},
    {id:'WT07',name:'Reservoir Secondary',sector:'WATER',type:'reservoir',status:'online',ip:'10.2.3.2',deps:['WT04'],criticality:7,population:1500000},
    {id:'WT08',name:'Distribution Hub Metro',sector:'WATER',type:'distribution',status:'online',ip:'10.2.4.1',deps:['WT06','PG11'],criticality:9,population:2800000},
    {id:'WT09',name:'Distribution Hub Industrial',sector:'WATER',type:'distribution',status:'online',ip:'10.2.4.2',deps:['WT07','PG12'],criticality:7,population:800000},
    {id:'WT10',name:'Distribution Hub Residential',sector:'WATER',type:'distribution',status:'online',ip:'10.2.4.3',deps:['WT06','PG11'],criticality:8,population:2200000},
    {id:'WT11',name:'SCADA Water Control',sector:'WATER',type:'scada',status:'online',ip:'10.2.5.1',deps:['WT01','TC03','PG16'],criticality:9,population:5000000},
    {id:'WT12',name:'Water Quality Monitor Array',sector:'WATER',type:'sensor',status:'online',ip:'10.2.6.1',deps:['WT11','TC05'],criticality:7,population:3500000},
    {id:'WT13',name:'Wastewater Processing East',sector:'WATER',type:'wastewater',status:'online',ip:'10.2.7.1',deps:['PG08','WT08'],criticality:7,population:1600000},
    {id:'WT14',name:'Wastewater Processing West',sector:'WATER',type:'wastewater',status:'online',ip:'10.2.7.2',deps:['PG07','WT10'],criticality:7,population:1400000},
    {id:'WT15',name:'Desalination Plant',sector:'WATER',type:'desalination',status:'online',ip:'10.2.8.1',deps:['PG19','EN05'],criticality:6,population:800000},
    {id:'WT16',name:'Flood Control System',sector:'WATER',type:'flood',status:'online',ip:'10.2.9.1',deps:['WT11','PG16'],criticality:8,population:4000000},
    {id:'WT17',name:'Chemical Treatment Dosing',sector:'WATER',type:'chemical',status:'online',ip:'10.2.10.1',deps:['WT01','WT11'],criticality:9,population:3500000},
    {id:'WT18',name:'Emergency Water Reserve',sector:'WATER',type:'reserve',status:'standby',ip:'10.2.11.1',deps:['WT06'],criticality:6,population:1000000},
    // ---- TELECOM sector (20 nodes) ----
    {id:'TC01',name:'Cell Tower Cluster Metro-A',sector:'TELECOM',type:'cell',status:'online',ip:'10.3.1.1',deps:['PG07'],criticality:7,population:1500000},
    {id:'TC02',name:'Cell Tower Cluster Metro-B',sector:'TELECOM',type:'cell',status:'online',ip:'10.3.1.2',deps:['PG08'],criticality:7,population:1400000},
    {id:'TC03',name:'Fiber Hub Primary',sector:'TELECOM',type:'fiber',status:'online',ip:'10.3.2.1',deps:['PG11'],criticality:10,population:6000000},
    {id:'TC04',name:'Fiber Hub Secondary',sector:'TELECOM',type:'fiber',status:'online',ip:'10.3.2.2',deps:['PG12'],criticality:9,population:4500000},
    {id:'TC05',name:'Fiber Hub Tertiary',sector:'TELECOM',type:'fiber',status:'online',ip:'10.3.2.3',deps:['PG13'],criticality:8,population:2500000},
    {id:'TC06',name:'Satellite Uplink Alpha',sector:'TELECOM',type:'satellite',status:'online',ip:'10.3.3.1',deps:['PG07'],criticality:8,population:3000000},
    {id:'TC07',name:'Satellite Uplink Bravo',sector:'TELECOM',type:'satellite',status:'online',ip:'10.3.3.2',deps:['PG09'],criticality:7,population:2000000},
    {id:'TC08',name:'ISP Gateway Tier-1',sector:'TELECOM',type:'isp',status:'online',ip:'10.3.4.1',deps:['TC03','TC06'],criticality:9,population:5500000},
    {id:'TC09',name:'ISP Gateway Tier-2',sector:'TELECOM',type:'isp',status:'online',ip:'10.3.4.2',deps:['TC04','TC07'],criticality:8,population:3500000},
    {id:'TC10',name:'Root DNS Resolver',sector:'TELECOM',type:'dns',status:'online',ip:'10.3.5.1',deps:['TC08'],criticality:10,population:8000000},
    {id:'TC11',name:'Authoritative DNS Cluster',sector:'TELECOM',type:'dns',status:'online',ip:'10.3.5.2',deps:['TC08','TC09'],criticality:9,population:7000000},
    {id:'TC12',name:'5G Core Network Alpha',sector:'TELECOM',type:'5g',status:'online',ip:'10.3.6.1',deps:['TC03','TC01'],criticality:8,population:2500000},
    {id:'TC13',name:'5G Core Network Bravo',sector:'TELECOM',type:'5g',status:'online',ip:'10.3.6.2',deps:['TC04','TC02'],criticality:8,population:2200000},
    {id:'TC14',name:'Internet Exchange Point',sector:'TELECOM',type:'ixp',status:'online',ip:'10.3.7.1',deps:['TC08','TC09'],criticality:10,population:8000000},
    {id:'TC15',name:'Undersea Cable Landing',sector:'TELECOM',type:'cable',status:'online',ip:'10.3.8.1',deps:['TC14'],criticality:9,population:6000000},
    {id:'TC16',name:'Mobile Switching Center',sector:'TELECOM',type:'msc',status:'online',ip:'10.3.9.1',deps:['TC01','TC02','TC12'],criticality:8,population:3000000},
    {id:'TC17',name:'Emergency Comms Network',sector:'TELECOM',type:'emergency',status:'online',ip:'10.3.10.1',deps:['TC06','PG15'],criticality:10,population:8000000},
    {id:'TC18',name:'CDN Edge Cluster',sector:'TELECOM',type:'cdn',status:'online',ip:'10.3.11.1',deps:['TC08','TC14'],criticality:5,population:4000000},
    {id:'TC19',name:'VoIP Gateway',sector:'TELECOM',type:'voip',status:'online',ip:'10.3.12.1',deps:['TC03','TC08'],criticality:6,population:2000000},
    {id:'TC20',name:'Wireless Backhaul Hub',sector:'TELECOM',type:'backhaul',status:'online',ip:'10.3.13.1',deps:['TC03','TC01','TC02'],criticality:7,population:2800000},
    // ---- TRANSPORT sector (20 nodes) ----
    {id:'TR01',name:'Air Traffic Control Center',sector:'TRANSPORT',type:'atc',status:'online',ip:'10.4.1.1',deps:['PG07','TC03','TC06'],criticality:10,population:500000},
    {id:'TR02',name:'ATC Backup Facility',sector:'TRANSPORT',type:'atc',status:'standby',ip:'10.4.1.2',deps:['PG15','TC04'],criticality:9,population:500000},
    {id:'TR03',name:'Rail Signaling System North',sector:'TRANSPORT',type:'rail',status:'online',ip:'10.4.2.1',deps:['PG07','TC03'],criticality:9,population:1200000},
    {id:'TR04',name:'Rail Signaling System South',sector:'TRANSPORT',type:'rail',status:'online',ip:'10.4.2.2',deps:['PG08','TC04'],criticality:9,population:1100000},
    {id:'TR05',name:'Rail Control Center',sector:'TRANSPORT',type:'rail_control',status:'online',ip:'10.4.2.3',deps:['TR03','TR04','TC03'],criticality:10,population:2300000},
    {id:'TR06',name:'Port Management System Alpha',sector:'TRANSPORT',type:'port',status:'online',ip:'10.4.3.1',deps:['PG07','TC08'],criticality:8,population:300000},
    {id:'TR07',name:'Port Management System Bravo',sector:'TRANSPORT',type:'port',status:'online',ip:'10.4.3.2',deps:['PG09','TC09'],criticality:7,population:250000},
    {id:'TR08',name:'Highway ITS Control',sector:'TRANSPORT',type:'its',status:'online',ip:'10.4.4.1',deps:['PG07','TC03'],criticality:7,population:3000000},
    {id:'TR09',name:'Highway ITS Sensor Array',sector:'TRANSPORT',type:'its_sensor',status:'online',ip:'10.4.4.2',deps:['TR08','TC05'],criticality:6,population:3000000},
    {id:'TR10',name:'Metro System Control',sector:'TRANSPORT',type:'metro',status:'online',ip:'10.4.5.1',deps:['PG07','PG08','TC03'],criticality:9,population:2500000},
    {id:'TR11',name:'Metro Station Network',sector:'TRANSPORT',type:'metro_station',status:'online',ip:'10.4.5.2',deps:['TR10','PG11'],criticality:8,population:2500000},
    {id:'TR12',name:'Bus Fleet Management',sector:'TRANSPORT',type:'bus',status:'online',ip:'10.4.6.1',deps:['TC01','TC12'],criticality:5,population:800000},
    {id:'TR13',name:'Traffic Light Control Grid',sector:'TRANSPORT',type:'traffic',status:'online',ip:'10.4.7.1',deps:['PG07','TC03','TR08'],criticality:7,population:3500000},
    {id:'TR14',name:'Bridge Monitoring System',sector:'TRANSPORT',type:'bridge',status:'online',ip:'10.4.8.1',deps:['TC05','PG10'],criticality:6,population:400000},
    {id:'TR15',name:'Tunnel Ventilation Control',sector:'TRANSPORT',type:'tunnel',status:'online',ip:'10.4.9.1',deps:['PG07','TR10'],criticality:8,population:1500000},
    {id:'TR16',name:'Airport Baggage System',sector:'TRANSPORT',type:'airport',status:'online',ip:'10.4.10.1',deps:['PG07','TC03'],criticality:5,population:200000},
    {id:'TR17',name:'Maritime Navigation Aid',sector:'TRANSPORT',type:'maritime',status:'online',ip:'10.4.11.1',deps:['TC06','PG10'],criticality:7,population:150000},
    {id:'TR18',name:'Freight Rail Dispatch',sector:'TRANSPORT',type:'freight',status:'online',ip:'10.4.12.1',deps:['TR05','TC04'],criticality:7,population:100000},
    {id:'TR19',name:'EV Charging Network',sector:'TRANSPORT',type:'ev',status:'online',ip:'10.4.13.1',deps:['PG07','PG08','TC12'],criticality:4,population:600000},
    {id:'TR20',name:'Autonomous Vehicle Grid',sector:'TRANSPORT',type:'av',status:'online',ip:'10.4.14.1',deps:['TC12','TC10','TR08','TR13'],criticality:8,population:1000000},
    // ---- FINANCIAL sector (18 nodes) ----
    {id:'FN01',name:'National Stock Exchange',sector:'FINANCIAL',type:'exchange',status:'online',ip:'10.5.1.1',deps:['PG07','TC03','TC14'],criticality:10,population:5000000},
    {id:'FN02',name:'Commodities Exchange',sector:'FINANCIAL',type:'exchange',status:'online',ip:'10.5.1.2',deps:['PG08','TC03','TC14'],criticality:9,population:2000000},
    {id:'FN03',name:'SWIFT Gateway Primary',sector:'FINANCIAL',type:'swift',status:'online',ip:'10.5.2.1',deps:['TC14','TC15','PG07'],criticality:10,population:10000000},
    {id:'FN04',name:'SWIFT Gateway Backup',sector:'FINANCIAL',type:'swift',status:'standby',ip:'10.5.2.2',deps:['TC14','TC04','PG15'],criticality:9,population:10000000},
    {id:'FN05',name:'Central Clearing House',sector:'FINANCIAL',type:'clearing',status:'online',ip:'10.5.3.1',deps:['FN01','FN03','TC03'],criticality:10,population:8000000},
    {id:'FN06',name:'Securities Clearing',sector:'FINANCIAL',type:'clearing',status:'online',ip:'10.5.3.2',deps:['FN01','FN02','TC03'],criticality:9,population:3000000},
    {id:'FN07',name:'Retail Banking Core A',sector:'FINANCIAL',type:'banking',status:'online',ip:'10.5.4.1',deps:['PG07','TC03','FN05'],criticality:9,population:6000000},
    {id:'FN08',name:'Retail Banking Core B',sector:'FINANCIAL',type:'banking',status:'online',ip:'10.5.4.2',deps:['PG08','TC04','FN05'],criticality:9,population:5500000},
    {id:'FN09',name:'ATM Network Controller',sector:'FINANCIAL',type:'atm',status:'online',ip:'10.5.5.1',deps:['FN07','FN08','TC03'],criticality:7,population:4000000},
    {id:'FN10',name:'Payment Processing Hub',sector:'FINANCIAL',type:'payment',status:'online',ip:'10.5.6.1',deps:['FN05','TC14','PG07'],criticality:9,population:8000000},
    {id:'FN11',name:'Crypto Exchange Platform',sector:'FINANCIAL',type:'crypto',status:'online',ip:'10.5.7.1',deps:['TC14','TC08','PG07'],criticality:6,population:1500000},
    {id:'FN12',name:'Insurance Claims System',sector:'FINANCIAL',type:'insurance',status:'online',ip:'10.5.8.1',deps:['FN07','TC03'],criticality:6,population:3000000},
    {id:'FN13',name:'Federal Reserve Link',sector:'FINANCIAL',type:'fedreserve',status:'online',ip:'10.5.9.1',deps:['FN03','FN05','TC14','GV07'],criticality:10,population:12000000},
    {id:'FN14',name:'Credit Card Processor',sector:'FINANCIAL',type:'creditcard',status:'online',ip:'10.5.10.1',deps:['FN10','TC03','TC14'],criticality:8,population:7000000},
    {id:'FN15',name:'Mortgage Servicing Platform',sector:'FINANCIAL',type:'mortgage',status:'online',ip:'10.5.11.1',deps:['FN07','TC03'],criticality:5,population:2000000},
    {id:'FN16',name:'Wire Transfer Gateway',sector:'FINANCIAL',type:'wire',status:'online',ip:'10.5.12.1',deps:['FN03','FN05','TC14'],criticality:9,population:5000000},
    {id:'FN17',name:'Anti-Fraud Detection Engine',sector:'FINANCIAL',type:'fraud',status:'online',ip:'10.5.13.1',deps:['FN07','FN08','FN10','TC03'],criticality:8,population:8000000},
    {id:'FN18',name:'Regulatory Reporting System',sector:'FINANCIAL',type:'regulatory',status:'online',ip:'10.5.14.1',deps:['FN01','FN05','FN13','TC03'],criticality:7,population:1000000},
    // ---- HEALTHCARE sector (18 nodes) ----
    {id:'HC01',name:'Metro Hospital Network A',sector:'HEALTHCARE',type:'hospital',status:'online',ip:'10.6.1.1',deps:['PG07','TC03','WT08'],criticality:10,population:2000000},
    {id:'HC02',name:'Metro Hospital Network B',sector:'HEALTHCARE',type:'hospital',status:'online',ip:'10.6.1.2',deps:['PG08','TC04','WT10'],criticality:10,population:1800000},
    {id:'HC03',name:'Regional Hospital Cluster',sector:'HEALTHCARE',type:'hospital',status:'online',ip:'10.6.1.3',deps:['PG09','TC05','WT09'],criticality:9,population:900000},
    {id:'HC04',name:'EHR System Primary',sector:'HEALTHCARE',type:'ehr',status:'online',ip:'10.6.2.1',deps:['HC01','HC02','TC03'],criticality:9,population:4500000},
    {id:'HC05',name:'EHR System Backup',sector:'HEALTHCARE',type:'ehr',status:'standby',ip:'10.6.2.2',deps:['HC03','TC04'],criticality:8,population:4500000},
    {id:'HC06',name:'Medical Device Network Metro',sector:'HEALTHCARE',type:'meddevice',status:'online',ip:'10.6.3.1',deps:['HC01','PG07','TC03'],criticality:9,population:1500000},
    {id:'HC07',name:'Medical Device Network Regional',sector:'HEALTHCARE',type:'meddevice',status:'online',ip:'10.6.3.2',deps:['HC03','PG09','TC05'],criticality:8,population:600000},
    {id:'HC08',name:'Pharmacy Dispensing System',sector:'HEALTHCARE',type:'pharmacy',status:'online',ip:'10.6.4.1',deps:['HC04','FN10'],criticality:8,population:3000000},
    {id:'HC09',name:'Blood Bank Network',sector:'HEALTHCARE',type:'bloodbank',status:'online',ip:'10.6.5.1',deps:['HC01','HC02','TC03','PG07'],criticality:9,population:2500000},
    {id:'HC10',name:'Lab Information System',sector:'HEALTHCARE',type:'lab',status:'online',ip:'10.6.6.1',deps:['HC04','TC03'],criticality:8,population:3500000},
    {id:'HC11',name:'Radiology PACS Network',sector:'HEALTHCARE',type:'pacs',status:'online',ip:'10.6.7.1',deps:['HC01','HC04','TC03'],criticality:7,population:2000000},
    {id:'HC12',name:'Telemedicine Platform',sector:'HEALTHCARE',type:'telehealth',status:'online',ip:'10.6.8.1',deps:['TC08','TC12','HC04'],criticality:6,population:1200000},
    {id:'HC13',name:'Emergency Dispatch Medical',sector:'HEALTHCARE',type:'dispatch',status:'online',ip:'10.6.9.1',deps:['TC17','HC01','HC02','PG07'],criticality:10,population:5000000},
    {id:'HC14',name:'Vaccine Distribution System',sector:'HEALTHCARE',type:'vaccine',status:'online',ip:'10.6.10.1',deps:['HC04','TR18','TC03'],criticality:7,population:8000000},
    {id:'HC15',name:'Health Insurance Gateway',sector:'HEALTHCARE',type:'insurance',status:'online',ip:'10.6.11.1',deps:['HC04','FN12','TC03'],criticality:6,population:4000000},
    {id:'HC16',name:'Medical Supply Chain Tracker',sector:'HEALTHCARE',type:'supply',status:'online',ip:'10.6.12.1',deps:['HC04','TR18','TC03'],criticality:7,population:3000000},
    {id:'HC17',name:'Ventilator Control Network',sector:'HEALTHCARE',type:'ventilator',status:'online',ip:'10.6.13.1',deps:['HC01','HC06','PG07'],criticality:10,population:500000},
    {id:'HC18',name:'Pandemic Monitoring System',sector:'HEALTHCARE',type:'pandemic',status:'online',ip:'10.6.14.1',deps:['HC04','HC10','TC08'],criticality:8,population:12000000},
    // ---- GOVERNMENT sector (20 nodes) ----
    {id:'GV01',name:'SIPRNet Gateway',sector:'GOVERNMENT',type:'classified',status:'online',ip:'10.7.1.1',deps:['PG07','TC03','TC06'],criticality:10,population:500000},
    {id:'GV02',name:'JWICS Terminal',sector:'GOVERNMENT',type:'classified',status:'online',ip:'10.7.1.2',deps:['PG07','TC06','GV01'],criticality:10,population:200000},
    {id:'GV03',name:'NIPRNet Gateway',sector:'GOVERNMENT',type:'unclassified',status:'online',ip:'10.7.2.1',deps:['TC08','PG07'],criticality:8,population:2000000},
    {id:'GV04',name:'Election Infrastructure Primary',sector:'GOVERNMENT',type:'election',status:'online',ip:'10.7.3.1',deps:['PG07','TC03','GV03'],criticality:10,population:15000000},
    {id:'GV05',name:'Election Infrastructure Backup',sector:'GOVERNMENT',type:'election',status:'standby',ip:'10.7.3.2',deps:['PG15','TC04'],criticality:9,population:15000000},
    {id:'GV06',name:'911 Emergency Services Hub',sector:'GOVERNMENT',type:'emergency',status:'online',ip:'10.7.4.1',deps:['TC17','TC03','PG07'],criticality:10,population:8000000},
    {id:'GV07',name:'Treasury Department Network',sector:'GOVERNMENT',type:'treasury',status:'online',ip:'10.7.5.1',deps:['GV01','FN13','TC03','PG07'],criticality:10,population:20000000},
    {id:'GV08',name:'Intelligence Database Primary',sector:'GOVERNMENT',type:'intel',status:'online',ip:'10.7.6.1',deps:['GV01','GV02','PG07'],criticality:10,population:100000},
    {id:'GV09',name:'Intelligence Database Mirror',sector:'GOVERNMENT',type:'intel',status:'online',ip:'10.7.6.2',deps:['GV01','PG15'],criticality:9,population:100000},
    {id:'GV10',name:'Military Command Center',sector:'GOVERNMENT',type:'milcommand',status:'online',ip:'10.7.7.1',deps:['GV01','GV02','TC06','PG07'],criticality:10,population:1000000},
    {id:'GV11',name:'Diplomatic Comms Network',sector:'GOVERNMENT',type:'diplomatic',status:'online',ip:'10.7.8.1',deps:['GV01','TC06','TC15'],criticality:9,population:50000},
    {id:'GV12',name:'Border Control Systems',sector:'GOVERNMENT',type:'border',status:'online',ip:'10.7.9.1',deps:['GV03','TC08','GV08'],criticality:8,population:5000000},
    {id:'GV13',name:'Tax Revenue Processing',sector:'GOVERNMENT',type:'tax',status:'online',ip:'10.7.10.1',deps:['GV07','FN07','TC03'],criticality:8,population:10000000},
    {id:'GV14',name:'Social Security System',sector:'GOVERNMENT',type:'social',status:'online',ip:'10.7.11.1',deps:['GV03','FN07','TC03'],criticality:8,population:12000000},
    {id:'GV15',name:'Federal Law Enforcement DB',sector:'GOVERNMENT',type:'law',status:'online',ip:'10.7.12.1',deps:['GV01','GV08','TC03'],criticality:9,population:2000000},
    {id:'GV16',name:'Nuclear Command Authority',sector:'GOVERNMENT',type:'nuclear_cmd',status:'online',ip:'10.7.13.1',deps:['GV01','GV02','GV10','TC06'],criticality:10,population:50000000},
    {id:'GV17',name:'Weather Service Systems',sector:'GOVERNMENT',type:'weather',status:'online',ip:'10.7.14.1',deps:['TC06','TC08','PG07'],criticality:7,population:20000000},
    {id:'GV18',name:'GPS Constellation Control',sector:'GOVERNMENT',type:'gps',status:'online',ip:'10.7.15.1',deps:['GV10','TC06','PG07'],criticality:10,population:50000000},
    {id:'GV19',name:'Cybersecurity Operations',sector:'GOVERNMENT',type:'cyberops',status:'online',ip:'10.7.16.1',deps:['GV01','GV08','TC03','TC14'],criticality:9,population:1000000},
    {id:'GV20',name:'National Guard Comms',sector:'GOVERNMENT',type:'natguard',status:'online',ip:'10.7.17.1',deps:['GV10','TC17','TC06'],criticality:8,population:3000000},
    // ---- ENERGY sector (21 nodes) ----
    {id:'EN01',name:'Trans-Continental Oil Pipeline',sector:'ENERGY',type:'pipeline',status:'online',ip:'10.8.1.1',deps:['PG16','TC03'],criticality:9,population:5000000},
    {id:'EN02',name:'Regional Oil Pipeline Network',sector:'ENERGY',type:'pipeline',status:'online',ip:'10.8.1.2',deps:['PG17','TC04'],criticality:8,population:3000000},
    {id:'EN03',name:'Natural Gas Distribution Hub',sector:'ENERGY',type:'gas',status:'online',ip:'10.8.2.1',deps:['PG07','TC03'],criticality:9,population:4000000},
    {id:'EN04',name:'Gas Pipeline Control',sector:'ENERGY',type:'gas_control',status:'online',ip:'10.8.2.2',deps:['EN03','PG16','TC03'],criticality:9,population:4000000},
    {id:'EN05',name:'Coastal Refinery Alpha',sector:'ENERGY',type:'refinery',status:'online',ip:'10.8.3.1',deps:['EN01','PG07','WT01'],criticality:8,population:2000000},
    {id:'EN06',name:'Inland Refinery Bravo',sector:'ENERGY',type:'refinery',status:'online',ip:'10.8.3.2',deps:['EN02','PG09','WT02'],criticality:8,population:1500000},
    {id:'EN07',name:'LNG Terminal East',sector:'ENERGY',type:'lng',status:'online',ip:'10.8.4.1',deps:['EN03','TR06','PG07'],criticality:8,population:1000000},
    {id:'EN08',name:'LNG Terminal West',sector:'ENERGY',type:'lng',status:'online',ip:'10.8.4.2',deps:['EN04','TR07','PG09'],criticality:7,population:800000},
    {id:'EN09',name:'Offshore Platform Cluster A',sector:'ENERGY',type:'offshore',status:'online',ip:'10.8.5.1',deps:['TC06','TC07'],criticality:7,population:200000},
    {id:'EN10',name:'Offshore Platform Cluster B',sector:'ENERGY',type:'offshore',status:'online',ip:'10.8.5.2',deps:['TC06'],criticality:7,population:180000},
    {id:'EN11',name:'Offshore Platform Cluster C',sector:'ENERGY',type:'offshore',status:'online',ip:'10.8.5.3',deps:['TC07'],criticality:6,population:150000},
    {id:'EN12',name:'Smart Meter Grid Metro',sector:'ENERGY',type:'smartmeter',status:'online',ip:'10.8.6.1',deps:['PG07','TC12','PG16'],criticality:5,population:2500000},
    {id:'EN13',name:'Smart Meter Grid Suburban',sector:'ENERGY',type:'smartmeter',status:'online',ip:'10.8.6.2',deps:['PG08','TC13','PG17'],criticality:5,population:1800000},
    {id:'EN14',name:'Strategic Petroleum Reserve',sector:'ENERGY',type:'reserve',status:'online',ip:'10.8.7.1',deps:['EN01','GV07'],criticality:9,population:20000000},
    {id:'EN15',name:'Fuel Distribution Network',sector:'ENERGY',type:'fuel',status:'online',ip:'10.8.8.1',deps:['EN05','EN06','TR18'],criticality:8,population:8000000},
    {id:'EN16',name:'Ethanol Processing Plant',sector:'ENERGY',type:'ethanol',status:'online',ip:'10.8.9.1',deps:['PG09','WT02'],criticality:4,population:300000},
    {id:'EN17',name:'Coal Terminal Operations',sector:'ENERGY',type:'coal',status:'online',ip:'10.8.10.1',deps:['TR06','PG09'],criticality:5,population:500000},
    {id:'EN18',name:'Energy Trading Platform',sector:'ENERGY',type:'trading',status:'online',ip:'10.8.11.1',deps:['FN01','TC14','PG07'],criticality:7,population:1000000},
    {id:'EN19',name:'Pipeline SCADA Master',sector:'ENERGY',type:'scada',status:'online',ip:'10.8.12.1',deps:['EN01','EN02','EN03','PG16','TC03'],criticality:10,population:8000000},
    {id:'EN20',name:'Hydrogen Production Facility',sector:'ENERGY',type:'hydrogen',status:'online',ip:'10.8.13.1',deps:['PG19','WT01'],criticality:5,population:200000},
    {id:'EN21',name:'Carbon Capture System',sector:'ENERGY',type:'carbon',status:'online',ip:'10.8.14.1',deps:['EN05','PG07'],criticality:3,population:100000}
  ];

  // ============================================================================
  // APT GROUPS — 35 nation-state threat actors
  // ============================================================================
  var APT_GROUPS = [
    {id:'APT01',name:'APT28',nation:'Russia',aliases:['Fancy Bear','Sofacy','Sednit','STRONTIUM'],targets:['government','military','media','energy'],ttps:['T1566','T1190','T1059','T1071','T1027'],active:true,threatLevel:9,lastSeen:'2026-09-10'},
    {id:'APT02',name:'APT29',nation:'Russia',aliases:['Cozy Bear','The Dukes','NOBELIUM','Midnight Blizzard'],targets:['government','think_tanks','healthcare','technology'],ttps:['T1195','T1078','T1098','T1550','T1087'],active:true,threatLevel:9,lastSeen:'2026-09-12'},
    {id:'APT03',name:'Sandworm',nation:'Russia',aliases:['Voodoo Bear','IRIDIUM','Seashell Blizzard','TeleBots'],targets:['energy','government','media','financial'],ttps:['T1190','T1059','T1485','T1561','T1529'],active:true,threatLevel:10,lastSeen:'2026-09-11'},
    {id:'APT04',name:'Turla',nation:'Russia',aliases:['Venomous Bear','KRYPTON','Snake','Uroburos'],targets:['government','military','diplomatic','research'],ttps:['T1071','T1573','T1090','T1027','T1140'],active:true,threatLevel:8,lastSeen:'2026-08-28'},
    {id:'APT05',name:'Gamaredon',nation:'Russia',aliases:['Primitive Bear','Shuckworm','Aqua Blizzard'],targets:['government','military','law_enforcement'],ttps:['T1566','T1059','T1547','T1071','T1082'],active:true,threatLevel:6,lastSeen:'2026-09-08'},
    {id:'APT06',name:'APT41',nation:'China',aliases:['Wicked Panda','BARIUM','Winnti','Double Dragon'],targets:['technology','healthcare','telecom','gaming','financial'],ttps:['T1195','T1190','T1059','T1055','T1078'],active:true,threatLevel:9,lastSeen:'2026-09-09'},
    {id:'APT07',name:'APT40',nation:'China',aliases:['Leviathan','BRONZE MOHAWK','Kryptonite Panda','Gingham Typhoon'],targets:['maritime','defense','technology','government'],ttps:['T1190','T1133','T1059','T1071','T1560'],active:true,threatLevel:8,lastSeen:'2026-09-05'},
    {id:'APT08',name:'APT31',nation:'China',aliases:['Zirconium','Judgment Panda','Violet Typhoon'],targets:['government','technology','financial','defense'],ttps:['T1190','T1566','T1059','T1071','T1005'],active:true,threatLevel:8,lastSeen:'2026-09-01'},
    {id:'APT09',name:'APT10',nation:'China',aliases:['Stone Panda','MenuPass','POTASSIUM','Red Apollo'],targets:['technology','aerospace','telecom','government'],ttps:['T1195','T1090','T1059','T1071','T1560'],active:true,threatLevel:8,lastSeen:'2026-08-20'},
    {id:'APT10',name:'Mustang Panda',nation:'China',aliases:['BRONZE PRESIDENT','Stately Taurus','RedDelta'],targets:['government','NGO','telecom','technology'],ttps:['T1566','T1059','T1547','T1071','T1105'],active:true,threatLevel:7,lastSeen:'2026-09-03'},
    {id:'APT11',name:'Volt Typhoon',nation:'China',aliases:['BRONZE SILHOUETTE','Vanguard Panda','DEV-0391'],targets:['critical_infrastructure','telecom','government','maritime'],ttps:['T1190','T1078','T1059','T1003','T1562'],active:true,threatLevel:10,lastSeen:'2026-09-12'},
    {id:'APT12',name:'Salt Typhoon',nation:'China',aliases:['GhostEmperor','FamousSparrow'],targets:['telecom','isp','government'],ttps:['T1190','T1059','T1078','T1056','T1005'],active:true,threatLevel:9,lastSeen:'2026-09-11'},
    {id:'APT13',name:'Lazarus Group',nation:'North Korea',aliases:['HIDDEN COBRA','Labyrinth Chollima','Diamond Sleet','APT38'],targets:['financial','cryptocurrency','defense','media'],ttps:['T1566','T1059','T1195','T1486','T1565'],active:true,threatLevel:9,lastSeen:'2026-09-10'},
    {id:'APT14',name:'Kimsuky',nation:'North Korea',aliases:['Velvet Chollima','Emerald Sleet','THALLIUM','Black Banshee'],targets:['government','research','think_tanks','media'],ttps:['T1566','T1059','T1056','T1071','T1119'],active:true,threatLevel:7,lastSeen:'2026-09-06'},
    {id:'APT15',name:'Andariel',nation:'North Korea',aliases:['Silent Chollima','Onyx Sleet','Stonefly'],targets:['defense','aerospace','nuclear','technology'],ttps:['T1190','T1059','T1486','T1005','T1021'],active:true,threatLevel:8,lastSeen:'2026-08-25'},
    {id:'APT16',name:'ScarCruft',nation:'North Korea',aliases:['Reaper','APT37','Ricochet Chollima','Ruby Sleet'],targets:['government','military','defectors','media'],ttps:['T1566','T1203','T1059','T1555','T1560'],active:true,threatLevel:7,lastSeen:'2026-08-30'},
    {id:'APT17',name:'Charming Kitten',nation:'Iran',aliases:['APT35','Phosphorus','Mint Sandstorm','NewsBeef'],targets:['government','military','media','academics'],ttps:['T1566','T1078','T1059','T1056','T1071'],active:true,threatLevel:7,lastSeen:'2026-09-07'},
    {id:'APT18',name:'MuddyWater',nation:'Iran',aliases:['MERCURY','Mango Sandstorm','Static Kitten','Seedworm'],targets:['government','telecom','energy','defense'],ttps:['T1566','T1059','T1219','T1071','T1027'],active:true,threatLevel:7,lastSeen:'2026-09-04'},
    {id:'APT19',name:'OilRig',nation:'Iran',aliases:['APT34','Helix Kitten','Hazel Sandstorm','CHRYSENE'],targets:['government','financial','energy','telecom'],ttps:['T1190','T1566','T1059','T1071','T1003'],active:true,threatLevel:8,lastSeen:'2026-09-02'},
    {id:'APT20',name:'CyberAv3ngers',nation:'Iran',aliases:['IRGC-CEC'],targets:['water','energy','critical_infrastructure'],ttps:['T1190','T1059','T1485','T1529'],active:true,threatLevel:7,lastSeen:'2026-08-15'},
    {id:'APT21',name:'Agrius',nation:'Iran',aliases:['Pink Sandstorm','DEV-0227','Agonizing Serpens'],targets:['technology','diamond_industry','education'],ttps:['T1190','T1059','T1486','T1485','T1070'],active:true,threatLevel:6,lastSeen:'2026-07-20'},
    {id:'APT22',name:'Equation Group',nation:'United States',aliases:['EQGRP','Tailored Access Operations'],targets:['government','military','telecom','energy','research'],ttps:['T1195','T1542','T1014','T1027','T1587'],active:true,threatLevel:10,lastSeen:'2026-09-12'},
    {id:'APT23',name:'Lamberts',nation:'United States',aliases:['Longhorn','The Lamberts'],targets:['government','aerospace','energy','telecom','financial'],ttps:['T1195','T1078','T1014','T1027','T1587'],active:false,threatLevel:9,lastSeen:'2025-06-15'},
    {id:'APT24',name:'FIN7',nation:'International',aliases:['Carbanak','Navigator Group','GOLD NIAGARA'],targets:['financial','retail','hospitality'],ttps:['T1566','T1059','T1055','T1071','T1560'],active:true,threatLevel:8,lastSeen:'2026-09-08'},
    {id:'APT25',name:'FIN11',nation:'International',aliases:['TA505','GOLD TAHOE','Graceful Spider'],targets:['financial','retail','healthcare'],ttps:['T1566','T1059','T1486','T1071','T1560'],active:true,threatLevel:7,lastSeen:'2026-08-22'},
    {id:'APT26',name:'Scattered Spider',nation:'International',aliases:['0ktapus','Roasted 0ktapus','Octo Tempest','UNC3944'],targets:['telecom','technology','financial','gaming'],ttps:['T1566','T1078','T1621','T1059','T1136'],active:true,threatLevel:8,lastSeen:'2026-09-11'},
    {id:'APT27',name:'LockBit',nation:'International',aliases:['ABCD Ransomware','Gold Mystic'],targets:['manufacturing','healthcare','education','government'],ttps:['T1190','T1059','T1486','T1490','T1071'],active:true,threatLevel:9,lastSeen:'2026-09-09'},
    {id:'APT28x',name:'BlackCat',nation:'International',aliases:['ALPHV','Noberus','Coreid'],targets:['healthcare','financial','government','critical_infrastructure'],ttps:['T1190','T1078','T1486','T1490','T1027'],active:false,threatLevel:8,lastSeen:'2026-03-15'},
    {id:'APT29x',name:'Rhysida',nation:'International',aliases:['Vice Society successor'],targets:['healthcare','education','government','manufacturing'],ttps:['T1190','T1566','T1486','T1059','T1071'],active:true,threatLevel:7,lastSeen:'2026-08-18'},
    {id:'APT30',name:'Ember Bear',nation:'Russia',aliases:['UAC-0056','Lorec53','Bleeding Bear','Cadet Blizzard'],targets:['government','military','NGO'],ttps:['T1190','T1059','T1485','T1561','T1027'],active:true,threatLevel:7,lastSeen:'2026-09-06'},
    {id:'APT31x',name:'Patchwork',nation:'India',aliases:['Dropping Elephant','Chinastrats','Monsoon'],targets:['government','diplomatic','think_tanks'],ttps:['T1566','T1059','T1203','T1071','T1027'],active:true,threatLevel:5,lastSeen:'2026-07-10'},
    {id:'APT32',name:'OceanLotus',nation:'Vietnam',aliases:['APT32','SeaLotus','Canvas Cyclone'],targets:['government','media','human_rights','manufacturing'],ttps:['T1566','T1059','T1055','T1071','T1027'],active:true,threatLevel:6,lastSeen:'2026-08-05'},
    {id:'APT33',name:'Elfin',nation:'Iran',aliases:['APT33','Refined Kitten','Peach Sandstorm','Holmium'],targets:['aerospace','energy','military','petrochemical'],ttps:['T1566','T1110','T1059','T1071','T1078'],active:true,threatLevel:7,lastSeen:'2026-08-12'},
    {id:'APT34x',name:'Bitter',nation:'South Asia',aliases:['T-APT-17','Hazy Tiger'],targets:['government','military','energy','engineering'],ttps:['T1566','T1059','T1203','T1071','T1056'],active:true,threatLevel:5,lastSeen:'2026-07-28'},
    {id:'APT35x',name:'Dark Caracal',nation:'Lebanon',aliases:['Dark Caracal'],targets:['government','military','financial','defense'],ttps:['T1566','T1059','T1429','T1426','T1071'],active:true,threatLevel:5,lastSeen:'2026-06-15'}
  ];

  // ============================================================================
  // WARGAME SCENARIOS — 22 exercises
  // ============================================================================
  var WARGAME_SCENARIOS = [
    {id:'WG01',name:'BLACKOUT CASCADE',description:'Nation-state actor targets power grid SCADA systems to trigger cascading blackout across 3 regions',difficulty:'extreme',duration:'72h',teams:['Red','Blue','White'],objectives:['Identify initial access vector','Contain lateral movement','Restore power within 4 hours','Preserve forensic evidence'],injects:[{time:'T+00:30',event:'SCADA anomaly detected on PG16'},{time:'T+01:00',event:'Substation PG07 reports unusual traffic'},{time:'T+02:00',event:'First transformer failure reported'},{time:'T+04:00',event:'Media reports widespread outages'},{time:'T+06:00',event:'Hospital backup generators failing'}],scoring:{detection:25,containment:25,recovery:30,reporting:20}},
    {id:'WG02',name:'SILENT WATERS',description:'Coordinated attack on water treatment facilities altering chemical dosing parameters',difficulty:'hard',duration:'48h',teams:['Red','Blue','White'],objectives:['Detect SCADA manipulation','Identify compromised PLCs','Restore safe water chemistry','Coordinate with public health'],injects:[{time:'T+00:15',event:'Chlorine levels fluctuating at WT01'},{time:'T+01:00',event:'pH sensor readings inconsistent'},{time:'T+02:30',event:'Public health complaint cluster'},{time:'T+04:00',event:'Second treatment plant affected'}],scoring:{detection:30,containment:25,recovery:25,reporting:20}},
    {id:'WG03',name:'PHANTOM TRADE',description:'Supply chain compromise targeting financial clearing systems through a corrupted software update',difficulty:'extreme',duration:'96h',teams:['Red','Blue','White','Purple'],objectives:['Identify supply chain vector','Map lateral movement','Prevent fund manipulation','Coordinate with financial regulators'],injects:[{time:'T+01:00',event:'Anomalous API calls to FN05'},{time:'T+03:00',event:'Unusual fund transfers detected'},{time:'T+06:00',event:'Third-party vendor reports breach'},{time:'T+12:00',event:'SEC inquiry received'}],scoring:{detection:20,containment:30,recovery:25,reporting:25}},
    {id:'WG04',name:'IRON SHIELD',description:'Multi-vector DDoS combined with targeted exploitation of military command networks',difficulty:'extreme',duration:'72h',teams:['Red','Blue','White'],objectives:['Maintain C2 capability under attack','Identify real attack vs. diversion','Protect classified systems','Coordinate allied response'],injects:[{time:'T+00:05',event:'Volumetric DDoS begins on GV03'},{time:'T+00:30',event:'Targeted exploitation attempt on GV01'},{time:'T+02:00',event:'Allied partner reports similar activity'},{time:'T+06:00',event:'Intelligence suggests state sponsor'}],scoring:{detection:25,containment:30,recovery:20,reporting:25}},
    {id:'WG05',name:'DARK SIGNAL',description:'Adversary compromises telecom infrastructure to conduct SIGINT collection on government targets',difficulty:'hard',duration:'48h',teams:['Red','Blue','White'],objectives:['Detect unauthorized interception','Identify compromised nodes','Restore secure communications','Assess intelligence loss'],injects:[{time:'T+00:45',event:'Unusual traffic patterns on TC14'},{time:'T+02:00',event:'Encrypted tunnel to unknown endpoint'},{time:'T+04:00',event:'Voice intercept capability confirmed'},{time:'T+08:00',event:'Diplomatic communications potentially compromised'}],scoring:{detection:30,containment:25,recovery:20,reporting:25}},
    {id:'WG06',name:'PIPELINE VENOM',description:'Ransomware attack on energy pipeline SCADA systems with physical safety implications',difficulty:'hard',duration:'48h',teams:['Red','Blue','White'],objectives:['Contain ransomware spread','Maintain pipeline safety','Restore operations without payment','Preserve evidence for attribution'],injects:[{time:'T+00:10',event:'EN19 displays ransom note'},{time:'T+00:45',event:'Pipeline pressure anomalies'},{time:'T+02:00',event:'Second pipeline segment affected'},{time:'T+06:00',event:'Media coverage begins'}],scoring:{detection:20,containment:35,recovery:25,reporting:20}},
    {id:'WG07',name:'GHOST HOSPITAL',description:'Targeted attack on hospital networks disrupting medical devices and EHR systems',difficulty:'hard',duration:'36h',teams:['Red','Blue','White'],objectives:['Protect patient safety','Restore EHR access','Maintain medical device operation','Coordinate with public health'],injects:[{time:'T+00:20',event:'HC04 EHR system slow'},{time:'T+01:00',event:'Medical device alerts on HC06'},{time:'T+02:00',event:'Emergency diversion protocol activated'},{time:'T+04:00',event:'Second hospital affected'}],scoring:{detection:25,containment:30,recovery:30,reporting:15}},
    {id:'WG08',name:'BALLOT BOX',description:'Election infrastructure compromise attempting to alter vote tabulation and registration databases',difficulty:'extreme',duration:'96h',teams:['Red','Blue','White','Legal'],objectives:['Detect manipulation attempts','Preserve vote integrity','Maintain public confidence','Document chain of custody'],injects:[{time:'T+01:00',event:'Registration database anomaly'},{time:'T+04:00',event:'Tabulation discrepancy reported'},{time:'T+08:00',event:'Social media disinformation campaign begins'},{time:'T+12:00',event:'Foreign nation linked to activity'},{time:'T+24:00',event:'Congressional inquiry'}],scoring:{detection:25,containment:25,recovery:20,reporting:30}},
    {id:'WG09',name:'MERIDIAN BREACH',description:'Insider threat exfiltrating classified data through covert channels',difficulty:'medium',duration:'24h',teams:['Red','Blue','White'],objectives:['Identify insider','Map exfiltration channels','Assess data loss','Coordinate with CI'],injects:[{time:'T+00:30',event:'DLP alert on GV08'},{time:'T+01:30',event:'Unusual after-hours access'},{time:'T+03:00',event:'Encrypted data to personal email'},{time:'T+06:00',event:'Insider identified'}],scoring:{detection:30,containment:25,recovery:20,reporting:25}},
    {id:'WG10',name:'TSUNAMI LOGIC',description:'Logic bomb planted in port management systems timed with physical weather event',difficulty:'hard',duration:'48h',teams:['Red','Blue','White'],objectives:['Detect logic bomb','Prevent port shutdown','Maintain maritime safety','Restore operations'],injects:[{time:'T+00:00',event:'Hurricane warning issued'},{time:'T+02:00',event:'TR06 port system malfunction'},{time:'T+04:00',event:'Logic bomb triggers on TR07'},{time:'T+08:00',event:'Ships unable to navigate safely'}],scoring:{detection:25,containment:30,recovery:30,reporting:15}},
    {id:'WG11',name:'CRYPTO SIEGE',description:'Coordinated attack on cryptocurrency exchanges and financial systems to manipulate markets',difficulty:'medium',duration:'24h',teams:['Red','Blue','White'],objectives:['Detect market manipulation','Prevent unauthorized trades','Freeze compromised accounts','Coordinate with SEC/CFTC'],injects:[{time:'T+00:15',event:'Flash crash on FN11'},{time:'T+00:45',event:'Unusual trading on FN01'},{time:'T+02:00',event:'Exchange API exploitation'},{time:'T+04:00',event:'$500M in suspicious transfers'}],scoring:{detection:30,containment:30,recovery:20,reporting:20}},
    {id:'WG12',name:'NOMAD STORM',description:'Advanced persistent threat establishing long-term presence across multiple sectors',difficulty:'extreme',duration:'168h',teams:['Red','Blue','White','Purple'],objectives:['Map adversary infrastructure','Identify all compromised nodes','Conduct controlled takedown','Prevent re-entry'],injects:[{time:'T+04:00',event:'Unusual beacon traffic detected'},{time:'T+12:00',event:'C2 channel identified'},{time:'T+24:00',event:'Lateral movement confirmed'},{time:'T+48:00',event:'Data staging discovered'},{time:'T+72:00',event:'Additional C2 channels found'}],scoring:{detection:25,containment:25,recovery:25,reporting:25}},
    {id:'WG13',name:'AMBER DAWN',description:'Pre-positioned implants across telecom activated during geopolitical crisis',difficulty:'extreme',duration:'72h',teams:['Red','Blue','White'],objectives:['Identify all implants','Assess communications integrity','Maintain government communications','Counter disinformation'],injects:[{time:'T+00:00',event:'Geopolitical crisis begins'},{time:'T+01:00',event:'TC03 and TC14 show anomalies'},{time:'T+04:00',event:'Government comms degraded'},{time:'T+08:00',event:'Military readiness impacted'}],scoring:{detection:25,containment:30,recovery:25,reporting:20}},
    {id:'WG14',name:'WINTER HARVEST',description:'Agricultural IoT systems compromised to disrupt food supply chain',difficulty:'medium',duration:'36h',teams:['Red','Blue'],objectives:['Detect IoT compromise','Isolate affected systems','Prevent crop damage','Restore monitoring'],injects:[{time:'T+00:30',event:'Irrigation system malfunction'},{time:'T+02:00',event:'Temperature controls failing'},{time:'T+04:00',event:'GPS spoofing on farm equipment'},{time:'T+08:00',event:'Regional food supply concern'}],scoring:{detection:30,containment:30,recovery:25,reporting:15}},
    {id:'WG15',name:'SILICON VEIL',description:'Supply chain attack through semiconductor manufacturer implanting hardware backdoors',difficulty:'extreme',duration:'168h',teams:['Red','Blue','White','Purple'],objectives:['Identify compromised hardware','Map affected deployments','Develop detection signatures','Coordinate national response'],injects:[{time:'T+24:00',event:'Anomalous chip behavior detected'},{time:'T+48:00',event:'Firmware analysis reveals backdoor'},{time:'T+72:00',event:'Scope of deployment assessed'},{time:'T+120:00',event:'Replacement plan initiated'}],scoring:{detection:30,containment:20,recovery:20,reporting:30}},
    {id:'WG16',name:'ECHO CHAMBER',description:'Combined cyber-information operation targeting public trust in government institutions',difficulty:'hard',duration:'72h',teams:['Red','Blue','White','IO'],objectives:['Detect bot networks','Counter false narratives','Protect government web presence','Coordinate public messaging'],injects:[{time:'T+00:00',event:'Viral disinformation post detected'},{time:'T+02:00',event:'Government website defaced'},{time:'T+06:00',event:'Deepfake video of official released'},{time:'T+12:00',event:'Public panic in social media'}],scoring:{detection:20,containment:25,recovery:25,reporting:30}},
    {id:'WG17',name:'BROKEN CHAIN',description:'Multi-stage supply chain attack through open-source libraries into government systems',difficulty:'hard',duration:'48h',teams:['Red','Blue','White'],objectives:['Identify malicious package','Map dependency tree impact','Patch affected systems','Prevent further compromise'],injects:[{time:'T+01:00',event:'Suspicious npm package update'},{time:'T+03:00',event:'Build pipeline compromise'},{time:'T+06:00',event:'Production systems affected'},{time:'T+12:00',event:'Data exfiltration detected'}],scoring:{detection:30,containment:25,recovery:25,reporting:20}},
    {id:'WG18',name:'RAIL GHOST',description:'Attack on rail signaling systems that could cause train collisions',difficulty:'hard',duration:'24h',teams:['Red','Blue','White'],objectives:['Detect signal manipulation','Prevent collision','Restore safe operations','Preserve evidence'],injects:[{time:'T+00:10',event:'Signal conflict on TR03'},{time:'T+00:30',event:'Automatic braking failure'},{time:'T+01:00',event:'Second rail segment affected'},{time:'T+02:00',event:'Emergency shutdown initiated'}],scoring:{detection:25,containment:35,recovery:25,reporting:15}},
    {id:'WG19',name:'PLAGUE PROTOCOL',description:'Cyber attack on pandemic response systems during active health emergency',difficulty:'extreme',duration:'96h',teams:['Red','Blue','White','Medical'],objectives:['Protect health data','Maintain vaccine distribution','Restore contact tracing','Coordinate with WHO'],injects:[{time:'T+00:30',event:'HC18 monitoring data corrupted'},{time:'T+02:00',event:'Vaccine supply chain disrupted'},{time:'T+06:00',event:'Contact tracing system offline'},{time:'T+12:00',event:'False pandemic data published'}],scoring:{detection:25,containment:25,recovery:30,reporting:20}},
    {id:'WG20',name:'QUANTUM HOUR',description:'Quantum computing breakthrough enables rapid decryption of legacy encrypted communications',difficulty:'extreme',duration:'168h',teams:['Red','Blue','White','Crypto'],objectives:['Assess cryptographic exposure','Rotate vulnerable credentials','Deploy quantum-resistant crypto','Protect intelligence equities'],injects:[{time:'T+00:00',event:'Intel reports quantum capability demonstrated'},{time:'T+04:00',event:'Legacy VPN traffic at risk'},{time:'T+24:00',event:'Classified traffic assessment'},{time:'T+48:00',event:'First confirmed decryption'}],scoring:{detection:20,containment:25,recovery:30,reporting:25}},
    {id:'WG21',name:'TABLETOP BASICS',description:'Introductory exercise covering phishing attack leading to ransomware on corporate network',difficulty:'easy',duration:'4h',teams:['Blue'],objectives:['Identify phishing email','Isolate infected host','Restore from backup','Update security awareness'],injects:[{time:'T+00:10',event:'User reports suspicious email'},{time:'T+00:30',event:'Endpoint detection alert'},{time:'T+01:00',event:'Network shares encrypted'}],scoring:{detection:30,containment:30,recovery:30,reporting:10}},
    {id:'WG22',name:'FIREWALL DRILL',description:'Basic network defense exercise testing firewall rules and IDS configuration',difficulty:'easy',duration:'4h',teams:['Blue'],objectives:['Detect port scans','Block unauthorized access','Tune IDS rules','Document findings'],injects:[{time:'T+00:05',event:'External port scan detected'},{time:'T+00:20',event:'Brute force SSH attempt'},{time:'T+00:45',event:'Web application probe'}],scoring:{detection:35,containment:30,recovery:15,reporting:20}}
  ];

  // ============================================================================
  // INTELLIGENCE FEEDS — 55 entries
  // ============================================================================
  var INTEL_FEEDS = [
    {id:'INT01',type:'SIGINT',source:'NSA/CSS',classification:'TS/SCI',timestamp:'2026-09-13T02:14:00Z',summary:'Intercepted encrypted communications between APT28 C2 server and compromised node in Baltic state telecom infrastructure',reliability:'A',credibility:1,related:['INT03','INT07']},
    {id:'INT02',type:'OSINT',source:'Twitter/X Monitoring',classification:'UNCLASSIFIED',timestamp:'2026-09-13T01:30:00Z',summary:'Multiple hacktivist groups announcing coordinated operation targeting financial sector for September 15',reliability:'C',credibility:3,related:['INT11']},
    {id:'INT03',type:'CYBINT',source:'US-CERT',classification:'SECRET',timestamp:'2026-09-12T22:00:00Z',summary:'New Sandworm malware variant identified targeting ICS/SCADA systems using Modbus TCP exploitation',reliability:'A',credibility:1,related:['INT01','INT15']},
    {id:'INT04',type:'HUMINT',source:'CIA Station Tallinn',classification:'TOP SECRET',timestamp:'2026-09-12T20:45:00Z',summary:'Source reports Russian GRU unit preparing cyber operations against NATO member energy infrastructure',reliability:'B',credibility:2,related:['INT01','INT03']},
    {id:'INT05',type:'SIGINT',source:'GCHQ',classification:'TS/SCI',timestamp:'2026-09-12T18:30:00Z',summary:'Detected Turla beacon traffic originating from diplomatic network in Southeast Asian nation',reliability:'A',credibility:1,related:['INT09']},
    {id:'INT06',type:'OSINT',source:'Recorded Future',classification:'UNCLASSIFIED',timestamp:'2026-09-12T16:00:00Z',summary:'Dark web marketplace listing zero-day exploit for Palo Alto GlobalProtect VPN, price $2.5M',reliability:'B',credibility:2,related:['INT20']},
    {id:'INT07',type:'CYBINT',source:'Mandiant',classification:'CONFIDENTIAL',timestamp:'2026-09-12T14:30:00Z',summary:'APT29 observed deploying novel backdoor in cloud environments via compromised OAuth applications',reliability:'A',credibility:1,related:['INT01','INT22']},
    {id:'INT08',type:'HUMINT',source:'DIA',classification:'SECRET',timestamp:'2026-09-12T12:00:00Z',summary:'North Korean cyber operators reportedly relocated to facility in Shenyang, China for joint operations',reliability:'B',credibility:3,related:['INT13']},
    {id:'INT09',type:'SIGINT',source:'Five Eyes SIGINT',classification:'TS/SCI',timestamp:'2026-09-12T10:15:00Z',summary:'Unusual satellite communications pattern detected consistent with pre-positioning for cyber operation',reliability:'A',credibility:2,related:['INT05','INT04']},
    {id:'INT10',type:'OSINT',source:'Shodan Monitor',classification:'UNCLASSIFIED',timestamp:'2026-09-12T08:00:00Z',summary:'Spike in scanning activity targeting Fortinet and Ivanti VPN endpoints from Chinese IP ranges',reliability:'B',credibility:2,related:['INT12']},
    {id:'INT11',type:'CYBINT',source:'FBI Cyber Division',classification:'SECRET',timestamp:'2026-09-12T06:30:00Z',summary:'Ransomware group LockBit developing new variant with wiper capability for use against critical infrastructure',reliability:'A',credibility:2,related:['INT02','INT25']},
    {id:'INT12',type:'SIGINT',source:'NSA/CSS',classification:'TS/SCI',timestamp:'2026-09-11T22:00:00Z',summary:'Volt Typhoon infrastructure expanded with 200+ new compromised SOHO routers in Southeast Asia',reliability:'A',credibility:1,related:['INT10','INT30']},
    {id:'INT13',type:'CYBINT',source:'CISA',classification:'CONFIDENTIAL',timestamp:'2026-09-11T20:00:00Z',summary:'Lazarus Group cryptocurrency theft campaign targeting DeFi protocols with smart contract exploits',reliability:'A',credibility:1,related:['INT08']},
    {id:'INT14',type:'HUMINT',source:'MI6',classification:'TOP SECRET',timestamp:'2026-09-11T18:30:00Z',summary:'Iranian IRGC cyber unit received new offensive tools from Russian partners for use against Gulf state infrastructure',reliability:'B',credibility:2,related:['INT18','INT04']},
    {id:'INT15',type:'OSINT',source:'VirusTotal',classification:'UNCLASSIFIED',timestamp:'2026-09-11T16:00:00Z',summary:'New malware sample with Sandworm TTPs uploaded from Ukrainian IP, targets Siemens S7 PLCs',reliability:'B',credibility:2,related:['INT03']},
    {id:'INT16',type:'CYBINT',source:'NCSC-UK',classification:'SECRET',timestamp:'2026-09-11T14:00:00Z',summary:'Active exploitation of zero-day in widely deployed enterprise email gateway affecting government departments',reliability:'A',credibility:1,related:['INT20']},
    {id:'INT17',type:'SIGINT',source:'ASD',classification:'TS/SCI',timestamp:'2026-09-11T12:00:00Z',summary:'Chinese military signals unit conducting electronic warfare exercises near Taiwan Strait with cyber component',reliability:'A',credibility:1,related:['INT30']},
    {id:'INT18',type:'HUMINT',source:'Mossad Liaison',classification:'TOP SECRET',timestamp:'2026-09-11T10:00:00Z',summary:'Iranian cyber operators testing destructive malware against simulated water treatment plant environment',reliability:'A',credibility:2,related:['INT14','INT20']},
    {id:'INT19',type:'OSINT',source:'GitHub Monitoring',classification:'UNCLASSIFIED',timestamp:'2026-09-11T08:00:00Z',summary:'Proof-of-concept exploit for critical Cisco IOS XE vulnerability published, active exploitation expected within 48h',reliability:'A',credibility:1,related:['INT06']},
    {id:'INT20',type:'CYBINT',source:'NSA/IAD',classification:'SECRET',timestamp:'2026-09-10T22:00:00Z',summary:'Assessment: 3 zero-day vulnerabilities in major firewall vendors being actively stockpiled by Chinese APTs',reliability:'A',credibility:2,related:['INT06','INT16','INT19']},
    {id:'INT21',type:'SIGINT',source:'CSEC',classification:'TS/SCI',timestamp:'2026-09-10T20:00:00Z',summary:'Intercepted tasking order for Kimsuky operators to target South Korean nuclear research institutions',reliability:'A',credibility:1,related:['INT08']},
    {id:'INT22',type:'CYBINT',source:'CrowdStrike',classification:'CONFIDENTIAL',timestamp:'2026-09-10T18:00:00Z',summary:'APT29 using compromised Microsoft 365 tenants as relay points for lateral movement into government clouds',reliability:'A',credibility:1,related:['INT07']},
    {id:'INT23',type:'OSINT',source:'Telegram Monitoring',classification:'UNCLASSIFIED',timestamp:'2026-09-10T16:00:00Z',summary:'Pro-Russian hacktivist group claiming DDoS capabilities against NATO member state banking systems',reliability:'C',credibility:4,related:['INT02']},
    {id:'INT24',type:'HUMINT',source:'CIA NCS',classification:'TOP SECRET',timestamp:'2026-09-10T14:00:00Z',summary:'Chinese MSS maintaining persistent access to 5+ US critical infrastructure entities per Volt Typhoon campaign',reliability:'A',credibility:1,related:['INT12','INT30']},
    {id:'INT25',type:'CYBINT',source:'Europol EC3',classification:'CONFIDENTIAL',timestamp:'2026-09-10T12:00:00Z',summary:'LockBit affiliate program restructuring with focus on critical infrastructure targets in Western Europe',reliability:'B',credibility:2,related:['INT11']},
    {id:'INT26',type:'SIGINT',source:'NSA/CSS',classification:'TS/SCI',timestamp:'2026-09-10T10:00:00Z',summary:'North Korean operators establishing new C2 infrastructure in neutral country hosting provider',reliability:'A',credibility:1,related:['INT08','INT13']},
    {id:'INT27',type:'OSINT',source:'DNS Passive Monitoring',classification:'UNCLASSIFIED',timestamp:'2026-09-10T08:00:00Z',summary:'Surge in DNS queries to known APT41 domain generation algorithm domains from US healthcare sector',reliability:'B',credibility:2,related:['INT31']},
    {id:'INT28',type:'CYBINT',source:'JCDC',classification:'SECRET',timestamp:'2026-09-09T22:00:00Z',summary:'Coordinated vulnerability disclosure: critical flaw in industrial control system protocol used in 70% of US power grid',reliability:'A',credibility:1,related:['INT03','INT15']},
    {id:'INT29',type:'HUMINT',source:'DIA ATTACHE',classification:'SECRET',timestamp:'2026-09-09T20:00:00Z',summary:'Russian military intelligence developing autonomous cyber weapon capable of self-propagation through air-gapped networks',reliability:'C',credibility:3,related:['INT04']},
    {id:'INT30',type:'CYBINT',source:'ODNI',classification:'TOP SECRET',timestamp:'2026-09-09T18:00:00Z',summary:'National intelligence estimate: China has pre-positioned destructive cyber capabilities across US critical infrastructure in preparation for Taiwan contingency',reliability:'A',credibility:1,related:['INT12','INT17','INT24']},
    {id:'INT31',type:'SIGINT',source:'GCHQ',classification:'TS/SCI',timestamp:'2026-09-09T16:00:00Z',summary:'APT41 operators using legitimate cloud services for data staging in campaign against pharmaceutical companies',reliability:'A',credibility:1,related:['INT27']},
    {id:'INT32',type:'OSINT',source:'Censys',classification:'UNCLASSIFIED',timestamp:'2026-09-09T14:00:00Z',summary:'Large-scale internet scan from Russian IP space targeting Exchange servers with ProxyNotShell signatures',reliability:'B',credibility:2,related:[]},
    {id:'INT33',type:'CYBINT',source:'ACSC',classification:'CONFIDENTIAL',timestamp:'2026-09-09T12:00:00Z',summary:'Salt Typhoon access to telecom infrastructure more extensive than initially assessed, includes lawful intercept systems',reliability:'A',credibility:1,related:['INT12']},
    {id:'INT34',type:'HUMINT',source:'SIS',classification:'SECRET',timestamp:'2026-09-09T10:00:00Z',summary:'Iranian proxy group Hezbollah developing cyber capabilities targeting Israeli water and energy infrastructure',reliability:'B',credibility:2,related:['INT14','INT18']},
    {id:'INT35',type:'SIGINT',source:'NSA/CSS',classification:'TS/SCI',timestamp:'2026-09-09T08:00:00Z',summary:'Detected command and control traffic consistent with Equation Group implant from allied nation defense network',reliability:'A',credibility:1,related:[]},
    {id:'INT36',type:'OSINT',source:'Pastebin Scraper',classification:'UNCLASSIFIED',timestamp:'2026-09-08T22:00:00Z',summary:'Database dump from regional ISP posted containing 50K subscriber credentials, potential credential stuffing risk',reliability:'B',credibility:2,related:[]},
    {id:'INT37',type:'CYBINT',source:'Unit 42',classification:'CONFIDENTIAL',timestamp:'2026-09-08T20:00:00Z',summary:'New Scattered Spider campaign targeting telecom providers using SIM swapping and social engineering',reliability:'A',credibility:1,related:[]},
    {id:'INT38',type:'HUMINT',source:'FBI LEGAT Seoul',classification:'SECRET',timestamp:'2026-09-08T18:00:00Z',summary:'DPRK cyber operatives conducting reconnaissance against South Korean and Japanese financial institutions',reliability:'B',credibility:2,related:['INT08','INT13']},
    {id:'INT39',type:'SIGINT',source:'Five Eyes',classification:'TS/SCI',timestamp:'2026-09-08T16:00:00Z',summary:'Unusual radio frequency emissions from Chinese fishing vessel near undersea cable landing point',reliability:'B',credibility:3,related:['INT17']},
    {id:'INT40',type:'OSINT',source:'AlienVault OTX',classification:'UNCLASSIFIED',timestamp:'2026-09-08T14:00:00Z',summary:'New IoC set released for MuddyWater campaign targeting Middle Eastern government email servers',reliability:'B',credibility:2,related:[]},
    {id:'INT41',type:'CYBINT',source:'CNMF',classification:'SECRET',timestamp:'2026-09-08T12:00:00Z',summary:'Forward hunt team identified novel Chinese implant in partner nation telecom infrastructure',reliability:'A',credibility:1,related:['INT33']},
    {id:'INT42',type:'HUMINT',source:'CIA Station Beijing',classification:'TOP SECRET',timestamp:'2026-09-08T10:00:00Z',summary:'PLA SSF Unit 61398 tasked with developing capabilities against US satellite ground stations',reliability:'B',credibility:2,related:['INT17']},
    {id:'INT43',type:'SIGINT',source:'NSA/CSS',classification:'TS/SCI',timestamp:'2026-09-08T08:00:00Z',summary:'Gamaredon operators increasing tempo of operations against Ukrainian military command systems',reliability:'A',credibility:1,related:[]},
    {id:'INT44',type:'OSINT',source:'MITRE ATT&CK Updates',classification:'UNCLASSIFIED',timestamp:'2026-09-07T22:00:00Z',summary:'New technique documented: adversaries using legitimate remote monitoring tools as living-off-the-land binaries',reliability:'A',credibility:1,related:[]},
    {id:'INT45',type:'CYBINT',source:'CISA ICS-CERT',classification:'CONFIDENTIAL',timestamp:'2026-09-07T20:00:00Z',summary:'Advisory: Critical vulnerabilities in Schneider Electric and Siemens PLCs affecting water and energy sectors',reliability:'A',credibility:1,related:['INT28']},
    {id:'INT46',type:'HUMINT',source:'DIA',classification:'SECRET',timestamp:'2026-09-07T18:00:00Z',summary:'Intelligence indicates Russia stockpiling cyber weapons for potential deployment in event of NATO escalation',reliability:'B',credibility:2,related:['INT04','INT29']},
    {id:'INT47',type:'SIGINT',source:'CSEC',classification:'TS/SCI',timestamp:'2026-09-07T16:00:00Z',summary:'Intercepted planning communications for coordinated ransomware campaign against Canadian healthcare',reliability:'A',credibility:2,related:['INT11']},
    {id:'INT48',type:'OSINT',source:'Exploit-DB',classification:'UNCLASSIFIED',timestamp:'2026-09-07T14:00:00Z',summary:'Public exploit released for VMware vCenter RCE vulnerability, patch adoption rate only 34%',reliability:'A',credibility:1,related:['INT19']},
    {id:'INT49',type:'CYBINT',source:'UK NCSC',classification:'CONFIDENTIAL',timestamp:'2026-09-07T12:00:00Z',summary:'Assessment: Russian state actors maintain persistent access to at least 12 UK critical infrastructure entities',reliability:'A',credibility:2,related:['INT04']},
    {id:'INT50',type:'HUMINT',source:'Mossad',classification:'TOP SECRET',timestamp:'2026-09-07T10:00:00Z',summary:'Iran developing offensive cyber capability targeting Gulf state desalination plants',reliability:'A',credibility:2,related:['INT18','INT34']},
    {id:'INT51',type:'SIGINT',source:'ASD',classification:'TS/SCI',timestamp:'2026-09-07T08:00:00Z',summary:'APT40 scanning Australian and Japanese maritime infrastructure networks',reliability:'A',credibility:1,related:[]},
    {id:'INT52',type:'OSINT',source:'Shadowserver',classification:'UNCLASSIFIED',timestamp:'2026-09-06T22:00:00Z',summary:'300K+ devices still vulnerable to Log4Shell despite 5 years of patches, concentrated in healthcare and education',reliability:'A',credibility:1,related:[]},
    {id:'INT53',type:'CYBINT',source:'Dragos',classification:'CONFIDENTIAL',timestamp:'2026-09-06T20:00:00Z',summary:'New ICS malware framework discovered targeting Modbus and OPC UA protocols in energy sector',reliability:'A',credibility:1,related:['INT03','INT28']},
    {id:'INT54',type:'HUMINT',source:'CIA',classification:'SECRET',timestamp:'2026-09-06T18:00:00Z',summary:'North Korean hackers stolen $1.2B in cryptocurrency in 2026, funding weapons programs',reliability:'A',credibility:1,related:['INT13','INT38']},
    {id:'INT55',type:'SIGINT',source:'NSA/CSS',classification:'TS/SCI',timestamp:'2026-09-06T16:00:00Z',summary:'Russian SVR leveraging compromised edge devices as operational relay boxes across 40+ countries',reliability:'A',credibility:1,related:['INT07','INT22']}
  ];

  // ============================================================================
  // THREAT PREDICTIONS — 25 forecasts
  // ============================================================================
  var THREAT_PREDICTIONS = [
    {id:'TP01',horizon:'24h',confidence:87,threat:'Sandworm SCADA exploitation campaign targeting European energy grid',targets:['PG14','PG16','EN19'],indicators:['New C2 infrastructure registered','Modbus scanning detected','HUMINT corroboration'],geopoliticalTriggers:['Russia-NATO tensions','Energy price manipulation','Winter heating season'],status:'active'},
    {id:'TP02',horizon:'24h',confidence:72,threat:'Ransomware attack on US hospital chain during holiday weekend',targets:['HC01','HC02','HC04'],indicators:['Reconnaissance scanning observed','Affiliate recruitment posts','Prior targeting pattern'],geopoliticalTriggers:[],status:'active'},
    {id:'TP03',horizon:'24h',confidence:91,threat:'DDoS campaign against NATO member financial institutions',targets:['FN01','FN03','FN07'],indicators:['Hacktivist announcements','Botnet rental observed','Test probes detected'],geopoliticalTriggers:['NATO summit','Sanctions expansion'],status:'active'},
    {id:'TP04',horizon:'48h',confidence:65,threat:'Supply chain compromise through popular JavaScript package manager',targets:['SC15','SC18','SC22'],indicators:['Suspicious package updates','Typosquatting detected','Build pipeline anomalies'],geopoliticalTriggers:[],status:'monitoring'},
    {id:'TP05',horizon:'48h',confidence:78,threat:'Chinese APT exploitation of telecom infrastructure for intelligence collection',targets:['TC03','TC14','TC15'],indicators:['Volt Typhoon infrastructure expansion','Zero-day stockpiling','Geopolitical escalation'],geopoliticalTriggers:['Taiwan strait tensions','Trade war escalation','Tech sanctions'],status:'active'},
    {id:'TP06',horizon:'72h',confidence:55,threat:'Iranian destructive attack on Gulf state water desalination infrastructure',targets:['WT15','WT01'],indicators:['IRGC cyber unit activity','Test environment operation','Regional tensions'],geopoliticalTriggers:['Iran nuclear negotiations','Gulf state normalization','Proxy conflict escalation'],status:'monitoring'},
    {id:'TP07',horizon:'24h',confidence:83,threat:'Credential stuffing campaign using leaked ISP database',targets:['GV03','FN07','FN08'],indicators:['Database posted on dark web','Credential validation activity','Automated login attempts'],geopoliticalTriggers:[],status:'active'},
    {id:'TP08',horizon:'48h',confidence:60,threat:'North Korean cryptocurrency exchange heist via smart contract exploit',targets:['FN11'],indicators:['Reconnaissance of DeFi protocols','Flash loan probing','Mixer pre-positioning'],geopoliticalTriggers:['DPRK sanctions pressure','Weapons program funding'],status:'monitoring'},
    {id:'TP09',horizon:'72h',confidence:45,threat:'Insider threat data exfiltration from classified network',targets:['GV01','GV08'],indicators:['Behavioral analytics anomaly','After-hours access pattern','Personal device usage'],geopoliticalTriggers:['Foreign recruitment activity'],status:'monitoring'},
    {id:'TP10',horizon:'24h',confidence:76,threat:'Exploitation of newly published Cisco IOS XE vulnerability in government networks',targets:['GV03','TC08','TC09'],indicators:['PoC published','Mass scanning detected','Patch adoption low'],geopoliticalTriggers:[],status:'active'},
    {id:'TP11',horizon:'48h',confidence:68,threat:'APT41 campaign against pharmaceutical companies for COVID-related research',targets:['HC10','HC14','HC18'],indicators:['DGA domain resolution','Cloud staging activity','Prior targeting history'],geopoliticalTriggers:['Pandemic response competition','Vaccine diplomacy'],status:'active'},
    {id:'TP12',horizon:'72h',confidence:40,threat:'Quantum computing threat to legacy VPN encryption in government networks',targets:['GV01','GV02','GV11'],indicators:['Intelligence assessment','Research publications','Adversary investment'],geopoliticalTriggers:['Technology competition','Arms race dynamics'],status:'monitoring'},
    {id:'TP13',horizon:'24h',confidence:89,threat:'Scattered Spider social engineering campaign targeting telecom providers',targets:['TC01','TC16','TC08'],indicators:['SIM swap attempts','Help desk social engineering','Prior campaign pattern'],geopoliticalTriggers:[],status:'active'},
    {id:'TP14',horizon:'48h',confidence:58,threat:'Logic bomb in port management software timed with hurricane season',targets:['TR06','TR07','TR17'],indicators:['Code analysis findings','Weather pattern correlation','Insider access confirmed'],geopoliticalTriggers:['Hurricane season','Trade disruption'],status:'monitoring'},
    {id:'TP15',horizon:'72h',confidence:52,threat:'Election infrastructure probing by multiple nation-state actors',targets:['GV04','GV05'],indicators:['Scanning activity','Social media coordination','Prior election cycles'],geopoliticalTriggers:['Upcoming elections','Foreign influence campaigns','Polarization'],status:'active'},
    {id:'TP16',horizon:'24h',confidence:70,threat:'Rhysida ransomware deployment against education sector',targets:['HC12'],indicators:['Reconnaissance confirmed','Access broker listing','School year timing'],geopoliticalTriggers:[],status:'monitoring'},
    {id:'TP17',horizon:'48h',confidence:74,threat:'GPS spoofing campaign targeting maritime navigation in contested waters',targets:['GV18','TR17'],indicators:['RF emission anomalies','Naval exercise timing','Prior incidents'],geopoliticalTriggers:['South China Sea tensions','Freedom of navigation'],status:'active'},
    {id:'TP18',horizon:'72h',confidence:48,threat:'Coordinated attack on autonomous vehicle communication systems',targets:['TR20','TC12','TC13'],indicators:['V2X protocol research published','5G vulnerability identified','Test network probing'],geopoliticalTriggers:['Technology competition'],status:'monitoring'},
    {id:'TP19',horizon:'24h',confidence:81,threat:'Exploitation of Schneider Electric PLC vulnerabilities in water sector',targets:['WT11','WT01','WT17'],indicators:['ICS-CERT advisory','Exploit code available','Targeted scanning'],geopoliticalTriggers:[],status:'active'},
    {id:'TP20',horizon:'48h',confidence:63,threat:'Russian pre-positioned implants activated in telecom during diplomatic crisis',targets:['TC03','TC14','TC17'],indicators:['Dormant beacon awakening','Geopolitical trigger','Intelligence reporting'],geopoliticalTriggers:['Diplomatic expulsions','Military posturing','Sanctions escalation'],status:'monitoring'},
    {id:'TP21',horizon:'72h',confidence:35,threat:'Hardware backdoor activation in widely deployed network equipment',targets:['TC08','TC09','TC14'],indicators:['Anomalous chip behavior','Firmware analysis','Supply chain investigation'],geopoliticalTriggers:['Tech decoupling','Supply chain competition'],status:'monitoring'},
    {id:'TP22',horizon:'24h',confidence:77,threat:'Gamaredon intensified targeting of Ukrainian military systems',targets:['GV10','GV19'],indicators:['Increased phishing volume','New infrastructure registered','Conflict dynamics'],geopoliticalTriggers:['Ukraine conflict','Counteroffensive operations','Escalation risk'],status:'active'},
    {id:'TP23',horizon:'48h',confidence:56,threat:'Attack on energy trading platform to manipulate commodity prices',targets:['EN18','FN01','FN02'],indicators:['Unauthorized API access attempts','Insider trading indicators','Market manipulation pattern'],geopoliticalTriggers:['OPEC decisions','Sanctions','Energy crisis'],status:'monitoring'},
    {id:'TP24',horizon:'72h',confidence:42,threat:'Multi-sector cascading attack originating from compromised DNS infrastructure',targets:['TC10','TC11'],indicators:['DNS poisoning attempts','BGP anomalies','Cache pollution'],geopoliticalTriggers:[],status:'monitoring'},
    {id:'TP25',horizon:'24h',confidence:85,threat:'APT28 phishing campaign targeting government employees with fake security updates',targets:['GV03','GV13','GV14'],indicators:['New phishing domains registered','Spearphishing emails intercepted','TTP match confirmed'],geopoliticalTriggers:['Intelligence collection priorities','Election cycle'],status:'active'}
  ];

  // ============================================================================
  // SUPPLY CHAIN COMPONENTS — 110 entries
  // ============================================================================
  var SUPPLY_CHAIN = [
    {id:'SC01',name:'Red Hat Enterprise Linux',vendor:'Red Hat',version:'9.4',category:'os',riskScore:12,deps:[],vulns:['CVE-2024-1086'],lastAudit:'2026-09-01',license:'GPL'},
    {id:'SC02',name:'Windows Server 2025',vendor:'Microsoft',version:'10.0.26100',category:'os',riskScore:25,deps:[],vulns:['CVE-2024-38063','CVE-2024-43491'],lastAudit:'2026-09-05',license:'Commercial'},
    {id:'SC03',name:'Ubuntu Server',vendor:'Canonical',version:'24.04 LTS',category:'os',riskScore:15,deps:[],vulns:['CVE-2024-2961'],lastAudit:'2026-08-28',license:'GPL'},
    {id:'SC04',name:'VMware ESXi',vendor:'Broadcom',version:'8.0U3',category:'os',riskScore:30,deps:[],vulns:['CVE-2024-37085','CVE-2024-37086'],lastAudit:'2026-08-15',license:'Commercial'},
    {id:'SC05',name:'VxWorks RTOS',vendor:'Wind River',version:'7.0',category:'os',riskScore:45,deps:[],vulns:['CVE-2019-12255','CVE-2019-12256'],lastAudit:'2026-06-01',license:'Commercial'},
    {id:'SC06',name:'Node.js',vendor:'OpenJS Foundation',version:'22.8.0',category:'runtime',riskScore:18,deps:['SC03'],vulns:[],lastAudit:'2026-09-10',license:'MIT'},
    {id:'SC07',name:'Python',vendor:'PSF',version:'3.13.0',category:'runtime',riskScore:10,deps:['SC01'],vulns:[],lastAudit:'2026-09-08',license:'PSF'},
    {id:'SC08',name:'Java OpenJDK',vendor:'Oracle/Community',version:'21.0.4',category:'runtime',riskScore:14,deps:['SC01'],vulns:[],lastAudit:'2026-09-03',license:'GPL-CPE'},
    {id:'SC09',name:'.NET Runtime',vendor:'Microsoft',version:'9.0',category:'runtime',riskScore:16,deps:['SC02'],vulns:[],lastAudit:'2026-09-01',license:'MIT'},
    {id:'SC10',name:'Go',vendor:'Google',version:'1.23',category:'runtime',riskScore:8,deps:['SC01'],vulns:[],lastAudit:'2026-09-05',license:'BSD'},
    {id:'SC11',name:'Rust',vendor:'Mozilla/Community',version:'1.81',category:'runtime',riskScore:6,deps:['SC01'],vulns:[],lastAudit:'2026-09-07',license:'MIT/Apache'},
    {id:'SC12',name:'Spring Boot',vendor:'VMware/Broadcom',version:'3.3.3',category:'framework',riskScore:20,deps:['SC08'],vulns:['CVE-2024-38809'],lastAudit:'2026-08-25',license:'Apache'},
    {id:'SC13',name:'Django',vendor:'Django Software Foundation',version:'5.1',category:'framework',riskScore:12,deps:['SC07'],vulns:[],lastAudit:'2026-09-01',license:'BSD'},
    {id:'SC14',name:'Express.js',vendor:'OpenJS Foundation',version:'4.19.2',category:'framework',riskScore:15,deps:['SC06'],vulns:[],lastAudit:'2026-08-20',license:'MIT'},
    {id:'SC15',name:'React',vendor:'Meta',version:'19.0',category:'framework',riskScore:10,deps:['SC06'],vulns:[],lastAudit:'2026-09-05',license:'MIT'},
    {id:'SC16',name:'Angular',vendor:'Google',version:'18.2',category:'framework',riskScore:12,deps:['SC06'],vulns:[],lastAudit:'2026-08-30',license:'MIT'},
    {id:'SC17',name:'ASP.NET Core',vendor:'Microsoft',version:'9.0',category:'framework',riskScore:14,deps:['SC09'],vulns:[],lastAudit:'2026-09-01',license:'MIT'},
    {id:'SC18',name:'Next.js',vendor:'Vercel',version:'14.2',category:'framework',riskScore:18,deps:['SC06','SC15'],vulns:['CVE-2024-34351'],lastAudit:'2026-08-28',license:'MIT'},
    {id:'SC19',name:'Flask',vendor:'Pallets',version:'3.0.3',category:'framework',riskScore:14,deps:['SC07'],vulns:[],lastAudit:'2026-08-15',license:'BSD'},
    {id:'SC20',name:'Ruby on Rails',vendor:'Rails Core',version:'7.2',category:'framework',riskScore:16,deps:[],vulns:[],lastAudit:'2026-08-22',license:'MIT'},
    {id:'SC21',name:'OpenSSL',vendor:'OpenSSL Project',version:'3.3.1',category:'library',riskScore:22,deps:[],vulns:[],lastAudit:'2026-09-10',license:'Apache'},
    {id:'SC22',name:'Log4j',vendor:'Apache',version:'2.23.1',category:'library',riskScore:15,deps:['SC08'],vulns:[],lastAudit:'2026-09-08',license:'Apache'},
    {id:'SC23',name:'libcurl',vendor:'curl project',version:'8.9.1',category:'library',riskScore:18,deps:[],vulns:[],lastAudit:'2026-09-01',license:'MIT'},
    {id:'SC24',name:'zlib',vendor:'zlib.net',version:'1.3.1',category:'library',riskScore:10,deps:[],vulns:[],lastAudit:'2026-08-15',license:'zlib'},
    {id:'SC25',name:'libxml2',vendor:'GNOME',version:'2.13.3',category:'library',riskScore:20,deps:[],vulns:['CVE-2024-25062'],lastAudit:'2026-08-20',license:'MIT'},
    {id:'SC26',name:'Bouncy Castle',vendor:'Legion of Bouncy Castle',version:'1.78',category:'library',riskScore:12,deps:['SC08'],vulns:[],lastAudit:'2026-08-25',license:'MIT'},
    {id:'SC27',name:'lodash',vendor:'lodash.com',version:'4.17.21',category:'library',riskScore:8,deps:['SC06'],vulns:[],lastAudit:'2026-07-01',license:'MIT'},
    {id:'SC28',name:'axios',vendor:'axios',version:'1.7.5',category:'library',riskScore:12,deps:['SC06'],vulns:[],lastAudit:'2026-09-01',license:'MIT'},
    {id:'SC29',name:'jsonwebtoken',vendor:'auth0',version:'9.0.2',category:'library',riskScore:15,deps:['SC06'],vulns:[],lastAudit:'2026-08-10',license:'MIT'},
    {id:'SC30',name:'cryptography',vendor:'PyCA',version:'43.0',category:'library',riskScore:14,deps:['SC07','SC21'],vulns:[],lastAudit:'2026-09-05',license:'Apache/BSD'},
    {id:'SC31',name:'gRPC',vendor:'Google/CNCF',version:'1.66',category:'library',riskScore:12,deps:['SC10'],vulns:[],lastAudit:'2026-08-28',license:'Apache'},
    {id:'SC32',name:'protobuf',vendor:'Google',version:'27.3',category:'library',riskScore:10,deps:[],vulns:[],lastAudit:'2026-08-20',license:'BSD'},
    {id:'SC33',name:'numpy',vendor:'NumPy',version:'2.1',category:'library',riskScore:8,deps:['SC07'],vulns:[],lastAudit:'2026-09-01',license:'BSD'},
    {id:'SC34',name:'pandas',vendor:'pandas-dev',version:'2.2.2',category:'library',riskScore:10,deps:['SC07','SC33'],vulns:[],lastAudit:'2026-08-15',license:'BSD'},
    {id:'SC35',name:'TensorFlow',vendor:'Google',version:'2.17',category:'library',riskScore:18,deps:['SC07','SC33'],vulns:[],lastAudit:'2026-08-20',license:'Apache'},
    {id:'SC36',name:'PostgreSQL',vendor:'PostgreSQL Global',version:'17.0',category:'database',riskScore:14,deps:['SC01'],vulns:[],lastAudit:'2026-09-10',license:'PostgreSQL'},
    {id:'SC37',name:'MySQL',vendor:'Oracle',version:'8.4',category:'database',riskScore:18,deps:['SC01'],vulns:['CVE-2024-21060'],lastAudit:'2026-08-25',license:'GPL/Commercial'},
    {id:'SC38',name:'MongoDB',vendor:'MongoDB Inc',version:'7.0.12',category:'database',riskScore:20,deps:['SC01'],vulns:[],lastAudit:'2026-09-01',license:'SSPL'},
    {id:'SC39',name:'Redis',vendor:'Redis Ltd',version:'7.4',category:'database',riskScore:16,deps:['SC01'],vulns:[],lastAudit:'2026-08-28',license:'RSALv2/SSPL'},
    {id:'SC40',name:'Microsoft SQL Server',vendor:'Microsoft',version:'2022 CU14',category:'database',riskScore:22,deps:['SC02'],vulns:['CVE-2024-37334'],lastAudit:'2026-08-15',license:'Commercial'},
    {id:'SC41',name:'Elasticsearch',vendor:'Elastic',version:'8.15',category:'database',riskScore:18,deps:['SC08'],vulns:[],lastAudit:'2026-09-05',license:'Elastic/SSPL'},
    {id:'SC42',name:'Cassandra',vendor:'Apache',version:'5.0',category:'database',riskScore:15,deps:['SC08'],vulns:[],lastAudit:'2026-08-20',license:'Apache'},
    {id:'SC43',name:'InfluxDB',vendor:'InfluxData',version:'2.7.8',category:'database',riskScore:12,deps:['SC10'],vulns:[],lastAudit:'2026-08-22',license:'MIT'},
    {id:'SC44',name:'Oracle Database',vendor:'Oracle',version:'23ai',category:'database',riskScore:28,deps:[],vulns:['CVE-2024-21082'],lastAudit:'2026-07-15',license:'Commercial'},
    {id:'SC45',name:'SQLite',vendor:'D. Richard Hipp',version:'3.46.1',category:'database',riskScore:8,deps:[],vulns:[],lastAudit:'2026-09-01',license:'Public Domain'},
    {id:'SC46',name:'Docker Engine',vendor:'Docker Inc',version:'27.2',category:'container',riskScore:22,deps:['SC01'],vulns:[],lastAudit:'2026-09-05',license:'Apache'},
    {id:'SC47',name:'Kubernetes',vendor:'CNCF',version:'1.31',category:'container',riskScore:25,deps:['SC46','SC10'],vulns:[],lastAudit:'2026-09-08',license:'Apache'},
    {id:'SC48',name:'containerd',vendor:'CNCF',version:'1.7.21',category:'container',riskScore:18,deps:['SC10'],vulns:[],lastAudit:'2026-08-28',license:'Apache'},
    {id:'SC49',name:'Podman',vendor:'Red Hat',version:'5.2',category:'container',riskScore:14,deps:['SC01'],vulns:[],lastAudit:'2026-09-01',license:'Apache'},
    {id:'SC50',name:'Istio',vendor:'Google/IBM',version:'1.23',category:'container',riskScore:20,deps:['SC47','SC10'],vulns:[],lastAudit:'2026-08-20',license:'Apache'},
    {id:'SC51',name:'Helm',vendor:'CNCF',version:'3.16',category:'container',riskScore:15,deps:['SC47'],vulns:[],lastAudit:'2026-08-25',license:'Apache'},
    {id:'SC52',name:'AWS SDK',vendor:'Amazon',version:'3.x',category:'cloud',riskScore:12,deps:[],vulns:[],lastAudit:'2026-09-10',license:'Apache'},
    {id:'SC53',name:'Azure SDK',vendor:'Microsoft',version:'latest',category:'cloud',riskScore:14,deps:[],vulns:[],lastAudit:'2026-09-08',license:'MIT'},
    {id:'SC54',name:'GCP SDK',vendor:'Google',version:'latest',category:'cloud',riskScore:12,deps:[],vulns:[],lastAudit:'2026-09-05',license:'Apache'},
    {id:'SC55',name:'Terraform',vendor:'HashiCorp',version:'1.9.5',category:'cloud',riskScore:18,deps:['SC10'],vulns:[],lastAudit:'2026-09-01',license:'BSL'},
    {id:'SC56',name:'Ansible',vendor:'Red Hat',version:'10.3',category:'cloud',riskScore:15,deps:['SC07'],vulns:[],lastAudit:'2026-08-28',license:'GPL'},
    {id:'SC57',name:'Vault',vendor:'HashiCorp',version:'1.17',category:'cloud',riskScore:20,deps:['SC10'],vulns:[],lastAudit:'2026-08-25',license:'BSL'},
    {id:'SC58',name:'Consul',vendor:'HashiCorp',version:'1.19',category:'cloud',riskScore:16,deps:['SC10'],vulns:[],lastAudit:'2026-08-20',license:'BSL'},
    {id:'SC59',name:'CloudFormation',vendor:'AWS',version:'latest',category:'cloud',riskScore:10,deps:['SC52'],vulns:[],lastAudit:'2026-09-01',license:'AWS TOS'},
    {id:'SC60',name:'Pulumi',vendor:'Pulumi',version:'3.130',category:'cloud',riskScore:14,deps:['SC06','SC10'],vulns:[],lastAudit:'2026-08-15',license:'Apache'},
    {id:'SC61',name:'Cisco IOS XE',vendor:'Cisco',version:'17.12',category:'firmware',riskScore:35,deps:[],vulns:['CVE-2023-20198','CVE-2023-20273'],lastAudit:'2026-08-01',license:'Commercial'},
    {id:'SC62',name:'FortiOS',vendor:'Fortinet',version:'7.4.4',category:'firmware',riskScore:38,deps:[],vulns:['CVE-2024-21762','CVE-2024-23113'],lastAudit:'2026-08-15',license:'Commercial'},
    {id:'SC63',name:'PAN-OS',vendor:'Palo Alto Networks',version:'11.2',category:'firmware',riskScore:32,deps:[],vulns:['CVE-2024-3400'],lastAudit:'2026-09-01',license:'Commercial'},
    {id:'SC64',name:'Junos OS',vendor:'Juniper',version:'24.2R1',category:'firmware',riskScore:22,deps:[],vulns:[],lastAudit:'2026-08-20',license:'Commercial'},
    {id:'SC65',name:'Arista EOS',vendor:'Arista',version:'4.32',category:'firmware',riskScore:15,deps:[],vulns:[],lastAudit:'2026-08-25',license:'Commercial'},
    {id:'SC66',name:'F5 BIG-IP TMOS',vendor:'F5',version:'17.1.1',category:'firmware',riskScore:30,deps:[],vulns:['CVE-2024-21793'],lastAudit:'2026-08-10',license:'Commercial'},
    {id:'SC67',name:'Ivanti Connect Secure',vendor:'Ivanti',version:'22.7R2.1',category:'firmware',riskScore:42,deps:[],vulns:['CVE-2024-21887','CVE-2023-46805'],lastAudit:'2026-07-15',license:'Commercial'},
    {id:'SC68',name:'NetScaler ADC',vendor:'Citrix/Cloud Software',version:'14.1-29.72',category:'firmware',riskScore:35,deps:[],vulns:['CVE-2023-4966'],lastAudit:'2026-08-01',license:'Commercial'},
    {id:'SC69',name:'Siemens S7 PLC Firmware',vendor:'Siemens',version:'4.6',category:'firmware',riskScore:40,deps:[],vulns:['CVE-2024-35303'],lastAudit:'2026-07-01',license:'Commercial'},
    {id:'SC70',name:'Schneider Modicon Firmware',vendor:'Schneider Electric',version:'3.60',category:'firmware',riskScore:45,deps:[],vulns:['CVE-2024-8933','CVE-2024-8935'],lastAudit:'2026-06-15',license:'Commercial'},
    {id:'SC71',name:'Intel Xeon Server Platform',vendor:'Intel',version:'Sapphire Rapids',category:'hardware',riskScore:18,deps:[],vulns:['CVE-2023-23583'],lastAudit:'2026-08-01',license:'Commercial'},
    {id:'SC72',name:'AMD EPYC Server Platform',vendor:'AMD',version:'Genoa',category:'hardware',riskScore:15,deps:[],vulns:[],lastAudit:'2026-08-15',license:'Commercial'},
    {id:'SC73',name:'Dell PowerEdge R760',vendor:'Dell',version:'BIOS 1.8.1',category:'hardware',riskScore:12,deps:['SC71'],vulns:[],lastAudit:'2026-08-20',license:'Commercial'},
    {id:'SC74',name:'HPE ProLiant DL380 Gen11',vendor:'HPE',version:'iLO 6',category:'hardware',riskScore:14,deps:['SC71'],vulns:[],lastAudit:'2026-08-18',license:'Commercial'},
    {id:'SC75',name:'Supermicro X13 Series',vendor:'Supermicro',version:'BMC 1.92',category:'hardware',riskScore:28,deps:['SC71'],vulns:['CVE-2023-40289'],lastAudit:'2026-07-01',license:'Commercial'},
    {id:'SC76',name:'Nvidia A100 GPU',vendor:'Nvidia',version:'535.183',category:'hardware',riskScore:10,deps:[],vulns:[],lastAudit:'2026-08-25',license:'Commercial'},
    {id:'SC77',name:'Mellanox ConnectX-7',vendor:'Nvidia',version:'FW 28.39',category:'hardware',riskScore:12,deps:[],vulns:[],lastAudit:'2026-08-10',license:'Commercial'},
    {id:'SC78',name:'Samsung PM9A3 NVMe',vendor:'Samsung',version:'GDC7602Q',category:'hardware',riskScore:8,deps:[],vulns:[],lastAudit:'2026-08-01',license:'Commercial'},
    {id:'SC79',name:'Broadcom Tomahawk 5',vendor:'Broadcom',version:'SDK 6.5',category:'hardware',riskScore:16,deps:[],vulns:[],lastAudit:'2026-07-15',license:'Commercial'},
    {id:'SC80',name:'Xilinx Alveo U55C',vendor:'AMD/Xilinx',version:'Shell 2.1',category:'hardware',riskScore:14,deps:[],vulns:[],lastAudit:'2026-07-20',license:'Commercial'},
    {id:'SC81',name:'Cisco Catalyst 9300',vendor:'Cisco',version:'IOS XE 17.12',category:'network',riskScore:28,deps:['SC61'],vulns:['CVE-2023-20198'],lastAudit:'2026-08-01',license:'Commercial'},
    {id:'SC82',name:'FortiGate 600F',vendor:'Fortinet',version:'FortiOS 7.4',category:'network',riskScore:30,deps:['SC62'],vulns:['CVE-2024-21762'],lastAudit:'2026-08-10',license:'Commercial'},
    {id:'SC83',name:'Palo Alto PA-5450',vendor:'Palo Alto',version:'PAN-OS 11.2',category:'network',riskScore:25,deps:['SC63'],vulns:['CVE-2024-3400'],lastAudit:'2026-09-01',license:'Commercial'},
    {id:'SC84',name:'Juniper SRX4600',vendor:'Juniper',version:'Junos 24.2',category:'network',riskScore:18,deps:['SC64'],vulns:[],lastAudit:'2026-08-20',license:'Commercial'},
    {id:'SC85',name:'Arista 7280R3',vendor:'Arista',version:'EOS 4.32',category:'network',riskScore:12,deps:['SC65'],vulns:[],lastAudit:'2026-08-25',license:'Commercial'},
    {id:'SC86',name:'F5 BIG-IP i5800',vendor:'F5',version:'TMOS 17.1',category:'network',riskScore:25,deps:['SC66'],vulns:['CVE-2024-21793'],lastAudit:'2026-08-10',license:'Commercial'},
    {id:'SC87',name:'Check Point Quantum 28000',vendor:'Check Point',version:'R81.20',category:'network',riskScore:20,deps:[],vulns:['CVE-2024-24919'],lastAudit:'2026-08-15',license:'Commercial'},
    {id:'SC88',name:'Zscaler Internet Access',vendor:'Zscaler',version:'SaaS',category:'network',riskScore:14,deps:[],vulns:[],lastAudit:'2026-09-05',license:'SaaS'},
    {id:'SC89',name:'CrowdStrike Falcon',vendor:'CrowdStrike',version:'7.x',category:'network',riskScore:16,deps:[],vulns:[],lastAudit:'2026-09-08',license:'SaaS'},
    {id:'SC90',name:'SentinelOne Singularity',vendor:'SentinelOne',version:'24.2',category:'network',riskScore:14,deps:[],vulns:[],lastAudit:'2026-09-01',license:'SaaS'},
    {id:'SC91',name:'Splunk Enterprise',vendor:'Cisco/Splunk',version:'9.3',category:'library',riskScore:18,deps:['SC07'],vulns:[],lastAudit:'2026-08-25',license:'Commercial'},
    {id:'SC92',name:'Apache Kafka',vendor:'Apache/Confluent',version:'3.8',category:'library',riskScore:16,deps:['SC08'],vulns:[],lastAudit:'2026-08-20',license:'Apache'},
    {id:'SC93',name:'RabbitMQ',vendor:'VMware/Broadcom',version:'4.0',category:'library',riskScore:14,deps:['SC11'],vulns:[],lastAudit:'2026-08-28',license:'MPL'},
    {id:'SC94',name:'Nginx',vendor:'F5',version:'1.27.1',category:'library',riskScore:12,deps:['SC01'],vulns:[],lastAudit:'2026-09-01',license:'BSD'},
    {id:'SC95',name:'Apache HTTPD',vendor:'Apache',version:'2.4.62',category:'library',riskScore:15,deps:['SC01'],vulns:[],lastAudit:'2026-08-25',license:'Apache'},
    {id:'SC96',name:'HAProxy',vendor:'HAProxy Technologies',version:'3.0',category:'library',riskScore:10,deps:['SC01'],vulns:[],lastAudit:'2026-08-28',license:'GPL'},
    {id:'SC97',name:'Envoy Proxy',vendor:'CNCF',version:'1.31',category:'library',riskScore:14,deps:['SC47'],vulns:[],lastAudit:'2026-09-05',license:'Apache'},
    {id:'SC98',name:'Grafana',vendor:'Grafana Labs',version:'11.2',category:'library',riskScore:16,deps:['SC10'],vulns:[],lastAudit:'2026-08-20',license:'AGPL'},
    {id:'SC99',name:'Prometheus',vendor:'CNCF',version:'2.54',category:'library',riskScore:10,deps:['SC10'],vulns:[],lastAudit:'2026-09-01',license:'Apache'},
    {id:'SC100',name:'GitLab',vendor:'GitLab Inc',version:'17.3',category:'library',riskScore:22,deps:['SC20','SC36'],vulns:['CVE-2024-6385'],lastAudit:'2026-08-25',license:'MIT/EE'},
    {id:'SC101',name:'Jenkins',vendor:'Jenkins Project',version:'2.472',category:'library',riskScore:25,deps:['SC08'],vulns:['CVE-2024-43044'],lastAudit:'2026-08-15',license:'MIT'},
    {id:'SC102',name:'GitHub Actions',vendor:'Microsoft/GitHub',version:'SaaS',category:'cloud',riskScore:16,deps:[],vulns:[],lastAudit:'2026-09-08',license:'SaaS'},
    {id:'SC103',name:'ArgoCD',vendor:'CNCF',version:'2.12',category:'cloud',riskScore:18,deps:['SC47'],vulns:[],lastAudit:'2026-08-20',license:'Apache'},
    {id:'SC104',name:'Keycloak',vendor:'Red Hat',version:'25.0',category:'library',riskScore:20,deps:['SC08'],vulns:[],lastAudit:'2026-08-28',license:'Apache'},
    {id:'SC105',name:'Okta',vendor:'Okta',version:'SaaS',category:'cloud',riskScore:22,deps:[],vulns:[],lastAudit:'2026-09-05',license:'SaaS'},
    {id:'SC106',name:'Cisco ISE',vendor:'Cisco',version:'3.3',category:'network',riskScore:24,deps:[],vulns:['CVE-2024-20368'],lastAudit:'2026-08-01',license:'Commercial'},
    {id:'SC107',name:'Fortinet FortiManager',vendor:'Fortinet',version:'7.4.3',category:'network',riskScore:28,deps:['SC62'],vulns:['CVE-2024-47575'],lastAudit:'2026-08-15',license:'Commercial'},
    {id:'SC108',name:'Wiz Cloud Security',vendor:'Wiz',version:'SaaS',category:'cloud',riskScore:10,deps:[],vulns:[],lastAudit:'2026-09-10',license:'SaaS'},
    {id:'SC109',name:'Datadog',vendor:'Datadog',version:'SaaS',category:'cloud',riskScore:12,deps:[],vulns:[],lastAudit:'2026-09-08',license:'SaaS'},
    {id:'SC110',name:'Snyk',vendor:'Snyk',version:'SaaS',category:'cloud',riskScore:10,deps:[],vulns:[],lastAudit:'2026-09-05',license:'SaaS'}
  ];

  // ============================================================================
  // GEOPOLITICAL TRIGGERS — 35 events
  // ============================================================================
  var GEO_TRIGGERS = [
    {id:'GT01',region:'Eastern Europe',event:'Russia-NATO border military exercises escalation',probability:72,impactAreas:['energy','government','military','telecom'],relatedAPTs:['APT01','APT02','APT03','APT04','APT30'],escalationRisk:'critical'},
    {id:'GT02',region:'East Asia',event:'Taiwan Strait military confrontation',probability:35,impactAreas:['telecom','financial','government','transport'],relatedAPTs:['APT06','APT07','APT08','APT11','APT12'],escalationRisk:'critical'},
    {id:'GT03',region:'Middle East',event:'Iran nuclear program crisis and sanctions escalation',probability:58,impactAreas:['energy','water','financial'],relatedAPTs:['APT17','APT18','APT19','APT20','APT33'],escalationRisk:'high'},
    {id:'GT04',region:'Korean Peninsula',event:'DPRK provocative missile test over Japan',probability:42,impactAreas:['government','military','financial','transport'],relatedAPTs:['APT13','APT14','APT15','APT16'],escalationRisk:'high'},
    {id:'GT05',region:'Global',event:'International sanctions expansion against Russia',probability:78,impactAreas:['financial','energy','telecom'],relatedAPTs:['APT01','APT02','APT03','APT05','APT30'],escalationRisk:'high'},
    {id:'GT06',region:'Southeast Asia',event:'South China Sea territorial dispute escalation',probability:48,impactAreas:['transport','telecom','government','energy'],relatedAPTs:['APT07','APT10','APT11'],escalationRisk:'medium'},
    {id:'GT07',region:'Global',event:'Major technology export controls imposed',probability:65,impactAreas:['technology','financial','government'],relatedAPTs:['APT06','APT08','APT09','APT11'],escalationRisk:'medium'},
    {id:'GT08',region:'Eastern Europe',event:'Ukraine conflict escalation with cyber component',probability:82,impactAreas:['energy','government','telecom','transport'],relatedAPTs:['APT01','APT03','APT05','APT30'],escalationRisk:'critical'},
    {id:'GT09',region:'Middle East',event:'Israel-Iran direct military confrontation',probability:38,impactAreas:['energy','government','military','telecom'],relatedAPTs:['APT17','APT19','APT21','APT33'],escalationRisk:'critical'},
    {id:'GT10',region:'Global',event:'OPEC production cuts triggering energy crisis',probability:55,impactAreas:['energy','financial','transport'],relatedAPTs:['APT19','APT33'],escalationRisk:'medium'},
    {id:'GT11',region:'North America',event:'US presidential election cyber interference',probability:70,impactAreas:['government','telecom','financial'],relatedAPTs:['APT01','APT02','APT11','APT14'],escalationRisk:'high'},
    {id:'GT12',region:'Europe',event:'EU data sovereignty regulations disrupting cloud services',probability:60,impactAreas:['technology','financial','healthcare'],relatedAPTs:[],escalationRisk:'low'},
    {id:'GT13',region:'Global',event:'Submarine cable sabotage in critical chokepoint',probability:25,impactAreas:['telecom','financial','government'],relatedAPTs:['APT03','APT11'],escalationRisk:'high'},
    {id:'GT14',region:'Africa',event:'Sahel region instability affecting rare earth supply chains',probability:62,impactAreas:['technology','energy','military'],relatedAPTs:['APT03','APT10'],escalationRisk:'medium'},
    {id:'GT15',region:'South Asia',event:'India-Pakistan border tensions escalation',probability:30,impactAreas:['government','military','telecom'],relatedAPTs:['APT31x','APT34x'],escalationRisk:'high'},
    {id:'GT16',region:'Global',event:'Major cryptocurrency market collapse',probability:40,impactAreas:['financial'],relatedAPTs:['APT13'],escalationRisk:'low'},
    {id:'GT17',region:'Arctic',event:'Arctic resource competition between NATO and Russia',probability:35,impactAreas:['energy','military','government'],relatedAPTs:['APT01','APT04'],escalationRisk:'medium'},
    {id:'GT18',region:'Global',event:'Pandemic resurgence triggering healthcare cyber attacks',probability:30,impactAreas:['healthcare','financial','government'],relatedAPTs:['APT06','APT02'],escalationRisk:'medium'},
    {id:'GT19',region:'Central Asia',event:'China Belt and Road digital infrastructure disputes',probability:45,impactAreas:['telecom','financial','government'],relatedAPTs:['APT10','APT11'],escalationRisk:'low'},
    {id:'GT20',region:'Latin America',event:'Cartel cyber operations targeting government institutions',probability:55,impactAreas:['government','financial','telecom'],relatedAPTs:[],escalationRisk:'medium'},
    {id:'GT21',region:'Global',event:'AI-generated deepfake crisis targeting world leaders',probability:50,impactAreas:['government','financial','media'],relatedAPTs:['APT01','APT11'],escalationRisk:'high'},
    {id:'GT22',region:'Europe',event:'NATO member state invokes Article 5 for cyber attack',probability:15,impactAreas:['government','military','all_sectors'],relatedAPTs:['APT03'],escalationRisk:'critical'},
    {id:'GT23',region:'East Asia',event:'North Korea diplomatic collapse',probability:28,impactAreas:['military','government','financial'],relatedAPTs:['APT13','APT14','APT15','APT16'],escalationRisk:'high'},
    {id:'GT24',region:'Global',event:'Critical semiconductor shortage due to geopolitical tensions',probability:45,impactAreas:['technology','military','healthcare','transport'],relatedAPTs:['APT06','APT09'],escalationRisk:'medium'},
    {id:'GT25',region:'Middle East',event:'Houthi attacks on Red Sea shipping escalation',probability:68,impactAreas:['transport','energy','financial'],relatedAPTs:['APT17','APT18'],escalationRisk:'medium'},
    {id:'GT26',region:'Global',event:'International cyber treaty negotiations collapse',probability:55,impactAreas:['government','all_sectors'],relatedAPTs:[],escalationRisk:'medium'},
    {id:'GT27',region:'East Asia',event:'Japan military modernization triggering regional cyber espionage',probability:60,impactAreas:['government','military','technology'],relatedAPTs:['APT06','APT07','APT09','APT13'],escalationRisk:'medium'},
    {id:'GT28',region:'Eastern Europe',event:'Russian gas pipeline disruption as geopolitical leverage',probability:50,impactAreas:['energy','financial','government'],relatedAPTs:['APT03'],escalationRisk:'high'},
    {id:'GT29',region:'Global',event:'Space debris incident affecting satellite communications',probability:10,impactAreas:['telecom','military','transport','government'],relatedAPTs:[],escalationRisk:'medium'},
    {id:'GT30',region:'North America',event:'US-Canada trade dispute affecting digital services',probability:25,impactAreas:['financial','technology'],relatedAPTs:[],escalationRisk:'low'},
    {id:'GT31',region:'Global',event:'Quantum computing breakthrough announced by adversary',probability:8,impactAreas:['government','military','financial','all_sectors'],relatedAPTs:['APT11','APT22'],escalationRisk:'critical'},
    {id:'GT32',region:'Southeast Asia',event:'ASEAN cyber cooperation framework deployment',probability:70,impactAreas:['government','telecom'],relatedAPTs:[],escalationRisk:'low'},
    {id:'GT33',region:'Africa',event:'Ethiopian dam dispute triggering regional cyber operations',probability:35,impactAreas:['water','energy','government'],relatedAPTs:[],escalationRisk:'medium'},
    {id:'GT34',region:'Global',event:'Major cloud provider outage revealing concentration risk',probability:40,impactAreas:['all_sectors'],relatedAPTs:[],escalationRisk:'low'},
    {id:'GT35',region:'Eastern Europe',event:'Belarus political crisis with cyber dimension',probability:45,impactAreas:['government','telecom','energy'],relatedAPTs:['APT01','APT05','APT30'],escalationRisk:'medium'}
  ];

  // ============================================================================
  // ESCALATION LEVELS — Command Authority
  // ============================================================================
  var ESCALATION_LEVELS = [
    {level:1,name:'ROUTINE',description:'Standard cybersecurity operations within existing authorities',authority:'SOC Manager / CISO',requiredApproval:'Shift Lead',examples:['Firewall rule changes','Vulnerability scanning','Patch deployment','User account lockout','Malware quarantine']},
    {level:2,name:'ELEVATED',description:'Active incident response requiring cross-team coordination',authority:'CISO / CTO',requiredApproval:'CISO with CTO notification',examples:['Network segment isolation','Emergency patching','Threat hunting operations','Incident response team activation','External DFIR engagement']},
    {level:3,name:'SIGNIFICANT',description:'Major incident with business impact requiring executive involvement',authority:'CIO / CEO',requiredApproval:'C-Suite authorization',examples:['Business system shutdown','Public disclosure decision','Law enforcement engagement','Ransom payment deliberation','Regulatory notification']},
    {level:4,name:'CRITICAL',description:'National security implications requiring government coordination',authority:'National Cyber Director / NSC',requiredApproval:'Interagency coordination',examples:['Critical infrastructure isolation','National-level threat response','Intelligence community coordination','Allied nation notification','Offensive cyber consideration']},
    {level:5,name:'MAXIMUM',description:'Strategic-level cyber operations with kinetic equivalence',authority:'President / National Command Authority',requiredApproval:'Presidential authorization',examples:['Offensive cyber operations','Proportional response authorization','Nuclear C2 protection','Strategic deterrence actions','International crisis management']}
  ];

  // ============================================================================
  // CSS STYLES
  // ============================================================================
  var PM_CSS = '<style>' +
    '*, *::before, *::after { box-sizing: border-box; }' +
    '.pm-wrap { background: #0a0e17; color: #c8d6e5; font-family: "Courier New", "Lucida Console", monospace; min-height: 100vh; padding: 0; position: relative; overflow-x: hidden; }' +
    '.pm-header { background: #0d1117; border-bottom: 2px solid #cc0000; padding: 16px 20px; position: relative; overflow: hidden; }' +
    '.pm-class-banner { background: #cc0000; color: #fff; text-align: center; font-size: 13px; font-weight: bold; letter-spacing: 4px; padding: 4px 0; text-transform: uppercase; }' +
    '.pm-scanline { display: none; }' +
    '.pm-title { font-size: 22px; font-weight: bold; color: #00ff88; text-transform: uppercase; letter-spacing: 3px; margin: 8px 0 4px 0; text-shadow: 0 0 10px rgba(0,255,136,0.5); }' +
    '.pm-subtitle { font-size: 11px; color: #667788; letter-spacing: 2px; text-transform: uppercase; line-height: 1.6; word-break: break-word; }' +
    '.pm-tabs { display: flex; flex-wrap: wrap; gap: 2px; background: #0d1117; padding: 6px 10px; border-bottom: 1px solid #1a2332; }' +
    '.pm-tab { background: #111820; color: #556677; border: 1px solid #1a2332; padding: 6px 12px; font-size: 10px; font-family: "Courier New", monospace; text-transform: uppercase; letter-spacing: 1px; cursor: pointer; transition: all 0.2s; white-space: nowrap; }' +
    '.pm-tab:hover { background: #1a2535; color: #88aacc; border-color: #2a3a4a; }' +
    '.pm-tab.active { background: #0d2137; color: #00ff88; border-color: #00ff88; box-shadow: 0 0 8px rgba(0,255,136,0.2); }' +
    '.pm-panel { background: #0d1117; border: 1px solid #1e2a3a; border-radius: 6px; margin-bottom: 16px; overflow: hidden; padding: 0; }' +
    '.pm-panel-hdr { background: #111820; padding: 10px 16px; font-size: 11px; color: #00ff88; text-transform: uppercase; letter-spacing: 2px; font-weight: bold; border-bottom: 1px solid #1a2a3a; display: flex; align-items: center; justify-content: space-between; }' +
    '.pm-grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }' +
    '.pm-grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; }' +
    '.pm-grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }' +
    '.pm-grid-5 { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }' +
    '.pm-card { background: #0d1117; border: 1px solid #1e2a3a; border-radius: 6px; padding: 16px; position: relative; }' +
    '.pm-card:hover { border-color: rgba(0,255,136,0.25); box-shadow: 0 8px 32px rgba(0,0,0,0.5); transform: translateY(-1px); }' +
    '.pm-card-header { font-size: 11px; color: #00ff88; text-transform: uppercase; letter-spacing: 2px; padding: 0 0 8px; border-left: 3px solid #00ff88; padding-left: 10px; font-weight: bold; }' +
    '.pm-card-body { padding: 0; }' +
    '.pm-domain-row { display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; border-bottom: 1px solid #111820; border-left: 3px solid transparent; }' +
    '.pm-domain-row:hover { background: rgba(0,255,136,0.03); border-left-color: rgba(0,255,136,0.3); }' +
    '.pm-domain-name { font-size: 12px; font-weight: bold; color: #c8d6e5; text-transform: uppercase; letter-spacing: 1px; }' +
    '.pm-domain-status { font-size: 11px; font-weight: bold; }' +
    '.pm-mission-row { padding: 12px 16px; border-bottom: 1px solid #111820; }' +
    '.pm-mission-row:hover { background: rgba(0,255,136,0.03); }' +
    '.pm-mission-top { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 6px; flex-wrap: wrap; }' +
    '.pm-mission-name { font-size: 13px; font-weight: bold; color: #c8d6e5; letter-spacing: 1px; text-transform: uppercase; }' +
    '.pm-mission-type { font-size: 10px; color: #667788; text-transform: uppercase; }' +
    '.pm-mission-status { font-size: 9px; font-weight: bold; padding: 3px 10px; border-radius: 3px; text-transform: uppercase; box-shadow: 0 2px 6px rgba(0,0,0,0.3); }' +
    '.pm-mission-progress { width: 100%; height: 6px; background: #111820; border-radius: 3px; overflow: hidden; margin-top: 6px; }' +
    '.pm-mission-progress-fill { height: 100%; border-radius: 3px; background: linear-gradient(90deg, #00ff88, #00cc66); box-shadow: 0 0 8px rgba(0,255,136,0.3); }' +
    '.pm-mission-pct { font-size: 10px; color: #667788; font-family: "Courier New", monospace; margin-top: 4px; }' +
    '.pm-card-title { font-size: 11px; color: #00ff88; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 10px; font-weight: bold; }' +
    '.pm-card-glow { box-shadow: 0 0 15px rgba(0,255,136,0.08); }' +
    '.pm-gauge { width: 180px; height: 180px; margin: 0 auto; position: relative; }' +
    '.pm-gauge canvas { width: 100%; height: 100%; }' +
    '.pm-gauge-label { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; }' +
    '.pm-gauge-value { font-size: 42px; font-weight: bold; line-height: 1; }' +
    '.pm-gauge-text { font-size: 10px; text-transform: uppercase; letter-spacing: 2px; color: #667788; margin-top: 4px; }' +
    '.pm-threat-map { width: 100%; height: 350px; background: #080c14; border: 1px solid #1a2332; border-radius: 4px; position: relative; }' +
    '.pm-threat-map canvas { width: 100%; height: 100%; }' +
    '.pm-alert-feed { max-height: 300px; overflow-y: auto; border: 1px solid #1a2332; background: #080c14; border-radius: 4px; }' +
    '.pm-alert-item { padding: 8px 14px; border-bottom: 1px solid #111820; font-size: 12px; display: flex; align-items: center; gap: 10px; }' +
    '.pm-alert-item:last-child { border-bottom: none; }' +
    '.pm-alert-time { color: #445566; font-size: 10px; font-family: "Courier New", monospace; min-width: 65px; flex-shrink: 0; }' +
    '.pm-alert-sev { font-size: 9px; font-weight: bold; padding: 3px 8px; border-radius: 3px; text-transform: uppercase; letter-spacing: 1px; min-width: 70px; text-align: center; flex-shrink: 0; box-shadow: 0 2px 6px rgba(0,0,0,0.3); }' +
    '.pm-alert-id { font-size: 10px; color: #556677; font-family: "Courier New", monospace; min-width: 90px; flex-shrink: 0; }' +
    '.pm-alert-msg { flex: 1; color: #aabbcc; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }' +
    '.pm-alert-critical { border-left: 3px solid #ff0040; }' +
    '.pm-alert-high { border-left: 3px solid #ff6600; }' +
    '.pm-alert-medium { border-left: 3px solid #ffaa00; }' +
    '.pm-alert-low { border-left: 3px solid #00aaff; }' +
    '.pm-alert-info { border-left: 3px solid #00ff88; }' +
    '.pm-status-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 6px; flex-shrink: 0; }' +
    '.pm-dot-green { background: #00ff88; box-shadow: 0 0 6px rgba(0,255,136,0.6); animation: pm-pulse 2s ease-in-out infinite; }' +
    '.pm-dot-yellow { background: #ffaa00; box-shadow: 0 0 6px rgba(255,170,0,0.6); animation: pm-pulse 1.5s ease-in-out infinite; }' +
    '.pm-dot-red { background: #ff0040; box-shadow: 0 0 6px rgba(255,0,64,0.6); animation: pm-pulse 1s ease-in-out infinite; }' +
    '.pm-dot-blue { background: #00aaff; box-shadow: 0 0 6px rgba(0,170,255,0.6); }' +
    '.pm-dot-gray { background: #445566; }' +
    '.pm-badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 9px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; }' +
    '.pm-badge-critical { background: #330010; color: #ff0040; border: 1px solid #660020; }' +
    '.pm-badge-high { background: #331a00; color: #ff6600; border: 1px solid #663300; }' +
    '.pm-badge-medium { background: #332a00; color: #ffaa00; border: 1px solid #665500; }' +
    '.pm-badge-low { background: #002233; color: #00aaff; border: 1px solid #004466; }' +
    '.pm-badge-info { background: #003322; color: #00ff88; border: 1px solid #006644; }' +
    '.pm-badge-ts { background: #440000; color: #ff4444; border: 1px solid #880000; }' +
    '.pm-badge-secret { background: #442200; color: #ff8800; border: 1px solid #884400; }' +
    '.pm-badge-conf { background: #003344; color: #0088cc; border: 1px solid #006688; }' +
    '.pm-badge-unclass { background: #002200; color: #00aa00; border: 1px solid #004400; }' +
    '.pm-btn { background: #0d2a1a; color: #00ff88; border: 1px solid #00aa55; padding: 6px 14px; font-family: "Courier New", monospace; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; cursor: pointer; transition: all 0.2s; }' +
    '.pm-btn:hover { background: #1a4030; box-shadow: 0 0 10px rgba(0,255,136,0.2); }' +
    '.pm-btn:active { background: #0a2015; }' +
    '.pm-btn-danger { background: #2a0d0d; color: #ff4444; border-color: #aa0000; }' +
    '.pm-btn-danger:hover { background: #401515; box-shadow: 0 0 10px rgba(255,0,0,0.2); }' +
    '.pm-btn-warn { background: #2a1a0d; color: #ffaa00; border-color: #aa6600; }' +
    '.pm-btn-warn:hover { background: #403020; box-shadow: 0 0 10px rgba(255,170,0,0.2); }' +
    '.pm-btn-blue { background: #0d1a2a; color: #00aaff; border-color: #0066aa; }' +
    '.pm-btn-blue:hover { background: #152a40; box-shadow: 0 0 10px rgba(0,170,255,0.2); }' +
    '.pm-btn-sm { padding: 3px 8px; font-size: 9px; }' +
    '.pm-table { width: 100%; border-collapse: collapse; font-size: 12px; }' +
    '.pm-table th { background: #111820; color: #00ff88; text-transform: uppercase; font-size: 10px; letter-spacing: 1px; padding: 8px 10px; text-align: left; border-bottom: 2px solid #1a2332; font-weight: normal; }' +
    '.pm-table td { padding: 6px 10px; border-bottom: 1px solid #111820; vertical-align: top; }' +
    '.pm-table tr:hover td { background: #0d1520; }' +
    '.pm-table-wrap { overflow-x: auto; border: 1px solid #1a2332; border-radius: 4px; }' +
    '.pm-input { background: #080c14; color: #c8d6e5; border: 1px solid #1a2332; padding: 6px 10px; font-family: "Courier New", monospace; font-size: 12px; width: 100%; }' +
    '.pm-input:focus { border-color: #00aa55; outline: none; box-shadow: 0 0 5px rgba(0,255,136,0.15); }' +
    '.pm-select { background: #080c14; color: #c8d6e5; border: 1px solid #1a2332; padding: 6px 10px; font-family: "Courier New", monospace; font-size: 12px; }' +
    '.pm-select:focus { border-color: #00aa55; outline: none; }' +
    '.pm-modal { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.85); z-index: 1000; display: flex; align-items: center; justify-content: center; }' +
    '.pm-modal-content { background: #0d1117; border: 1px solid #1a2332; border-radius: 6px; padding: 24px; max-width: 700px; width: 90%; max-height: 80vh; overflow-y: auto; box-shadow: 0 0 40px rgba(0,0,0,0.8); }' +
    '.pm-modal-title { font-size: 16px; color: #00ff88; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid #1a2332; }' +
    '.pm-timeline { position: relative; padding-left: 24px; }' +
    '.pm-timeline::before { content: ""; position: absolute; left: 8px; top: 0; bottom: 0; width: 2px; background: #1a2332; }' +
    '.pm-timeline-item { position: relative; margin-bottom: 16px; padding: 8px 12px; background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; }' +
    '.pm-timeline-item::before { content: ""; position: absolute; left: -20px; top: 12px; width: 10px; height: 10px; border-radius: 50%; background: #00ff88; border: 2px solid #0a0e17; }' +
    '.pm-timeline-time { font-size: 10px; color: #445566; text-transform: uppercase; }' +
    '.pm-timeline-red::before { background: #ff0040; }' +
    '.pm-timeline-blue::before { background: #00aaff; }' +
    '.pm-timeline-white::before { background: #ffffff; }' +
    '.pm-sector-card { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 12px; text-align: center; }' +
    '.pm-sector-card:hover { border-color: #2a3a4a; transform: translateY(-2px); transition: all 0.2s; }' +
    '.pm-sector-icon { font-size: 28px; margin-bottom: 6px; }' +
    '.pm-sector-name { font-size: 10px; text-transform: uppercase; letter-spacing: 2px; color: #00ff88; margin-bottom: 4px; }' +
    '.pm-sector-count { font-size: 20px; font-weight: bold; color: #fff; }' +
    '.pm-node { display: inline-flex; align-items: center; gap: 4px; background: #111820; border: 1px solid #1a2332; border-radius: 3px; padding: 3px 8px; font-size: 10px; margin: 2px; }' +
    '.pm-node-crit { border-color: #ff0040; }' +
    '.pm-node-warn { border-color: #ffaa00; }' +
    '.pm-node-ok { border-color: #00ff88; }' +
    '.pm-progress { background: #111820; border-radius: 3px; height: 8px; overflow: hidden; }' +
    '.pm-progress-bar { height: 100%; border-radius: 3px; transition: width 0.5s; }' +
    '.pm-progress-green { background: linear-gradient(90deg, #00aa55, #00ff88); }' +
    '.pm-progress-yellow { background: linear-gradient(90deg, #aa6600, #ffaa00); }' +
    '.pm-progress-red { background: linear-gradient(90deg, #aa0020, #ff0040); }' +
    '.pm-progress-blue { background: linear-gradient(90deg, #0055aa, #00aaff); }' +
    '.pm-sparkline { display: inline-block; vertical-align: middle; }' +
    '.pm-sparkline canvas { height: 24px; width: 80px; }' +
    '.pm-clock { font-size: 12px; color: #667788; }' +
    '.pm-clock-time { font-size: 16px; color: #00ff88; font-weight: bold; }' +
    '.pm-clock-label { font-size: 9px; text-transform: uppercase; letter-spacing: 1px; color: #445566; }' +
    '.pm-defcon-1 { color: #ffffff; text-shadow: 0 0 10px rgba(255,255,255,0.8); }' +
    '.pm-defcon-2 { color: #ff0040; text-shadow: 0 0 10px rgba(255,0,64,0.8); }' +
    '.pm-defcon-3 { color: #ffaa00; text-shadow: 0 0 10px rgba(255,170,0,0.8); }' +
    '.pm-defcon-4 { color: #00ff88; text-shadow: 0 0 10px rgba(0,255,136,0.8); }' +
    '.pm-defcon-5 { color: #00aaff; text-shadow: 0 0 10px rgba(0,170,255,0.8); }' +
    '.pm-defcon-btns { display: flex; gap: 6px; margin: 12px 0; justify-content: center; }' +
    '.pm-defcon-btn { width: 42px; height: 42px; border: 2px solid #2a3a4a; border-radius: 4px; background: linear-gradient(180deg, #1a2030 0%, #0d1117 100%); color: #667788; font-family: "Courier New", monospace; font-size: 15px; font-weight: bold; cursor: pointer; transition: all 0.25s ease; box-shadow: 0 3px 10px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.06); }' +
    '.pm-defcon-btn:hover { border-color: #00ff88; color: #00ff88; transform: translateY(-2px); box-shadow: 0 4px 20px rgba(0,255,136,0.25); }' +
    '.pm-defcon-btn-active { border-color: #ff6600; color: #fff; background: linear-gradient(180deg, #ff6600 0%, #cc4400 100%); box-shadow: 0 0 24px rgba(255,102,0,0.5), 0 6px 16px rgba(255,102,0,0.35), inset 0 1px 0 rgba(255,255,255,0.25); text-shadow: 0 0 10px rgba(255,255,255,0.6); }' +
    '.pm-cascade { position: relative; background: #080c14; border: 1px solid #1a2332; border-radius: 4px; min-height: 300px; }' +
    '.pm-cascade canvas { width: 100%; height: 100%; }' +
    '.pm-tooltip { position: absolute; background: #1a2332; color: #c8d6e5; padding: 6px 10px; border-radius: 3px; font-size: 11px; pointer-events: none; z-index: 100; box-shadow: 0 4px 12px rgba(0,0,0,0.5); white-space: nowrap; }' +
    '.pm-search { background: #080c14; color: #c8d6e5; border: 1px solid #1a2332; padding: 8px 12px; font-family: "Courier New", monospace; font-size: 12px; width: 100%; margin-bottom: 12px; }' +
    '.pm-search:focus { border-color: #00aa55; outline: none; }' +
    '.pm-label { font-size: 9px; text-transform: uppercase; letter-spacing: 2px; color: #556677; margin-bottom: 4px; }' +
    '.pm-metric { font-size: 28px; font-weight: bold; color: #fff; line-height: 1.2; }' +
    '.pm-metric-sm { font-size: 18px; }' +
    '.pm-chart { background: #080c14; border: 1px solid #1a2332; border-radius: 4px; padding: 12px; min-height: 200px; }' +
    '.pm-separator { border: none; border-top: 1px solid #1a2332; margin: 16px 0; }' +
    '.pm-kpi { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 14px; text-align: center; }' +
    '.pm-kpi-value { font-size: 32px; font-weight: bold; color: #00ff88; line-height: 1; }' +
    '.pm-kpi-label { font-size: 9px; text-transform: uppercase; letter-spacing: 2px; color: #556677; margin-top: 6px; }' +
    '.pm-flex { display: flex; gap: 12px; align-items: center; }' +
    '.pm-flex-wrap { display: flex; flex-wrap: wrap; gap: 8px; }' +
    '.pm-flex-between { display: flex; justify-content: space-between; align-items: center; }' +
    '.pm-flex-col { display: flex; flex-direction: column; gap: 8px; }' +
    '.pm-mb-8 { margin-bottom: 8px; }' +
    '.pm-mb-12 { margin-bottom: 12px; }' +
    '.pm-mb-16 { margin-bottom: 16px; }' +
    '.pm-mt-12 { margin-top: 12px; }' +
    '.pm-mt-16 { margin-top: 16px; }' +
    '.pm-text-green { color: #00ff88; }' +
    '.pm-text-red { color: #ff0040; }' +
    '.pm-text-yellow { color: #ffaa00; }' +
    '.pm-text-blue { color: #00aaff; }' +
    '.pm-text-white { color: #ffffff; }' +
    '.pm-text-muted { color: #556677; }' +
    '.pm-text-sm { font-size: 11px; }' +
    '.pm-text-xs { font-size: 10px; }' +
    '.pm-text-center { text-align: center; }' +
    '.pm-text-right { text-align: right; }' +
    '.pm-text-bold { font-weight: bold; }' +
    '.pm-tag { display: inline-block; padding: 1px 6px; background: #111820; border: 1px solid #1a2332; border-radius: 2px; font-size: 9px; color: #667788; margin: 1px; }' +
    '.pm-ladder { display: flex; flex-direction: column; gap: 0; }' +
    '.pm-ladder-step { padding: 14px 18px; border: 1px solid #1a2332; border-bottom: none; position: relative; }' +
    '.pm-ladder-step:last-child { border-bottom: 1px solid #1a2332; }' +
    '.pm-ladder-step.active { background: #0d2137; border-color: #00ff88; }' +
    '.pm-ladder-step .pm-ladder-num { font-size: 24px; font-weight: bold; color: #00ff88; margin-right: 12px; }' +
    '.pm-roe-item { padding: 8px 12px; display: flex; align-items: center; gap: 8px; border-bottom: 1px solid #111820; }' +
    '.pm-roe-pass { color: #00ff88; }' +
    '.pm-roe-fail { color: #ff0040; }' +
    '.pm-score-bar { display: flex; height: 28px; border-radius: 3px; overflow: hidden; }' +
    '.pm-score-red { background: #aa0020; }' +
    '.pm-score-blue { background: #0055aa; }' +
    '.pm-section-title { font-size: 13px; color: #00ff88; text-transform: uppercase; letter-spacing: 2px; padding-bottom: 6px; border-bottom: 1px solid #1a2332; margin-bottom: 12px; }' +
    '.pm-scroll-y { overflow-y: auto; max-height: 400px; }' +
    '.pm-evidence-item { padding: 8px 12px; background: #111820; border: 1px solid #1a2332; border-radius: 3px; margin-bottom: 6px; font-size: 11px; }' +
    '.pm-form-group { margin-bottom: 12px; }' +
    '.pm-form-label { font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: #556677; margin-bottom: 4px; display: block; }' +
    '.pm-textarea { background: #080c14; color: #c8d6e5; border: 1px solid #1a2332; padding: 8px 10px; font-family: "Courier New", monospace; font-size: 12px; width: 100%; min-height: 80px; resize: vertical; }' +
    '.pm-textarea:focus { border-color: #00aa55; outline: none; }' +
    '.pm-dep-graph { background: #080c14; border: 1px solid #1a2332; border-radius: 4px; padding: 12px; min-height: 250px; overflow: auto; }' +
    '.pm-dep-node { display: inline-block; padding: 4px 10px; background: #111820; border: 1px solid #1a2332; border-radius: 3px; font-size: 10px; margin: 3px; cursor: pointer; }' +
    '.pm-dep-node:hover { border-color: #00ff88; color: #00ff88; }' +
    '.pm-dep-node.selected { background: #0d2137; border-color: #00ff88; color: #00ff88; }' +
    '.pm-dep-node.failed { background: #2a0d0d; border-color: #ff0040; color: #ff0040; }' +
    '.pm-dep-node.degraded { background: #2a1a0d; border-color: #ffaa00; color: #ffaa00; }' +
    '.pm-tab-icon { margin-right: 4px; }' +
    '.pm-no-data { text-align: center; padding: 40px; color: #334455; font-size: 13px; text-transform: uppercase; letter-spacing: 2px; }' +
    '.pm-pulse-ring { animation: pm-ring-pulse 2s ease-in-out infinite; }' +
    '.pm-blink { animation: pm-blink 1s ease-in-out infinite; }' +
    '@keyframes pm-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }' +
    '@keyframes pm-scanmove { 0% { transform: translateY(0); } 100% { transform: translateY(4px); } }' +
    '@keyframes pm-blink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }' +
    '@keyframes pm-slideIn { from { transform: translateY(-10px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }' +
    '@keyframes pm-fadeIn { from { opacity: 0; } to { opacity: 1; } }' +
    '@keyframes pm-ring-pulse { 0% { box-shadow: 0 0 0 0 rgba(0,255,136,0.4); } 70% { box-shadow: 0 0 0 15px rgba(0,255,136,0); } 100% { box-shadow: 0 0 0 0 rgba(0,255,136,0); } }' +
    '@media (max-width: 1200px) { .pm-grid-4 { grid-template-columns: repeat(2, 1fr); } .pm-grid-3 { grid-template-columns: 1fr 1fr; } .pm-grid-5 { grid-template-columns: repeat(3, 1fr); } }' +
    '@media (max-width: 900px) { .pm-grid-2, .pm-grid-3, .pm-grid-4, .pm-grid-5 { grid-template-columns: 1fr; } .pm-tabs { flex-wrap: wrap; } .pm-tab { font-size: 9px; padding: 4px 8px; } .pm-gauge { width: 140px; height: 140px; } }' +
    '@media (max-width: 600px) { .pm-panel { padding: 8px; } .pm-metric { font-size: 22px; } .pm-kpi-value { font-size: 24px; } }' +
    '.pm-wrap ::-webkit-scrollbar { width: 6px; height: 6px; }' +
    '.pm-wrap ::-webkit-scrollbar-track { background: #0a0e17; }' +
    '.pm-wrap ::-webkit-scrollbar-thumb { background: #1a2332; border-radius: 3px; }' +
    '.pm-wrap ::-webkit-scrollbar-thumb:hover { background: #2a3a4a; }' +
    '.pm-cc-top { display: grid; grid-template-columns: 1fr 2fr; gap: 16px; margin-bottom: 16px; }' +
  '.pm-cc-mid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }' +
  '.pm-cc-bot { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin-bottom: 16px; }' +
  '@media (max-width: 900px) { .pm-cc-top, .pm-cc-mid, .pm-cc-bot { grid-template-columns: 1fr; } }' +
  '.pm-predict-card { background: #0d1117; border: 1px solid #1a2a3a; border-radius: 8px; padding: 16px; position: relative; }' +
  '.pm-predict-card:hover { border-color: rgba(0,255,136,0.25); }' +
  '.pm-alert-row { padding: 8px 14px; border-bottom: 1px solid #111820; font-size: 12px; display: flex; align-items: center; gap: 10px; transition: background 0.15s; }' +
  '.pm-alert-row:hover { background: rgba(0,255,136,0.03); }' +
  '.pm-alert-row:last-child { border-bottom: none; }' +
  '.pm-classification-banner { background: #cc0000; color: #fff; text-align: center; font-size: 11px; font-weight: bold; letter-spacing: 4px; padding: 6px 0; text-transform: uppercase; }' +
  '.pm-progress-bar { width: 100%; height: 6px; background: #111820; border-radius: 3px; overflow: hidden; margin-top: 6px; }' +
  // Pro theme overrides
  '[data-style=pro] .pm-wrap { background: #fff !important; color: #18181b !important; font-family: ui-sans-serif,system-ui,-apple-system,sans-serif !important; }' +
  '[data-style=pro] .pm-class-banner { background: #18181b !important; font-size: 11px !important; letter-spacing: .08em !important; }' +
  '[data-style=pro] .pm-classification-banner { background: #18181b !important; font-size: 10px !important; letter-spacing: .08em !important; }' +
  '[data-style=pro] .pm-header { background: #fff !important; border-bottom: 1px solid #e2e8f0 !important; padding: 16px 20px !important; }' +
  '[data-style=pro] .pm-header-content { background: transparent !important; border-bottom: none !important; padding: 0 !important; }' +
  '[data-style=pro] .pm-title { color: #0f172a !important; text-shadow: none !important; font-size: 20px !important; letter-spacing: .02em !important; }' +
  '[data-style=pro] .pm-subtitle { color: #64748b !important; font-size: 10px !important; letter-spacing: .04em !important; }' +
  '[data-style=pro] .pm-header-meta { color: #94a3b8 !important; }' +
  '[data-style=pro] .pm-version { color: #94a3b8 !important; }' +
  '[data-style=pro] .pm-operator { color: #64748b !important; }' +
  '[data-style=pro] .pm-session { color: #94a3b8 !important; }' +
  '[data-style=pro] .pm-tabs { background: #f9fafb !important; border-bottom: 1px solid #e5e5e5 !important; }' +
  '[data-style=pro] .pm-tab { background: #fff !important; color: #71717a !important; border: 1px solid #e5e5e5 !important; border-radius: 4px !important; font-family: ui-sans-serif,system-ui,sans-serif !important; }' +
  '[data-style=pro] .pm-tab:hover { background: #f4f4f5 !important; color: #18181b !important; }' +
  '[data-style=pro] .pm-tab.active { background: #18181b !important; color: #fff !important; border-color: #18181b !important; box-shadow: none !important; }' +
  '[data-style=pro] .pm-panel { background: #fff !important; border: 1px solid #e5e5e5 !important; }' +
  '[data-style=pro] .pm-panel-hdr { background: #f9fafb !important; border-bottom: 1px solid #e5e5e5 !important; color: #18181b !important; letter-spacing: .05em !important; }' +
  '[data-style=pro] .pm-table { color: #18181b !important; }' +
  '[data-style=pro] .pm-table th { background: #f9fafb !important; color: #18181b !important; border-bottom: 1px solid #e5e5e5 !important; }' +
  '[data-style=pro] .pm-table td { border-bottom: 1px solid #f4f4f5 !important; color: #3f3f46 !important; }' +
  '[data-style=pro] .pm-table tr:hover td { background: #f9fafb !important; }' +
  '[data-style=pro] .pm-metric { background: #f9fafb !important; border: 1px solid #e5e5e5 !important; border-radius: 8px !important; }' +
  '[data-style=pro] .pm-metric-value { color: #18181b !important; text-shadow: none !important; }' +
  '[data-style=pro] .pm-metric-label { color: #71717a !important; }' +
  '[data-style=pro] .pm-section-title { color: #18181b !important; text-shadow: none !important; }' +
  '[data-style=pro] .pm-section-subtitle { color: #71717a !important; }' +
  '[data-style=pro] .pm-badge { background: #f4f4f5 !important; border: 1px solid #e5e5e5 !important; color: #18181b !important; }' +
  '[data-style=pro] .pm-badge-critical { background: #fef2f2 !important; color: #dc2626 !important; border-color: #fecaca !important; }' +
  '[data-style=pro] .pm-badge-high { background: #fff7ed !important; color: #ea580c !important; border-color: #fed7aa !important; }' +
  '[data-style=pro] .pm-badge-medium { background: #fefce8 !important; color: #ca8a04 !important; border-color: #fef08a !important; }' +
  '[data-style=pro] .pm-badge-low { background: #eff6ff !important; color: #2563eb !important; border-color: #bfdbfe !important; }' +
  '[data-style=pro] .pm-badge-info { background: #f0fdf4 !important; color: #16a34a !important; border-color: #bbf7d0 !important; }' +
  '[data-style=pro] .pm-status-dot.pm-status-online { background: #22c55e !important; box-shadow: none !important; }' +
  '[data-style=pro] .pm-status-dot.pm-status-offline { background: #ef4444 !important; }' +
  '[data-style=pro] .pm-status-dot.pm-status-degraded { background: #eab308 !important; }' +
  '[data-style=pro] .pm-status-dot.pm-status-standby { background: #71717a !important; }' +
  '[data-style=pro] .pm-progress-bar { background: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-progress-fill { background: #18181b !important; }' +
  '[data-style=pro] .pm-card { background: #fff !important; border: 1px solid #e5e5e5 !important; }' +
  '[data-style=pro] .pm-card:hover { border-color: #d4d4d8 !important; box-shadow: 0 4px 12px rgba(0,0,0,0.06) !important; transform: none !important; }' +
  '[data-style=pro] .pm-card-header { color: #18181b !important; border-left-color: #18181b !important; }' +
  '[data-style=pro] .pm-card-title { color: #18181b !important; }' +
  '[data-style=pro] .pm-card-body { color: #3f3f46 !important; }' +
  '[data-style=pro] .pm-card-glow { box-shadow: none !important; }' +
  '[data-style=pro] .pm-alert-feed { background: #fff !important; border-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-alert-item { border-bottom-color: #f4f4f5 !important; }' +
  '[data-style=pro] .pm-alert-row { border-bottom: 1px solid #f4f4f5 !important; }' +
  '[data-style=pro] .pm-alert-row:hover { background: #f9fafb !important; }' +
  '[data-style=pro] .pm-alert-time { color: #71717a !important; }' +
  '[data-style=pro] .pm-alert-sev { box-shadow: none !important; }' +
  '[data-style=pro] .pm-alert-id { color: #71717a !important; }' +
  '[data-style=pro] .pm-alert-msg { color: #3f3f46 !important; }' +
  '[data-style=pro] .pm-alert-count { color: #71717a !important; }' +
  '[data-style=pro] .pm-timeline { color: #3f3f46 !important; }' +
  '[data-style=pro] .pm-timeline::before { background: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-timeline-item { background: #fff !important; border-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-timeline-time { color: #71717a !important; }' +
  '[data-style=pro] .pm-timeline-label { color: #18181b !important; }' +
  '[data-style=pro] .pm-timeline-detail { color: #71717a !important; }' +
  '[data-style=pro] .pm-predict-card { background: #fff !important; border: 1px solid #e5e5e5 !important; }' +
  '[data-style=pro] .pm-predict-card:hover { border-color: #d4d4d8 !important; }' +
  '[data-style=pro] .pm-operator { color: #71717a !important; }' +
  '[data-style=pro] .pm-table-wrap { border: 1px solid #e5e5e5 !important; border-radius: 8px !important; overflow: hidden !important; }' +
  '[data-style=pro] .pm-btn { background: #f4f4f5 !important; color: #18181b !important; border: 1px solid #e5e5e5 !important; border-radius: 4px !important; box-shadow: none !important; }' +
  '[data-style=pro] .pm-btn:hover { background: #e4e4e7 !important; }' +
  '[data-style=pro] .pm-btn-primary, [data-style=pro] .pm-btn-accent { background: #18181b !important; color: #fff !important; border-color: #18181b !important; }' +
  '[data-style=pro] .pm-btn-primary:hover, [data-style=pro] .pm-btn-accent:hover { background: #27272a !important; }' +
  '[data-style=pro] .pm-btn-danger, [data-style=pro] .pm-btn-kill { background: #dc2626 !important; color: #fff !important; border-color: #dc2626 !important; }' +
  '[data-style=pro] .pm-btn-warning, [data-style=pro] .pm-btn-warn { background: #ca8a04 !important; color: #fff !important; border-color: #ca8a04 !important; }' +
  '[data-style=pro] .pm-btn-blue { background: #2563eb !important; color: #fff !important; border-color: #2563eb !important; }' +
  '[data-style=pro] .pm-text-green { color: #16a34a !important; }' +
  '[data-style=pro] .pm-text-red { color: #dc2626 !important; }' +
  '[data-style=pro] .pm-text-yellow { color: #ca8a04 !important; }' +
  '[data-style=pro] .pm-text-blue { color: #2563eb !important; }' +
  '[data-style=pro] .pm-text-white { color: #18181b !important; }' +
  '[data-style=pro] .pm-text-muted { color: #71717a !important; }' +
  '[data-style=pro] .pm-text-bold { color: #18181b !important; }' +
  '[data-style=pro] .pm-val-accent { color: #18181b !important; text-shadow: none !important; }' +
  '[data-style=pro] .pm-tooltip { background: #fff !important; border: 1px solid #e5e5e5 !important; color: #18181b !important; box-shadow: 0 4px 12px rgba(0,0,0,0.1) !important; }' +
  '[data-style=pro] .pm-vuln-card { background: #fff !important; border: 1px solid #e5e5e5 !important; }' +
  '[data-style=pro] .pm-vuln-cvss { color: #18181b !important; }' +
  '[data-style=pro] .pm-actor-card { background: #fff !important; border: 1px solid #e5e5e5 !important; }' +
  '[data-style=pro] .pm-actor-name { color: #18181b !important; }' +
  '[data-style=pro] .pm-actor-nation { color: #71717a !important; }' +
  '[data-style=pro] .pm-allied-card { background: #fff !important; border: 1px solid #e5e5e5 !important; }' +
  '[data-style=pro] .pm-allied-name { color: #18181b !important; }' +
  '[data-style=pro] .pm-campaign-card { background: #fff !important; border: 1px solid #e5e5e5 !important; }' +
  '[data-style=pro] .pm-campaign-title { color: #18181b !important; }' +
  '[data-style=pro] .pm-whatif-panel { background: #fff !important; border: 1px solid #e5e5e5 !important; }' +
  '[data-style=pro] .pm-whatif-result { background: #f9fafb !important; border: 1px solid #e5e5e5 !important; }' +
  '[data-style=pro] .pm-whatif-result-title { color: #18181b !important; }' +
  '[data-style=pro] .pm-aar-panel { background: #fff !important; border: 1px solid #e5e5e5 !important; }' +
  '[data-style=pro] .pm-aar-title { color: #18181b !important; }' +
  '[data-style=pro] .pm-aar-section { color: #3f3f46 !important; }' +
  '[data-style=pro] .pm-analyst-workspace { background: #fff !important; }' +
  '[data-style=pro] .pm-blink { animation: none !important; }' +
  '[data-style=pro] .pm-version { color: #a1a1aa !important; }' +
  '[data-style=pro] .pm-topo-table { color: #18181b !important; }' +
  '[data-style=pro] .pm-topo-row:hover { background: #f9fafb !important; }' +
  '[data-style=pro] .pm-wrap ::-webkit-scrollbar-track { background: #f4f4f5 !important; }' +
  '[data-style=pro] .pm-wrap ::-webkit-scrollbar-thumb { background: #d4d4d8 !important; }' +
  '[data-style=pro] .pm-wrap input, [data-style=pro] .pm-wrap select, [data-style=pro] .pm-wrap textarea { background: #fff !important; border: 1px solid #e5e5e5 !important; color: #18181b !important; border-radius: 6px !important; }' +
  '[data-style=pro] .pm-wrap button { font-family: ui-sans-serif,system-ui,sans-serif !important; }' +
  '[data-style=pro] .pm-scanline { display: none !important; }' +
  '[data-style=pro] .pm-wrap [style*="background: #0"] { background: #fff !important; }' +
  '[data-style=pro] .pm-wrap [style*="background:#0"] { background: #fff !important; }' +
  '[data-style=pro] .pm-wrap [style*="color: #00ff"] { color: #18181b !important; }' +
  '[data-style=pro] .pm-wrap [style*="color:#00ff"] { color: #18181b !important; }' +
  '[data-style=pro] .pm-wrap [style*="color: #0f0"] { color: #18181b !important; }' +
  '[data-style=pro] .pm-wrap [style*="text-shadow"] { text-shadow: none !important; }' +
  '[data-style=pro] .pm-wrap [style*="box-shadow: 0 0"] { box-shadow: none !important; }' +
  '[data-style=pro] .pm-subsection-title { color: #18181b !important; border-bottom-color: #e5e5e5 !important; font-family: ui-sans-serif,system-ui,sans-serif !important; }' +
  '[data-style=pro] .pm-playbook-card { background: #fff !important; border: 1px solid #e5e5e5 !important; border-radius: 8px !important; }' +
  '[data-style=pro] .pm-playbook-card:hover { border-color: #d4d4d8 !important; }' +
  '[data-style=pro] .pm-playbook-header { color: #18181b !important; }' +
  '[data-style=pro] .pm-playbook-name { color: #18181b !important; font-family: ui-sans-serif,system-ui,sans-serif !important; }' +
  '[data-style=pro] .pm-playbook-team { color: #71717a !important; }' +
  '[data-style=pro] .pm-playbook-steps { color: #71717a !important; }' +
  '[data-style=pro] .pm-playbook-step { border-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-playbook-step .step-num { background: #f4f4f5 !important; color: #18181b !important; }' +
  '[data-style=pro] .pm-playbook-auto { color: #16a34a !important; border-color: #bbf7d0 !important; }' +
  '[data-style=pro] .pm-playbook-manual { color: #ca8a04 !important; border-color: #fef08a !important; }' +
  '[data-style=pro] .pm-progress { background: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-progress-green { background: #18181b !important; }' +
  '[data-style=pro] .pm-progress-yellow { background: #ca8a04 !important; }' +
  '[data-style=pro] .pm-progress-red { background: #dc2626 !important; }' +
  '[data-style=pro] .pm-progress-blue { background: #2563eb !important; }' +
  '[data-style=pro] .pm-wrap [style*="background:#0d"] { background: #fff !important; }' +
  '[data-style=pro] .pm-wrap [style*="background: #0d"] { background: #fff !important; }' +
  '[data-style=pro] .pm-wrap [style*="background:#08"] { background: #fff !important; }' +
  '[data-style=pro] .pm-wrap [style*="background: #08"] { background: #fff !important; }' +
  '[data-style=pro] .pm-wrap [style*="background:#11"] { background: #f9fafb !important; }' +
  '[data-style=pro] .pm-wrap [style*="background: #11"] { background: #f9fafb !important; }' +
  '[data-style=pro] .pm-wrap [style*="color:#00e5"] { color: #18181b !important; }' +
  '[data-style=pro] .pm-wrap [style*="color: #00e5"] { color: #18181b !important; }' +
  '[data-style=pro] .pm-wrap [style*="color:#00aa"] { color: #18181b !important; }' +
  '[data-style=pro] .pm-wrap [style*="color: #00aa"] { color: #18181b !important; }' +
  '[data-style=pro] .pm-wrap [style*="color:#ff"] { color: #18181b !important; }' +
  '[data-style=pro] .pm-wrap [style*="color: #ff"] { color: #18181b !important; }' +
  '[data-style=pro] .pm-wrap [style*="border-left:3px solid #"] { border-left-color: #d4d4d8 !important; }' +
  '[data-style=pro] .pm-wrap [style*="border: 1px solid #1a"] { border-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-wrap [style*="border:1px solid #1a"] { border-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-wrap [style*="font-family:monospace"], [data-style=pro] .pm-wrap [style*="font-family: monospace"] { font-family: ui-sans-serif,system-ui,sans-serif !important; }' +
  '[data-style=pro] .pm-wrap [style*="font-family:\\"Courier"] { font-family: ui-sans-serif,system-ui,sans-serif !important; }' +
  '[data-style=pro] .pm-section-header { color: #18181b !important; border-bottom-color: #e5e5e5 !important; font-family: ui-sans-serif,system-ui,sans-serif !important; }' +
  '[data-style=pro] .pm-mono { font-family: ui-monospace,"SF Mono",Menlo,monospace !important; color: #71717a !important; }' +
  '[data-style=pro] .pm-label { color: #71717a !important; }' +
  '[data-style=pro] .pm-label-sm { color: #71717a !important; }' +
  '[data-style=pro] .pm-select { background: #fff !important; color: #18181b !important; border: 1px solid #e5e5e5 !important; border-radius: 6px !important; font-family: ui-sans-serif,system-ui,sans-serif !important; }' +
  '[data-style=pro] .pm-select:focus { border-color: #18181b !important; }' +
  '[data-style=pro] .pm-response-log { background: #fff !important; border-color: #e5e5e5 !important; font-family: ui-sans-serif,system-ui,sans-serif !important; }' +
  '[data-style=pro] .pm-status-green { color: #16a34a !important; }' +
  '[data-style=pro] .pm-status-yellow { color: #ca8a04 !important; }' +
  '[data-style=pro] .pm-status-blue { color: #2563eb !important; }' +
  '[data-style=pro] .pm-dot-green { background: #16a34a !important; box-shadow: none !important; }' +
  '[data-style=pro] .pm-dot-yellow { background: #ca8a04 !important; box-shadow: none !important; }' +
  '[data-style=pro] .pm-containment-card, [data-style=pro] .pm-containment-card.pm-contain-active, [data-style=pro] .pm-containment-card.pm-contain-standby { background: #fff !important; border: 1px solid #e5e5e5 !important; border-radius: 8px !important; padding: 14px !important; }' +
  '[data-style=pro] .pm-contain-name { color: #18181b !important; font-family: ui-sans-serif,system-ui,sans-serif !important; }' +
  '[data-style=pro] .pm-contain-status { color: #3f3f46 !important; }' +
  '[data-style=pro] .pm-contain-detail { color: #71717a !important; }' +
  '[data-style=pro] .pm-contain-scope { color: #71717a !important; }' +
  '[data-style=pro] .pm-form-row { color: #18181b !important; }' +

  /* ---- Defense tab: containment, response log, playbook, recovery ---- */
  '[data-style=pro] .pm-containment-grid { gap: 12px !important; }' +
  '[data-style=pro] .pm-contain-icon { filter: grayscale(1) !important; }' +
  '[data-style=pro] .pm-contain-toggle { background: #18181b !important; color: #fff !important; border: none !important; border-radius: 4px !important; font-family: ui-sans-serif,system-ui,sans-serif !important; font-size: 11px !important; padding: 5px 12px !important; cursor: pointer !important; letter-spacing: 0 !important; text-transform: none !important; }' +
  '[data-style=pro] .pm-contain-toggle:hover { background: #3f3f46 !important; }' +
  '[data-style=pro] .pm-response-log { background: #fff !important; border-color: #e5e5e5 !important; font-family: ui-sans-serif,system-ui,sans-serif !important; }' +
  '[data-style=pro] .pm-response-row td { color: #3f3f46 !important; }' +
  '[data-style=pro] .pm-response-row:hover td { background: #f9fafb !important; }' +
  '[data-style=pro] .pm-progress-text { color: #71717a !important; font-family: ui-sans-serif,system-ui,sans-serif !important; }' +
  '[data-style=pro] .pm-playbook-toggle { background: #18181b !important; color: #fff !important; border: none !important; border-radius: 4px !important; font-family: ui-sans-serif,system-ui,sans-serif !important; }' +
  '[data-style=pro] .pm-playbook-toggle:hover { background: #3f3f46 !important; }' +
  '[data-style=pro] .pm-step { color: #71717a !important; }' +
  '[data-style=pro] .pm-step-done { color: #16a34a !important; }' +
  '[data-style=pro] .pm-step-active { color: #18181b !important; font-weight: 600 !important; }' +
  '[data-style=pro] .pm-step-pending { color: #a1a1aa !important; }' +
  '[data-style=pro] .pm-recovery-btn { background: #18181b !important; color: #fff !important; border: none !important; border-radius: 4px !important; font-family: ui-sans-serif,system-ui,sans-serif !important; }' +
  '[data-style=pro] .pm-recovery-btn:hover { background: #3f3f46 !important; }' +
  '[data-style=pro] .pm-status-red { color: #dc2626 !important; }' +
  '[data-style=pro] .pm-center { color: #3f3f46 !important; }' +

  /* ---- Broad inline-style overrides for remaining dark backgrounds ---- */
  '[data-style=pro] .pm-wrap [style*="background:#080c"] { background: #fafafa !important; }' +
  '[data-style=pro] .pm-wrap [style*="background: #080c"] { background: #fafafa !important; }' +
  '[data-style=pro] .pm-wrap [style*="background:#111"] { background: #f9fafb !important; }' +
  '[data-style=pro] .pm-wrap [style*="background: #111"] { background: #f9fafb !important; }' +
  '[data-style=pro] .pm-wrap [style*="background:#0a0"] { background: #fff !important; }' +
  '[data-style=pro] .pm-wrap [style*="background: #0a0"] { background: #fff !important; }' +
  '[data-style=pro] .pm-wrap [style*="border-color:#1a"] { border-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-wrap [style*="border-color: #1a"] { border-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-wrap [style*="border:1px solid #0d"] { border-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-wrap [style*="border: 1px solid #0d"] { border-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-wrap [style*="border-bottom:1px solid #1a"] { border-bottom-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-wrap [style*="border-bottom: 1px solid #1a"] { border-bottom-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-wrap [style*="border-top:1px solid #1a"] { border-top-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-wrap [style*="border-top: 1px solid #1a"] { border-top-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-wrap [style*="color:#c8d"] { color: #3f3f46 !important; }' +
  '[data-style=pro] .pm-wrap [style*="color: #c8d"] { color: #3f3f46 !important; }' +
  '[data-style=pro] .pm-wrap [style*="color:#8899"] { color: #71717a !important; }' +
  '[data-style=pro] .pm-wrap [style*="color: #8899"] { color: #71717a !important; }' +
  '[data-style=pro] .pm-wrap [style*="color:#6677"] { color: #a1a1aa !important; }' +
  '[data-style=pro] .pm-wrap [style*="color: #6677"] { color: #a1a1aa !important; }' +
  '[data-style=pro] .pm-wrap [style*="color:#4a6a"] { color: #a1a1aa !important; }' +
  '[data-style=pro] .pm-wrap [style*="color: #4a6a"] { color: #a1a1aa !important; }' +

  /* ---- Deception, correlation, comparison panels (all dark-background) ---- */
  '[data-style=pro] .pm-deception-card { background: #fff !important; border-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-deception-name { color: #18181b !important; }' +
  '[data-style=pro] .pm-deception-type { color: #71717a !important; }' +
  '[data-style=pro] .pm-deception-detail { color: #71717a !important; }' +
  '[data-style=pro] .pm-deception-desc { color: #71717a !important; }' +
  '[data-style=pro] .pm-corr-alert { background: #fff !important; border-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-corr-alert:hover { border-color: #d4d4d8 !important; }' +
  '[data-style=pro] .pm-corr-title { color: #18181b !important; }' +
  '[data-style=pro] .pm-corr-id { color: #71717a !important; font-family: ui-monospace,monospace !important; }' +
  '[data-style=pro] .pm-corr-confidence { color: #18181b !important; }' +
  '[data-style=pro] .pm-corr-timestamp { color: #a1a1aa !important; }' +
  '[data-style=pro] .pm-corr-src-tag { background: #f4f4f5 !important; color: #3f3f46 !important; }' +
  '[data-style=pro] .pm-corr-src-label { color: #a1a1aa !important; }' +
  '[data-style=pro] .pm-corr-action { background: #f9fafb !important; border-top-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-corr-action-label { color: #18181b !important; }' +
  '[data-style=pro] .pm-corr-action-text { color: #3f3f46 !important; }' +
  '[data-style=pro] .pm-corr-expand-btn { border-color: #e5e5e5 !important; color: #18181b !important; font-family: ui-sans-serif,system-ui,sans-serif !important; }' +
  '[data-style=pro] .pm-corr-expand-btn:hover { background: #f4f4f5 !important; }' +
  '[data-style=pro] .pm-comp-panel { background: #fff !important; border-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-comp-title { color: #18181b !important; }' +
  '[data-style=pro] .pm-comp-stat { color: #3f3f46 !important; }' +
  '[data-style=pro] .pm-comp-delta { background: #f9fafb !important; border-color: #e5e5e5 !important; color: #18181b !important; }' +
  '[data-style=pro] .pm-classification-banner { background: #dc2626 !important; }' +
  '[data-style=pro] .pm-deploy-status { color: #71717a !important; font-family: ui-sans-serif,system-ui,sans-serif !important; }' +

  /* ---- CI Report, Dep Tree, Clock panels ---- */
  '[data-style=pro] .pm-ci-report-title { color: #18181b !important; }' +
  '[data-style=pro] .pm-ci-report-summary { color: #71717a !important; }' +
  '[data-style=pro] .pm-dep-hdr { color: #18181b !important; border-bottom-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-dep-category { background: #fff !important; border-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-dep-name { color: #18181b !important; }' +
  '[data-style=pro] .pm-dep-item-name { color: #3f3f46 !important; }' +
  '[data-style=pro] .pm-dep-ver { color: #71717a !important; font-family: ui-monospace,monospace !important; }' +
  '[data-style=pro] .pm-dep-child { color: #71717a !important; }' +

  /* ---- Recovery dashboard ---- */
  '[data-style=pro] .pm-recovery-timeline { border-color: #e5e5e5 !important; }' +

  /* Playbook step spacing */
  '[data-style=pro] .pm-playbook-steps { display: flex !important; flex-wrap: wrap !important; gap: 4px 8px !important; }' +

  '</style>';

  // ============================================================================
  // TAB CONFIGURATION
  // ============================================================================
  var PM_TABS = [
    {id:'command',label:'COMMAND CENTER',icon:'&#9733;'},
    {id:'twin',label:'DIGITAL TWIN',icon:'&#9881;'},
    {id:'terrain',label:'CYBER TERRAIN',icon:'&#9730;'},
    {id:'sigint',label:'SIGINT FUSION',icon:'&#9873;'},
    {id:'predict',label:'PREDICTIVE',icon:'&#9888;'},
    {id:'engage',label:'ENGAGEMENT',icon:'&#9876;'},
    {id:'wargame',label:'WARGAME',icon:'&#9812;'},
    {id:'cascade',label:'CASCADE',icon:'&#10043;'},
    {id:'counterintel',label:'COUNTER-INTEL',icon:'[CI]'},
    {id:'supplychain',label:'SUPPLY CHAIN',icon:'&#9741;'},
    {id:'defense',label:'DEFENSE',icon:'&#9879;'},
    {id:'bda',label:'BATTLE DAMAGE',icon:'&#10006;'},
    {id:'authority',label:'AUTHORITY',icon:'&#9878;'},
    {id:'pivot',label:'OMNI-PIVOT',icon:'[PX]'},
    {id:'attribution',label:'ATTRIBUTION',icon:'[AX]'},
    {id:'exposure',label:'EXPOSURE',icon:'[EX]'},
    {id:'report',label:'REPORT BUILDER',icon:'[RB]'}
  ];

  // ============================================================================
  // STATE MANAGEMENT
  // ============================================================================
  var state = {
    activeTab: 'command',
    defcon: 3,
    alerts: [],
    intervals: [],
    selectedNode: null,
    selectedScenario: null,
    exerciseRunning: false,
    exerciseSpeed: 1,
    exerciseTime: 0,
    cascadeRunning: false,
    cascadeResults: [],
    engagePlan: {target: null, phases: [], roe: []},
    wargameTeam: 'Blue',
    wargameScore: {red: 0, blue: 0},
    filterText: '',
    modalOpen: false,
    modalContent: ''
  };

  function loadState() {
    try {
      var saved = localStorage.getItem('dn_prometheus_v1');
      if (saved) {
        var parsed = JSON.parse(saved);
        if (parsed.activeTab) state.activeTab = parsed.activeTab;
        if (parsed.defcon) state.defcon = parsed.defcon;
      }
    } catch(e) {}
  }

  function saveState() {
    try {
      localStorage.setItem('dn_prometheus_v1', JSON.stringify({
        activeTab: state.activeTab,
        defcon: state.defcon
      }));
    } catch(e) {}
  }

  loadState();

  // ============================================================================
  // HELPER FUNCTIONS
  // ============================================================================
  function getSectorNodes(sector) {
    var result = [];
    for (var i = 0; i < INFRA_NODES.length; i++) {
      if (INFRA_NODES[i].sector === sector) result.push(INFRA_NODES[i]);
    }
    return result;
  }

  function getNodeById(id) {
    for (var i = 0; i < INFRA_NODES.length; i++) {
      if (INFRA_NODES[i].id === id) return INFRA_NODES[i];
    }
    return null;
  }

  function getSectorHealth(sector) {
    var nodes = getSectorNodes(sector);
    var online = 0;
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i].status === 'online' || nodes[i].status === 'standby') online++;
    }
    return nodes.length > 0 ? Math.round((online / nodes.length) * 100) : 0;
  }

  function getStatusColor(status) {
    if (status === 'online') return 'green';
    if (status === 'standby') return 'blue';
    if (status === 'degraded') return 'yellow';
    return 'red';
  }

  function getDefconColor(level) {
    if (level === 1) return '#ffffff';
    if (level === 2) return '#ff0040';
    if (level === 3) return '#ffaa00';
    if (level === 4) return '#00ff88';
    return '#00aaff';
  }

  function getClassBadge(classification) {
    if (classification === 'TS/SCI' || classification === 'TOP SECRET') return 'pm-badge-ts';
    if (classification === 'SECRET') return 'pm-badge-secret';
    if (classification === 'CONFIDENTIAL') return 'pm-badge-conf';
    return 'pm-badge-unclass';
  }

  function formatNumber(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(0) + 'K';
    return String(n);
  }

  function fmtTime(ts) {
    var d = new Date(ts);
    var h = d.getUTCHours();
    var m = d.getUTCMinutes();
    return (h < 10 ? '0' : '') + h + ':' + (m < 10 ? '0' : '') + m + 'Z';
  }

  function randInt(a, b) {
    return Math.floor(Math.random() * (b - a + 1)) + a;
  }

  function getDependents(nodeId) {
    var result = [];
    for (var i = 0; i < INFRA_NODES.length; i++) {
      if (INFRA_NODES[i].deps.indexOf(nodeId) !== -1) result.push(INFRA_NODES[i]);
    }
    return result;
  }

  function getCascade(nodeId, attackType) {
    var affected = [nodeId];
    var queue = [nodeId];
    var timeline = [{minute: 0, node: nodeId, effect: attackType}];
    var minute = 1;
    while (queue.length > 0 && minute < 60) {
      var next = [];
      for (var q = 0; q < queue.length; q++) {
        var dependents = getDependents(queue[q]);
        for (var d = 0; d < dependents.length; d++) {
          if (affected.indexOf(dependents[d].id) === -1) {
            affected.push(dependents[d].id);
            next.push(dependents[d].id);
            timeline.push({minute: minute, node: dependents[d].id, effect: 'cascading ' + attackType});
          }
        }
      }
      queue = next;
      minute += randInt(2, 8);
    }
    return {affected: affected, timeline: timeline};
  }

  function generateAlerts() {
    var types = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
    var msgs = [
      'Anomalous traffic detected on node ',
      'Failed authentication attempt on ',
      'Port scan detected targeting ',
      'Malware signature matched on ',
      'Configuration change detected on ',
      'Unusual data transfer from ',
      'IDS alert triggered on ',
      'Certificate expiry warning for ',
      'Patch missing on ',
      'Unauthorized access attempt to ',
      'DDoS mitigation activated for ',
      'Privilege escalation detected on ',
      'Lateral movement suspected from ',
      'C2 beacon detected from ',
      'Data exfiltration alert on '
    ];
    var node = INFRA_NODES[randInt(0, INFRA_NODES.length - 1)];
    var severity = types[randInt(0, 4)];
    var msg = msgs[randInt(0, msgs.length - 1)] + node.name;
    var now = new Date();
    return {
      time: (now.getUTCHours() < 10 ? '0' : '') + now.getUTCHours() + ':' + (now.getUTCMinutes() < 10 ? '0' : '') + now.getUTCMinutes() + ':' + (now.getUTCSeconds() < 10 ? '0' : '') + now.getUTCSeconds() + 'Z',
      severity: severity,
      message: msg,
      node: node.id
    };
  }

  var SECTORS = [
    {id:'POWER_GRID',name:'Power Grid',icon:'&#9889;'},
    {id:'WATER',name:'Water',icon:'[W]'},
    {id:'TELECOM',name:'Telecom',icon:'[T]'},
    {id:'TRANSPORT',name:'Transport',icon:'&#9992;'},
    {id:'FINANCIAL',name:'Financial',icon:'[F]'},
    {id:'HEALTHCARE',name:'Healthcare',icon:'&#9764;'},
    {id:'GOVERNMENT',name:'Government',icon:'[G]'},
    {id:'ENERGY',name:'Energy',icon:'&#9981;'}
  ];

  // ============================================================================
  // WORLD MAP DRAWING (Canvas)
  // ============================================================================
  function drawWorldMap(canvas) {
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var w = canvas.width = canvas.offsetWidth * 2;
    var h = canvas.height = canvas.offsetHeight * 2;
    ctx.scale(2, 2);
    var dw = canvas.offsetWidth;
    var dh = canvas.offsetHeight;

    ctx.fillStyle = '#080c14';
    ctx.fillRect(0, 0, dw, dh);

    ctx.strokeStyle = '#0d2a1a';
    ctx.lineWidth = 0.5;
    for (var gx = 0; gx < dw; gx += 30) {
      ctx.beginPath(); ctx.moveTo(gx, 0); ctx.lineTo(gx, dh); ctx.stroke();
    }
    for (var gy = 0; gy < dh; gy += 30) {
      ctx.beginPath(); ctx.moveTo(0, gy); ctx.lineTo(dw, gy); ctx.stroke();
    }

    var continents = [
      {x: 0.15, y: 0.28, w: 0.08, h: 0.22, name: 'NA'},
      {x: 0.20, y: 0.55, w: 0.06, h: 0.25, name: 'SA'},
      {x: 0.42, y: 0.18, w: 0.10, h: 0.28, name: 'EU'},
      {x: 0.45, y: 0.48, w: 0.12, h: 0.35, name: 'AF'},
      {x: 0.55, y: 0.20, w: 0.20, h: 0.30, name: 'AS'},
      {x: 0.72, y: 0.60, w: 0.08, h: 0.15, name: 'OC'}
    ];

    ctx.fillStyle = '#0d2a1a';
    for (var c = 0; c < continents.length; c++) {
      var cont = continents[c];
      ctx.beginPath();
      ctx.ellipse(cont.x * dw, cont.y * dh + (cont.h * dh) / 2, (cont.w * dw) / 2, (cont.h * dh) / 2, 0, 0, Math.PI * 2);
      ctx.fill();
    }

    var threats = [
      {x: 0.14, y: 0.32, label: 'US', level: 3},
      {x: 0.44, y: 0.25, label: 'UK', level: 2},
      {x: 0.46, y: 0.22, label: 'DE', level: 2},
      {x: 0.52, y: 0.22, label: 'RU', level: 5},
      {x: 0.55, y: 0.28, label: 'UA', level: 5},
      {x: 0.67, y: 0.35, label: 'CN', level: 4},
      {x: 0.55, y: 0.35, label: 'IR', level: 4},
      {x: 0.70, y: 0.30, label: 'KP', level: 3},
      {x: 0.72, y: 0.32, label: 'JP', level: 1},
      {x: 0.73, y: 0.35, label: 'KR', level: 2},
      {x: 0.68, y: 0.40, label: 'TW', level: 4},
      {x: 0.50, y: 0.38, label: 'SA', level: 2},
      {x: 0.48, y: 0.32, label: 'IL', level: 3},
      {x: 0.48, y: 0.50, label: 'NG', level: 1},
      {x: 0.20, y: 0.55, label: 'BR', level: 1},
      {x: 0.75, y: 0.62, label: 'AU', level: 1},
      {x: 0.62, y: 0.40, label: 'IN', level: 2},
      {x: 0.43, y: 0.28, label: 'FR', level: 2},
      {x: 0.54, y: 0.25, label: 'PL', level: 2},
      {x: 0.59, y: 0.20, label: 'FI', level: 1}
    ];

    var time = Date.now() / 1000;
    for (var t = 0; t < threats.length; t++) {
      var th = threats[t];
      var tx = th.x * dw;
      var ty = th.y * dh;
      var colors = ['#00ff88','#00aaff','#ffaa00','#ff6600','#ff0040'];
      var col = colors[Math.min(th.level - 1, 4)];
      var blink = Math.sin(time * (1 + th.level * 0.5) + t) * 0.5 + 0.5;

      ctx.beginPath();
      ctx.arc(tx, ty, 3 + th.level, 0, Math.PI * 2);
      ctx.fillStyle = col;
      ctx.globalAlpha = 0.3 + blink * 0.7;
      ctx.fill();
      ctx.globalAlpha = 1;

      ctx.beginPath();
      ctx.arc(tx, ty, 2, 0, Math.PI * 2);
      ctx.fillStyle = col;
      ctx.fill();

      ctx.font = '8px Courier New';
      ctx.fillStyle = '#667788';
      ctx.fillText(th.label, tx + 6, ty + 3);
    }

    if (state.defcon <= 2) {
      for (var a = 0; a < 5; a++) {
        var ax = threats[randInt(0, threats.length - 1)];
        var bx = threats[randInt(0, threats.length - 1)];
        if (ax !== bx) {
          ctx.beginPath();
          ctx.moveTo(ax.x * dw, ax.y * dh);
          ctx.lineTo(bx.x * dw, bx.y * dh);
          ctx.strokeStyle = 'rgba(255,0,64,0.15)';
          ctx.lineWidth = 1;
          ctx.stroke();
        }
      }
    }
  }

  // ============================================================================
  // DEFCON GAUGE DRAWING (Canvas)
  // ============================================================================
  function drawDefconGauge(canvas) {
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var s = 180;
    canvas.width = s * 2;
    canvas.height = s * 2;
    ctx.scale(2, 2);
    var cx = s / 2, cy = s / 2, r = 70;

    ctx.clearRect(0, 0, s, s);

    ctx.beginPath();
    ctx.arc(cx, cy, r, 0.75 * Math.PI, 2.25 * Math.PI);
    ctx.strokeStyle = '#1a2332';
    ctx.lineWidth = 12;
    ctx.stroke();

    var segments = [
      {start: 0.75, end: 1.05, color: '#00aaff'},
      {start: 1.05, end: 1.35, color: '#00ff88'},
      {start: 1.35, end: 1.65, color: '#ffaa00'},
      {start: 1.65, end: 1.95, color: '#ff6600'},
      {start: 1.95, end: 2.25, color: '#ff0040'}
    ];

    var activeIdx = 5 - state.defcon;
    for (var sg = 0; sg <= activeIdx; sg++) {
      ctx.beginPath();
      ctx.arc(cx, cy, r, segments[sg].start * Math.PI, segments[sg].end * Math.PI);
      ctx.strokeStyle = segments[sg].color;
      ctx.lineWidth = 12;
      ctx.globalAlpha = sg === activeIdx ? 1 : 0.3;
      ctx.stroke();
      ctx.globalAlpha = 1;
    }

    var needleAngle = (0.75 + (5 - state.defcon) * 0.3) * Math.PI;
    var nx = cx + Math.cos(needleAngle) * (r - 20);
    var ny = cy + Math.sin(needleAngle) * (r - 20);
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(nx, ny);
    ctx.strokeStyle = getDefconColor(state.defcon);
    ctx.lineWidth = 2;
    ctx.stroke();

    ctx.beginPath();
    ctx.arc(cx, cy, 4, 0, Math.PI * 2);
    ctx.fillStyle = getDefconColor(state.defcon);
    ctx.fill();
  }

  // ============================================================================
  // SPARKLINE DRAWING
  // ============================================================================
  function drawSparkline(canvas, data, color) {
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    canvas.width = 160;
    canvas.height = 48;
    ctx.clearRect(0, 0, 160, 48);
    var max = Math.max.apply(null, data);
    var min = Math.min.apply(null, data);
    var range = max - min || 1;
    ctx.beginPath();
    for (var i = 0; i < data.length; i++) {
      var x = (i / (data.length - 1)) * 156 + 2;
      var y = 44 - ((data[i] - min) / range) * 40;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.strokeStyle = color || '#00ff88';
    ctx.lineWidth = 1.5;
    ctx.stroke();
  }

  // ============================================================================
  // TAB 1: COMMAND CENTER
  // ============================================================================


  // ===========================================================================
  // UTILITY FUNCTIONS
  // ===========================================================================

  function getUptime() {
    var now = Date.now();
    var start = state.startTime || now;
    var diff = Math.floor((now - start) / 1000);
    var days = Math.floor(diff / 86400);
    var hours = Math.floor((diff % 86400) / 3600);
    var mins = Math.floor((diff % 3600) / 60);
    var secs = diff % 60;
    return days + 'd ' + hours + 'h ' + mins + 'm ' + secs + 's';
  }

  function formatTimestamp(date) {
    if (!date) date = new Date();
    var y = date.getFullYear();
    var mo = String(date.getMonth() + 1);
    if (mo.length < 2) mo = '0' + mo;
    var d = String(date.getDate());
    if (d.length < 2) d = '0' + d;
    var h = String(date.getHours());
    if (h.length < 2) h = '0' + h;
    var mi = String(date.getMinutes());
    if (mi.length < 2) mi = '0' + mi;
    var s = String(date.getSeconds());
    if (s.length < 2) s = '0' + s;
    return y + '-' + mo + '-' + d + ' ' + h + ':' + mi + ':' + s;
  }

  function formatDateShort(date) {
    if (!date) date = new Date();
    var mo = String(date.getMonth() + 1);
    if (mo.length < 2) mo = '0' + mo;
    var d = String(date.getDate());
    if (d.length < 2) d = '0' + d;
    var h = String(date.getHours());
    if (h.length < 2) h = '0' + h;
    var mi = String(date.getMinutes());
    if (mi.length < 2) mi = '0' + mi;
    return mo + '/' + d + ' ' + h + ':' + mi;
  }

  function generateId() {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    var id = '';
    for (var i = 0; i < 12; i++) {
      id += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return id;
  }

  function getNodeById(id) {
    for (var i = 0; i < INFRA_NODES.length; i++) {
      if (INFRA_NODES[i].id === id) return INFRA_NODES[i];
    }
    return null;
  }

  function getNodesBySector(sector) {
    var result = [];
    for (var i = 0; i < INFRA_NODES.length; i++) {
      if (INFRA_NODES[i].sector === sector) result.push(INFRA_NODES[i]);
    }
    return result;
  }

  function getDependentNodes(nodeId) {
    var result = [];
    for (var i = 0; i < INFRA_NODES.length; i++) {
      var node = INFRA_NODES[i];
      if (node.deps && node.deps.indexOf(nodeId) !== -1) {
        result.push(node);
      }
    }
    return result;
  }

  function calculateCascade(nodeId, attackType) {
    var impactMap = { destroy: 1.0, degrade: 0.6, deny: 0.8, compromise: 0.4 };
    var baseImpact = impactMap[attackType] || 0.5;
    var cascade = [];
    var visited = {};
    var queue = [{ id: nodeId, minute: 0, depth: 0 }];
    visited[nodeId] = true;
    var startNode = getNodeById(nodeId);
    if (startNode) {
      cascade.push({
        node: startNode,
        minute: 0,
        impact: Math.round(baseImpact * 100),
        depth: 0,
        status: attackType === 'destroy' ? 'DESTROYED' : attackType === 'degrade' ? 'DEGRADED' : attackType === 'deny' ? 'DENIED' : 'COMPROMISED'
      });
    }
    while (queue.length > 0) {
      var current = queue.shift();
      var dependents = getDependentNodes(current.id);
      for (var i = 0; i < dependents.length; i++) {
        var dep = dependents[i];
        if (!visited[dep.id]) {
          visited[dep.id] = true;
          var propagationDelay = 2 + Math.floor(Math.random() * 4);
          var cascadeMinute = current.minute + propagationDelay;
          var cascadeImpact = Math.round(baseImpact * 100 * Math.pow(0.85, current.depth + 1));
          var cascadeStatus = cascadeImpact > 70 ? 'CRITICAL' : cascadeImpact > 40 ? 'DEGRADED' : 'DISRUPTED';
          cascade.push({
            node: dep,
            minute: cascadeMinute,
            impact: cascadeImpact,
            depth: current.depth + 1,
            status: cascadeStatus
          });
          queue.push({ id: dep.id, minute: cascadeMinute, depth: current.depth + 1 });
        }
      }
    }
    cascade.sort(function(a, b) { return a.minute - b.minute; });
    return cascade;
  }

  function getPopulationImpact(affectedNodes) {
    var total = 0;
    for (var i = 0; i < affectedNodes.length; i++) {
      var node = affectedNodes[i].node || affectedNodes[i];
      total += (node.population || 0);
    }
    return total;
  }

  function getEconomicImpact(affectedNodes) {
    var total = 0;
    var critMultiplier = { critical: 50, high: 20, medium: 8, low: 2 };
    var sectorMultiplier = {
      energy: 12, water: 8, telecom: 10, transport: 7,
      finance: 15, health: 9, government: 6, defense: 20
    };
    for (var i = 0; i < affectedNodes.length; i++) {
      var item = affectedNodes[i];
      var node = item.node || item;
      var impact = item.impact || 50;
      var crit = critMultiplier[node.criticality] || 5;
      var sect = sectorMultiplier[node.sector] || 5;
      total += crit * sect * (impact / 100) * 1000000;
    }
    return total;
  }

  function drawWorldMap(canvasId) {
    var canvas = main.querySelector('#' + canvasId);
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var w = canvas.width;
    var h = canvas.height;
    ctx.fillStyle = '#0a0e17';
    ctx.fillRect(0, 0, w, h);

    // Draw grid lines
    ctx.strokeStyle = 'rgba(0, 255, 65, 0.06)';
    ctx.lineWidth = 0.5;
    for (var gx = 0; gx < w; gx += 30) {
      ctx.beginPath();
      ctx.moveTo(gx, 0);
      ctx.lineTo(gx, h);
      ctx.stroke();
    }
    for (var gy = 0; gy < h; gy += 30) {
      ctx.beginPath();
      ctx.moveTo(0, gy);
      ctx.lineTo(w, gy);
      ctx.stroke();
    }

    // Simplified continent outlines (x,y as fraction of canvas w,h)
    var continents = [
      // North America
      { color: 'rgba(0, 255, 65, 0.15)', points: [
        [0.10, 0.12], [0.18, 0.10], [0.25, 0.12], [0.28, 0.18],
        [0.30, 0.25], [0.28, 0.32], [0.25, 0.38], [0.22, 0.42],
        [0.18, 0.48], [0.15, 0.45], [0.12, 0.40], [0.10, 0.35],
        [0.08, 0.28], [0.07, 0.20], [0.10, 0.12]
      ]},
      // South America
      { color: 'rgba(0, 255, 65, 0.15)', points: [
        [0.22, 0.52], [0.25, 0.50], [0.28, 0.52], [0.30, 0.58],
        [0.32, 0.65], [0.30, 0.72], [0.27, 0.78], [0.24, 0.82],
        [0.22, 0.85], [0.20, 0.80], [0.19, 0.72], [0.18, 0.65],
        [0.19, 0.58], [0.22, 0.52]
      ]},
      // Europe
      { color: 'rgba(0, 255, 65, 0.15)', points: [
        [0.45, 0.12], [0.50, 0.10], [0.55, 0.12], [0.56, 0.18],
        [0.54, 0.25], [0.52, 0.30], [0.50, 0.35], [0.48, 0.32],
        [0.46, 0.28], [0.44, 0.22], [0.45, 0.12]
      ]},
      // Africa
      { color: 'rgba(0, 255, 65, 0.15)', points: [
        [0.45, 0.35], [0.50, 0.33], [0.55, 0.35], [0.58, 0.42],
        [0.60, 0.50], [0.58, 0.60], [0.55, 0.68], [0.52, 0.75],
        [0.50, 0.78], [0.48, 0.75], [0.46, 0.68], [0.44, 0.60],
        [0.42, 0.50], [0.43, 0.42], [0.45, 0.35]
      ]},
      // Asia
      { color: 'rgba(0, 255, 65, 0.15)', points: [
        [0.55, 0.10], [0.62, 0.08], [0.70, 0.10], [0.78, 0.12],
        [0.85, 0.15], [0.90, 0.20], [0.88, 0.28], [0.85, 0.35],
        [0.80, 0.42], [0.75, 0.45], [0.70, 0.48], [0.65, 0.45],
        [0.60, 0.40], [0.58, 0.35], [0.56, 0.28], [0.55, 0.20],
        [0.55, 0.10]
      ]},
      // Australia
      { color: 'rgba(0, 255, 65, 0.15)', points: [
        [0.78, 0.62], [0.82, 0.58], [0.88, 0.60], [0.92, 0.64],
        [0.90, 0.72], [0.86, 0.76], [0.82, 0.74], [0.78, 0.70],
        [0.76, 0.66], [0.78, 0.62]
      ]}
    ];

    for (var ci = 0; ci < continents.length; ci++) {
      var cont = continents[ci];
      ctx.fillStyle = cont.color;
      ctx.strokeStyle = 'rgba(0, 255, 65, 0.3)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      for (var pi = 0; pi < cont.points.length; pi++) {
        var px = cont.points[pi][0] * w;
        var py = cont.points[pi][1] * h;
        if (pi === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      }
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
    }

    // Threat indicator cities
    var cities = [
      { name: 'Washington DC', x: 0.22, y: 0.30, threat: 'high' },
      { name: 'New York', x: 0.24, y: 0.28, threat: 'medium' },
      { name: 'London', x: 0.47, y: 0.20, threat: 'medium' },
      { name: 'Moscow', x: 0.58, y: 0.18, threat: 'critical' },
      { name: 'Beijing', x: 0.78, y: 0.28, threat: 'critical' },
      { name: 'Tehran', x: 0.60, y: 0.30, threat: 'high' },
      { name: 'Pyongyang', x: 0.82, y: 0.28, threat: 'high' },
      { name: 'Berlin', x: 0.50, y: 0.20, threat: 'low' },
      { name: 'Tokyo', x: 0.87, y: 0.28, threat: 'low' },
      { name: 'Tel Aviv', x: 0.56, y: 0.32, threat: 'medium' },
      { name: 'Mumbai', x: 0.66, y: 0.40, threat: 'low' },
      { name: 'Sydney', x: 0.86, y: 0.70, threat: 'low' },
      { name: 'Sao Paulo', x: 0.27, y: 0.68, threat: 'low' },
      { name: 'Lagos', x: 0.47, y: 0.50, threat: 'medium' },
      { name: 'Riyadh', x: 0.58, y: 0.36, threat: 'medium' },
      { name: 'Shanghai', x: 0.80, y: 0.32, threat: 'high' },
      { name: 'Singapore', x: 0.75, y: 0.50, threat: 'low' },
      { name: 'Taipei', x: 0.82, y: 0.34, threat: 'high' }
    ];

    var threatColors = {
      critical: '#ff1744',
      high: '#ff9100',
      medium: '#ffd600',
      low: '#00e676'
    };

    var pulse = (Math.sin(Date.now() / 400) + 1) / 2;
    for (var ti = 0; ti < cities.length; ti++) {
      var city = cities[ti];
      var cx = city.x * w;
      var cy = city.y * h;
      var color = threatColors[city.threat] || '#448aff';

      // Pulsing outer ring for critical/high
      if (city.threat === 'critical' || city.threat === 'high') {
        var outerR = 6 + pulse * 4;
        ctx.beginPath();
        ctx.arc(cx, cy, outerR, 0, Math.PI * 2);
        ctx.fillStyle = color.replace(')', ', 0.2)').replace('rgb', 'rgba').replace('#', '');
        // Use hex to rgba manually
        var r = parseInt(color.slice(1, 3), 16);
        var g = parseInt(color.slice(3, 5), 16);
        var b = parseInt(color.slice(5, 7), 16);
        ctx.fillStyle = 'rgba(' + r + ',' + g + ',' + b + ',0.25)';
        ctx.fill();
      }

      // Inner dot
      ctx.beginPath();
      ctx.arc(cx, cy, 3, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();

      // Label
      ctx.font = '8px monospace';
      ctx.fillStyle = 'rgba(0, 255, 65, 0.7)';
      ctx.fillText(city.name, cx + 6, cy + 3);
    }

    // Draw attack arcs for critical threats
    ctx.strokeStyle = 'rgba(255, 23, 68, 0.4)';
    ctx.lineWidth = 1;
    ctx.setLineDash([4, 4]);
    for (var ai = 0; ai < cities.length; ai++) {
      if (cities[ai].threat === 'critical') {
        var src = cities[ai];
        // Draw arc to Washington DC
        var dc = cities[0];
        var sx = src.x * w;
        var sy = src.y * h;
        var dx = dc.x * w;
        var dy = dc.y * h;
        var midX = (sx + dx) / 2;
        var midY = Math.min(sy, dy) - 30;
        ctx.beginPath();
        ctx.moveTo(sx, sy);
        ctx.quadraticCurveTo(midX, midY, dx, dy);
        ctx.stroke();
      }
    }
    ctx.setLineDash([]);
  }

  function drawDonutChart(canvasId, data, colors) {
    var canvas = main.querySelector('#' + canvasId);
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var w = canvas.width;
    var h = canvas.height;
    var cx = w / 2;
    var cy = h / 2;
    var outerR = Math.min(w, h) / 2 - 10;
    var innerR = outerR * 0.6;

    ctx.fillStyle = '#0a0e17';
    ctx.fillRect(0, 0, w, h);

    var total = 0;
    for (var i = 0; i < data.length; i++) total += data[i].value;
    if (total === 0) return;

    var startAngle = -Math.PI / 2;
    for (var i = 0; i < data.length; i++) {
      var sliceAngle = (data[i].value / total) * Math.PI * 2;
      var endAngle = startAngle + sliceAngle;
      var color = colors[i % colors.length];

      ctx.beginPath();
      ctx.arc(cx, cy, outerR, startAngle, endAngle);
      ctx.arc(cx, cy, innerR, endAngle, startAngle, true);
      ctx.closePath();
      ctx.fillStyle = color;
      ctx.fill();

      // Label
      var labelAngle = startAngle + sliceAngle / 2;
      var labelR = outerR + 14;
      var lx = cx + Math.cos(labelAngle) * labelR;
      var ly = cy + Math.sin(labelAngle) * labelR;
      ctx.font = '9px monospace';
      ctx.fillStyle = '#8892b0';
      ctx.textAlign = lx > cx ? 'left' : 'right';
      ctx.fillText(data[i].label, lx, ly);
      // Percentage in center of slice
      var pctAngle = labelAngle;
      var pctR = (outerR + innerR) / 2;
      var pctX = cx + Math.cos(pctAngle) * pctR;
      var pctY = cy + Math.sin(pctAngle) * pctR;
      var pct = Math.round((data[i].value / total) * 100);
      if (pct >= 5) {
        ctx.textAlign = 'center';
        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 9px monospace';
        ctx.fillText(pct + '%', pctX, pctY + 3);
      }
      startAngle = endAngle;
    }
    ctx.textAlign = 'left';

    // Center text
    ctx.font = 'bold 14px monospace';
    ctx.fillStyle = '#00ff41';
    ctx.textAlign = 'center';
    ctx.fillText(total, cx, cy + 5);
    ctx.textAlign = 'left';
  }

  function drawSparkline(canvasId, values, color) {
    var canvas = main.querySelector('#' + canvasId);
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var w = canvas.width;
    var h = canvas.height;
    ctx.clearRect(0, 0, w, h);
    if (!values || values.length < 2) return;
    var maxVal = Math.max.apply(null, values);
    var minVal = Math.min.apply(null, values);
    var range = maxVal - minVal || 1;
    ctx.strokeStyle = color || '#00ff41';
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    for (var i = 0; i < values.length; i++) {
      var x = (i / (values.length - 1)) * w;
      var y = h - ((values[i] - minVal) / range) * (h - 4) - 2;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.stroke();
    // Fill under the line
    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    var grad = ctx.createLinearGradient(0, 0, 0, h);
    var r = parseInt((color || '#00ff41').slice(1, 3), 16);
    var g = parseInt((color || '#00ff41').slice(3, 5), 16);
    var b = parseInt((color || '#00ff41').slice(5, 7), 16);
    grad.addColorStop(0, 'rgba(' + r + ',' + g + ',' + b + ',0.2)');
    grad.addColorStop(1, 'rgba(' + r + ',' + g + ',' + b + ',0.02)');
    ctx.fillStyle = grad;
    ctx.fill();
  }

  function drawBarChart(canvasId, labels, values, colors) {
    var canvas = main.querySelector('#' + canvasId);
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var w = canvas.width;
    var h = canvas.height;
    ctx.fillStyle = '#0a0e17';
    ctx.fillRect(0, 0, w, h);
    if (!values || values.length === 0) return;
    var maxVal = Math.max.apply(null, values) || 1;
    var barWidth = (w - 40) / values.length - 4;
    var chartH = h - 30;
    for (var i = 0; i < values.length; i++) {
      var barH = (values[i] / maxVal) * (chartH - 10);
      var bx = 30 + i * (barWidth + 4);
      var by = chartH - barH;
      var color = colors ? colors[i % colors.length] : '#00ff41';
      ctx.fillStyle = color;
      ctx.fillRect(bx, by, barWidth, barH);
      // Label below
      ctx.font = '8px monospace';
      ctx.fillStyle = '#8892b0';
      ctx.textAlign = 'center';
      ctx.fillText(labels[i] || '', bx + barWidth / 2, h - 5);
      // Value above
      ctx.fillStyle = '#ccd6f6';
      ctx.fillText(String(values[i]), bx + barWidth / 2, by - 4);
    }
    ctx.textAlign = 'left';
  }

  function formatNumber(n) {
    if (n === null || n === undefined) return '0';
    var parts = String(Math.round(n)).split('.');
    var intPart = parts[0];
    var isNeg = false;
    if (intPart.charAt(0) === '-') {
      isNeg = true;
      intPart = intPart.slice(1);
    }
    var result = '';
    var count = 0;
    for (var i = intPart.length - 1; i >= 0; i--) {
      if (count > 0 && count % 3 === 0) result = ',' + result;
      result = intPart.charAt(i) + result;
      count++;
    }
    if (isNeg) result = '-' + result;
    if (parts.length > 1) result += '.' + parts[1];
    return result;
  }

  function formatCurrency(n) {
    if (n >= 1e12) return '$' + (n / 1e12).toFixed(1) + 'T';
    if (n >= 1e9) return '$' + (n / 1e9).toFixed(1) + 'B';
    if (n >= 1e6) return '$' + (n / 1e6).toFixed(1) + 'M';
    if (n >= 1e3) return '$' + (n / 1e3).toFixed(1) + 'K';
    return '$' + formatNumber(n);
  }

  function severityColor(severity) {
    var map = {
      critical: '#ff1744',
      high: '#ff9100',
      medium: '#ffd600',
      low: '#00e676',
      info: '#448aff',
      CRITICAL: '#ff1744',
      HIGH: '#ff9100',
      MEDIUM: '#ffd600',
      LOW: '#00e676',
      INFO: '#448aff'
    };
    return map[severity] || '#8892b0';
  }

  function statusDot(status) {
    return '<span class="pm-status-dot pm-status-' + esc(status) + '"></span>';
  }

  function makeProgressBar(value, max, color) {
    var pct = max > 0 ? Math.min(100, Math.round((value / max) * 100)) : 0;
    return '<div class="pm-progress-bar">' +
      '<div class="pm-progress-fill" style="width:' + pct + '%;background:' + (color || '#00ff41') + '"></div>' +
      '<span class="pm-progress-label">' + pct + '%</span>' +
      '</div>';
  }

  function makeTable(headers, rows) {
    var html = '<div class="pm-table-wrap"><table class="pm-table"><thead><tr>';
    for (var i = 0; i < headers.length; i++) {
      html += '<th>' + esc(headers[i]) + '</th>';
    }
    html += '</tr></thead><tbody>';
    for (var r = 0; r < rows.length; r++) {
      html += '<tr>';
      for (var c = 0; c < rows[r].length; c++) {
        var cell = rows[r][c];
        if (typeof cell === 'object' && cell !== null && cell.html) {
          html += '<td>' + cell.html + '</td>';
        } else {
          html += '<td>' + esc(cell) + '</td>';
        }
      }
      html += '</tr>';
    }
    html += '</tbody></table></div>';
    return html;
  }

  function makeBadge(text, color) {
    return '<span class="pm-badge" style="background:' + (color || '#1a1a2e') + ';border:1px solid ' + (color || '#333') + '">' + esc(text) + '</span>';
  }

  function makeBadgeHtml(text, color) {
    return '<span class="pm-badge" style="background:' + (color || '#1a1a2e') + ';border:1px solid ' + (color || '#333') + '">' + text + '</span>';
  }

  function makeMetric(label, value, unit) {
    return '<div class="pm-metric">' +
      '<div class="pm-metric-value">' + esc(value) + (unit ? '<span class="pm-metric-unit">' + esc(unit) + '</span>' : '') + '</div>' +
      '<div class="pm-metric-label">' + esc(label) + '</div>' +
      '</div>';
  }

  function makeKPI(label, value, trend, trendUp) {
    var arrow = trendUp ? '&#9650;' : '&#9660;';
    var trendColor = trendUp ? '#00e676' : '#ff1744';
    return '<div class="pm-kpi">' +
      '<div class="pm-kpi-value">' + esc(value) + '</div>' +
      '<div class="pm-kpi-trend" style="color:' + trendColor + '">' + arrow + ' ' + esc(trend) + '</div>' +
      '<div class="pm-kpi-label">' + esc(label) + '</div>' +
      '</div>';
  }

  function makeTimeline(events) {
    var html = '<div class="pm-timeline">';
    for (var i = 0; i < events.length; i++) {
      var ev = events[i];
      var color = ev.color || '#00ff41';
      html += '<div class="pm-timeline-item">' +
        '<div class="pm-timeline-dot" style="background:' + color + '"></div>' +
        '<div class="pm-timeline-connector"></div>' +
        '<div class="pm-timeline-content">' +
        '<div class="pm-timeline-time">' + esc(ev.time) + '</div>' +
        '<div class="pm-timeline-label">' + esc(ev.label) + '</div>' +
        (ev.detail ? '<div class="pm-timeline-detail">' + esc(ev.detail) + '</div>' : '') +
        '</div>' +
        '</div>';
    }
    html += '</div>';
    return html;
  }

  function makeStatRow(items) {
    var html = '<div class="pm-stat-row">';
    for (var i = 0; i < items.length; i++) {
      var item = items[i];
      html += '<div class="pm-stat-box">' +
        '<div class="pm-stat-value" style="color:' + (item.color || '#00ff41') + '">' + esc(item.value) + '</div>' +
        '<div class="pm-stat-label">' + esc(item.label) + '</div>' +
        '</div>';
    }
    html += '</div>';
    return html;
  }

  function makeCard(title, content, headerColor) {
    return '<div class="pm-card">' +
      '<div class="pm-card-header" style="border-left-color:' + (headerColor || '#00ff41') + '">' + esc(title) + '</div>' +
      '<div class="pm-card-body">' + content + '</div>' +
      '</div>';
  }

  function makeSelect(id, options, selected) {
    var html = '<select class="pm-select" id="' + id + '">';
    for (var i = 0; i < options.length; i++) {
      var opt = options[i];
      var val = typeof opt === 'object' ? opt.value : opt;
      var label = typeof opt === 'object' ? opt.label : opt;
      html += '<option value="' + esc(val) + '"' + (val === selected ? ' selected' : '') + '>' + esc(label) + '</option>';
    }
    html += '</select>';
    return html;
  }

  function makeButton(label, id, style) {
    return '<button class="pm-btn' + (style ? ' pm-btn-' + style : '') + '" id="' + id + '">' + esc(label) + '</button>';
  }

  function showModal(title, content) {
    var overlay = document.createElement('div');
    overlay.className = 'pm-modal-overlay';
    overlay.id = 'pm-modal-overlay';
    overlay.innerHTML = '<div class="pm-modal">' +
      '<div class="pm-modal-header">' +
      '<span class="pm-modal-title">' + esc(title) + '</span>' +
      '<button class="pm-modal-close" id="pm-modal-close-btn">&times;</button>' +
      '</div>' +
      '<div class="pm-modal-body">' + content + '</div>' +
      '</div>';
    main.appendChild(overlay);
    var closeBtn = overlay.querySelector('#pm-modal-close-btn');
    if (closeBtn) {
      closeBtn.addEventListener('click', function() { hideModal(); });
    }
    overlay.addEventListener('click', function(e) {
      if (e.target === overlay) hideModal();
    });
  }

  function hideModal() {
    var overlay = main.querySelector('#pm-modal-overlay');
    if (overlay) overlay.remove();
  }

  function generateAlerts(count) {
    var types = ['INTRUSION', 'MALWARE', 'EXFILTRATION', 'RECON', 'LATERAL_MOVE', 'PRIVILEGE_ESC', 'C2_BEACON', 'ANOMALY', 'POLICY_VIOLATION', 'BRUTE_FORCE'];
    var severities = ['critical', 'high', 'medium', 'low', 'info'];
    var sources = ['NIDS', 'HIDS', 'SIEM', 'EDR', 'WAF', 'FW', 'PROXY', 'DNS', 'EMAIL_GW', 'DLP'];
    var alerts = [];
    for (var i = 0; i < count; i++) {
      var now = new Date(Date.now() - Math.floor(Math.random() * 3600000));
      alerts.push({
        id: 'ALT-' + generateId().slice(0, 8),
        type: types[Math.floor(Math.random() * types.length)],
        severity: severities[Math.floor(Math.random() * severities.length)],
        source: sources[Math.floor(Math.random() * sources.length)],
        timestamp: formatTimestamp(now),
        message: 'Automated alert generated by PROMETHEUS threat engine',
        target: '10.' + Math.floor(Math.random() * 255) + '.' + Math.floor(Math.random() * 255) + '.' + Math.floor(Math.random() * 255),
        acknowledged: Math.random() > 0.6
      });
    }
    return alerts;
  }

  function randomSparkData(count, min, max) {
    var data = [];
    var val = min + Math.random() * (max - min);
    for (var i = 0; i < count; i++) {
      val += (Math.random() - 0.48) * ((max - min) * 0.1);
      if (val < min) val = min + Math.random() * 5;
      if (val > max) val = max - Math.random() * 5;
      data.push(Math.round(val * 10) / 10);
    }
    return data;
  }

  function getTimeInZone(offsetHours) {
    var now = new Date();
    var utc = now.getTime() + now.getTimezoneOffset() * 60000;
    var d = new Date(utc + offsetHours * 3600000);
    var h = String(d.getHours());
    if (h.length < 2) h = '0' + h;
    var m = String(d.getMinutes());
    if (m.length < 2) m = '0' + m;
    var s = String(d.getSeconds());
    if (s.length < 2) s = '0' + s;
    return h + ':' + m + ':' + s;
  }

  function truncate(str, len) {
    if (!str) return '';
    str = String(str);
    if (str.length <= len) return str;
    return str.slice(0, len - 3) + '...';
  }

  function hashString(str) {
    var hash = 0;
    for (var i = 0; i < str.length; i++) {
      var ch = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + ch;
      hash = hash & hash;
    }
    return Math.abs(hash);
  }

  // ===========================================================================
  // MAIN RENDER FUNCTION
  // ===========================================================================



  // =========================================================================
  // TAB 1: COMMAND CENTER
  // =========================================================================

  var defconColors = ['#00ff00', '#00cc44', '#ffcc00', '#ff6600', '#ff0000'];
  var defconLabels = ['NORMAL', 'INCREASED', 'ELEVATED', 'HIGH', 'MAXIMUM'];
  var sparkData = { cpu: [], mem: [], disk: [], net: [] };
  var alertMessages = [
    'Unauthorized access attempt detected on perimeter firewall',
    'Anomalous DNS exfiltration pattern identified from subnet 10.0.3.0/24',
    'Brute force attack against SSH gateway - 847 attempts in 60s',
    'Suspicious lateral movement detected: ADMIN-WS01 -> DC-PRIMARY',
    'Malware signature match: SUNBURST variant on endpoint EPT-0442',
    'Certificate transparency log anomaly for *.gov.mil domain',
    'BGP route hijack attempt detected for AS64512 prefix',
    'Phishing campaign targeting executive staff - 23 emails intercepted',
    'ICS/SCADA protocol anomaly on power grid control network',
    'Credential stuffing attack on VPN gateway - source: 185.220.x.x',
    'Ransomware beacon activity detected from quarantined segment',
    'Supply chain compromise indicator: tampered package checksum',
    'Nation-state APT activity correlated across 3 intelligence feeds',
    'Zero-day exploit attempt against Exchange server CVE-2026-XXXX',
    'Data exfiltration alert: 2.3GB upload to cloud storage endpoint',
    'Insider threat indicator: off-hours access to classified repository',
    'DDoS volumetric attack ramping - current: 340Gbps ingress',
    'Unauthorized firmware modification detected on network switch',
    'Tor exit node communication from internal host 10.0.7.88',
    'SIGINT intercept correlation: adversary C2 channel active',
    'Watering hole attack detected on partner organization portal',
    'Memory-resident implant detected via behavioral analysis',
    'Abnormal Kerberos ticket request pattern - possible Golden Ticket',
    'Critical infrastructure SCADA command injection attempt blocked',
    'Geofencing alert: classified device detected outside secure zone',
    'Shadow IT cloud service discovered with sensitive data exposure',
    'USB device policy violation on air-gapped network segment',
    'Satellite communication link degradation - possible jamming',
    'Electromagnetic emanation anomaly near TEMPEST-rated facility',
    'Social engineering attempt via phone against help desk staff'
  ];

  var domainStatuses = [
    { name: 'Power Grid', status: 'green', text: 'All systems nominal' },
    { name: 'Water Systems', status: 'green', text: 'Monitoring active' },
    { name: 'Telecommunications', status: 'yellow', text: 'Elevated traffic' },
    { name: 'Transportation', status: 'green', text: 'Normal operations' },
    { name: 'Financial Services', status: 'yellow', text: 'DDoS mitigation active' },
    { name: 'Healthcare', status: 'green', text: 'Protected' },
    { name: 'Government Networks', status: 'red', text: 'Active intrusion' },
    { name: 'Energy Sector', status: 'green', text: 'Secure' },
    { name: 'Emergency Services', status: 'green', text: 'Operational' },
    { name: 'Defense Systems', status: 'yellow', text: 'Heightened posture' },
    { name: 'Intelligence Networks', status: 'green', text: 'Encrypted channels OK' },
    { name: 'Diplomatic Comms', status: 'green', text: 'COMSEC verified' }
  ];

  var activeMissions = [
    { codename: 'IRON SENTINEL', status: 'ACTIVE', progress: 72, type: 'Defensive' },
    { codename: 'SHADOW HARVEST', status: 'ACTIVE', progress: 45, type: 'Collection' },
    { codename: 'CRIMSON TIDE', status: 'STANDBY', progress: 10, type: 'Offensive' },
    { codename: 'GHOST PROTOCOL', status: 'ACTIVE', progress: 88, type: 'Counter-Intel' },
    { codename: 'DEEP CURRENT', status: 'PLANNING', progress: 5, type: 'Reconnaissance' }
  ];

  function drawDefconGauge() {
    var canvas = main.querySelector('#pm-defcon-canvas');
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var w = canvas.width;
    var h = canvas.height;
    var cx = w / 2;
    var cy = h / 2;
    var r = Math.min(cx, cy) - 20;
    var level = state.defcon;
    var color = defconColors[level - 1] || '#ff0000';

    ctx.clearRect(0, 0, w, h);

    // Outer ring background
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.strokeStyle = '#1a2a1a';
    ctx.lineWidth = 18;
    ctx.stroke();

    // Colored arc based on DEFCON level
    var arcEnd = (level / 5) * Math.PI * 2;
    ctx.beginPath();
    ctx.arc(cx, cy, r, -Math.PI / 2, -Math.PI / 2 + arcEnd);
    ctx.strokeStyle = color;
    ctx.lineWidth = 18;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Pulsing glow
    var pulse = 0.4 + 0.6 * Math.abs(Math.sin(Date.now() / 500));
    ctx.beginPath();
    ctx.arc(cx, cy, r, -Math.PI / 2, -Math.PI / 2 + arcEnd);
    ctx.strokeStyle = color.replace(')', ',' + (pulse * 0.3) + ')').replace('rgb', 'rgba').replace('#', '');
    ctx.lineWidth = 28;
    ctx.stroke();

    // Inner glow ring
    ctx.beginPath();
    ctx.arc(cx, cy, r - 20, 0, Math.PI * 2);
    ctx.strokeStyle = 'rgba(' + hexToRgb(color) + ', 0.15)';
    ctx.lineWidth = 2;
    ctx.stroke();

    // DEFCON number
    ctx.font = 'bold 64px monospace';
    ctx.fillStyle = color;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(String(level), cx, cy - 10);

    // Label
    ctx.font = '14px monospace';
    ctx.fillStyle = '#88aa88';
    ctx.fillText('DEFCON', cx, cy + 35);

    // Status label
    ctx.font = 'bold 12px monospace';
    ctx.fillStyle = color;
    ctx.fillText(defconLabels[level - 1] || '', cx, cy + 52);
  }

  function hexToRgb(hex) {
    if (hex.charAt(0) === '#') {
      var bigint = parseInt(hex.slice(1), 16);
      return ((bigint >> 16) & 255) + ',' + ((bigint >> 8) & 255) + ',' + (bigint & 255);
    }
    return '136,170,136';
  }

  function drawThreatMap() {
    var canvas = main.querySelector('#pm-threat-map-canvas');
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var w = canvas.width;
    var h = canvas.height;

    ctx.clearRect(0, 0, w, h);

    // Dark background with grid
    ctx.fillStyle = '#0a0f0a';
    ctx.fillRect(0, 0, w, h);

    // Grid lines
    ctx.strokeStyle = '#0d1a0d';
    ctx.lineWidth = 0.5;
    var gridSize = 30;
    var gx, gy;
    for (gx = 0; gx < w; gx += gridSize) {
      ctx.beginPath();
      ctx.moveTo(gx, 0);
      ctx.lineTo(gx, h);
      ctx.stroke();
    }
    for (gy = 0; gy < h; gy += gridSize) {
      ctx.beginPath();
      ctx.moveTo(0, gy);
      ctx.lineTo(w, gy);
      ctx.stroke();
    }

    // Simplified continental outlines (polylines)
    ctx.strokeStyle = '#1a3a1a';
    ctx.lineWidth = 1.5;

    // North America
    drawContinent(ctx, w, h, [
      [0.12,0.18],[0.14,0.15],[0.18,0.13],[0.22,0.14],[0.25,0.18],
      [0.28,0.22],[0.30,0.28],[0.28,0.35],[0.25,0.38],[0.22,0.42],
      [0.18,0.45],[0.15,0.42],[0.13,0.38],[0.12,0.32],[0.10,0.25]
    ]);

    // South America
    drawContinent(ctx, w, h, [
      [0.22,0.50],[0.25,0.48],[0.28,0.52],[0.30,0.58],[0.29,0.65],
      [0.27,0.72],[0.25,0.78],[0.23,0.82],[0.21,0.78],[0.20,0.72],
      [0.19,0.62],[0.20,0.55]
    ]);

    // Europe
    drawContinent(ctx, w, h, [
      [0.42,0.18],[0.45,0.15],[0.48,0.14],[0.52,0.16],[0.54,0.20],
      [0.52,0.25],[0.50,0.30],[0.48,0.32],[0.45,0.30],[0.43,0.26],
      [0.42,0.22]
    ]);

    // Africa
    drawContinent(ctx, w, h, [
      [0.44,0.35],[0.48,0.33],[0.52,0.35],[0.55,0.42],[0.56,0.50],
      [0.54,0.58],[0.52,0.65],[0.50,0.70],[0.47,0.68],[0.45,0.62],
      [0.43,0.55],[0.42,0.48],[0.43,0.42]
    ]);

    // Asia
    drawContinent(ctx, w, h, [
      [0.55,0.14],[0.60,0.12],[0.65,0.14],[0.70,0.16],[0.75,0.20],
      [0.80,0.22],[0.82,0.28],[0.80,0.32],[0.78,0.35],[0.75,0.38],
      [0.70,0.40],[0.65,0.38],[0.60,0.35],[0.58,0.30],[0.55,0.25],
      [0.54,0.20]
    ]);

    // Australia
    drawContinent(ctx, w, h, [
      [0.78,0.58],[0.82,0.55],[0.86,0.57],[0.88,0.62],[0.86,0.68],
      [0.83,0.72],[0.80,0.70],[0.78,0.65],[0.77,0.62]
    ]);

    // Plot threat sources from APT_GROUPS
    var now = Date.now();
    var aptCoords = [
      { lat: 0.20, lon: 0.72, color: '#ff0000', label: 'CN' },   // China
      { lat: 0.22, lon: 0.58, color: '#ff4400', label: 'RU' },   // Russia
      { lat: 0.28, lon: 0.55, color: '#ff6600', label: 'IR' },   // Iran
      { lat: 0.25, lon: 0.62, color: '#ffaa00', label: 'KP' },   // North Korea
      { lat: 0.30, lon: 0.48, color: '#ff8800', label: 'PK' },   // Pakistan
      { lat: 0.42, lon: 0.55, color: '#ccaa00', label: 'NG' },   // Nigeria
      { lat: 0.38, lon: 0.22, color: '#ff2200', label: 'BR' },   // Brazil
      { lat: 0.32, lon: 0.52, color: '#ff5500', label: 'SY' }    // Syria
    ];

    var ai;
    for (ai = 0; ai < aptCoords.length; ai++) {
      var apt = aptCoords[ai];
      var px = apt.lon * w;
      var py = apt.lat * h;
      var blink = Math.sin(now / 400 + ai * 1.3);

      // Pulse ring
      if (blink > 0) {
        ctx.beginPath();
        ctx.arc(px, py, 8 + blink * 6, 0, Math.PI * 2);
        ctx.strokeStyle = apt.color.replace(')', ',0.3)').replace('#', 'rgba(');
        ctx.strokeStyle = 'rgba(' + hexToRgb(apt.color) + ',' + (0.2 + blink * 0.3) + ')';
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      // Core dot
      ctx.beginPath();
      ctx.arc(px, py, 4, 0, Math.PI * 2);
      ctx.fillStyle = apt.color;
      ctx.fill();

      // Label
      ctx.font = '9px monospace';
      ctx.fillStyle = '#88aa88';
      ctx.fillText(apt.label, px + 8, py + 3);
    }

    // Draw connection lines between threat sources and US targets
    var usx = 0.20 * w;
    var usy = 0.30 * h;
    ctx.setLineDash([4, 4]);
    for (ai = 0; ai < aptCoords.length; ai++) {
      var bv = Math.sin(now / 600 + ai * 0.8);
      if (bv > 0.3) {
        ctx.beginPath();
        ctx.moveTo(aptCoords[ai].lon * w, aptCoords[ai].lat * h);
        ctx.lineTo(usx, usy);
        ctx.strokeStyle = 'rgba(' + hexToRgb(aptCoords[ai].color) + ',0.15)';
        ctx.lineWidth = 1;
        ctx.stroke();
      }
    }
    ctx.setLineDash([]);
  }

  function drawContinent(ctx, w, h, points) {
    if (points.length < 2) return;
    ctx.beginPath();
    ctx.moveTo(points[0][1] * w, points[0][0] * h);
    var pi;
    for (pi = 1; pi < points.length; pi++) {
      ctx.lineTo(points[pi][1] * w, points[pi][0] * h);
    }
    ctx.closePath();
    ctx.stroke();
    ctx.fillStyle = 'rgba(20, 50, 20, 0.3)';
    ctx.fill();
  }

  function drawSparkline(canvasId, data, color) {
    var canvas = main.querySelector('#' + canvasId);
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var w = canvas.width;
    var h = canvas.height;

    ctx.clearRect(0, 0, w, h);

    if (data.length < 2) return;

    // Fill background
    ctx.fillStyle = 'rgba(' + hexToRgb(color) + ', 0.05)';
    ctx.fillRect(0, 0, w, h);

    // Draw line
    var maxVal = Math.max.apply(null, data);
    var minVal = Math.min.apply(null, data);
    var range = maxVal - minVal || 1;
    var step = w / (data.length - 1);

    ctx.beginPath();
    var di;
    for (di = 0; di < data.length; di++) {
      var x = di * step;
      var y = h - ((data[di] - minVal) / range) * (h - 4) - 2;
      if (di === 0) { ctx.moveTo(x, y); } else { ctx.lineTo(x, y); }
    }
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Fill area under
    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fillStyle = 'rgba(' + hexToRgb(color) + ', 0.1)';
    ctx.fill();

    // Current value text
    ctx.font = '10px monospace';
    ctx.fillStyle = color;
    ctx.textAlign = 'right';
    ctx.fillText(data[data.length - 1] + '%', w - 4, 12);
  }

  function generateAlert() {
    var severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    var sevWeights = [0.08, 0.18, 0.35, 0.25, 0.14];
    var rand = Math.random();
    var cumulative = 0;
    var severity = 'INFO';
    var si;
    for (si = 0; si < sevWeights.length; si++) {
      cumulative += sevWeights[si];
      if (rand <= cumulative) { severity = severities[si]; break; }
    }
    var msg = alertMessages[Math.floor(Math.random() * alertMessages.length)];
    var now = new Date();
    var ts = String(now.getUTCHours()).replace(/^(\d)$/, '0$1') + ':' +
             String(now.getUTCMinutes()).replace(/^(\d)$/, '0$1') + ':' +
             String(now.getUTCSeconds()).replace(/^(\d)$/, '0$1') + 'Z';
    return { time: ts, severity: severity, message: msg, id: 'ALT-' + Math.floor(Math.random() * 99999) };
  }

  function addAlert(alert) {
    state.alerts.unshift(alert);
    if (state.alerts.length > 50) state.alerts.length = 50;
    var feed = main.querySelector('#pm-alert-feed');
    if (!feed) return;
    var sevColorMap = { CRITICAL: '#ff0040', HIGH: '#ff6600', MEDIUM: '#ffcc00', LOW: '#00cc66', INFO: '#4488ff' };
    var col = sevColorMap[alert.severity] || '#4488ff';
    var row = '<div class="pm-alert-row" style="border-left:3px solid ' + col + '">' +
      '<span class="pm-alert-time">' + esc(alert.time) + '</span>' +
      '<span class="pm-alert-sev" style="background:' + col + '">' + esc(alert.severity) + '</span>' +
      '<span class="pm-alert-id">' + esc(alert.id) + '</span>' +
      '<span class="pm-alert-msg">' + esc(alert.message) + '</span>' +
      '</div>';
    feed.innerHTML = row + feed.innerHTML;
    // Trim DOM
    var rows = feed.querySelectorAll('.pm-alert-row');
    var ri;
    for (ri = 20; ri < rows.length; ri++) {
      rows[ri].parentNode.removeChild(rows[ri]);
    }
  }

  function formatTZ(offset, label) {
    var now = new Date();
    var utc = now.getTime() + now.getTimezoneOffset() * 60000;
    var target = new Date(utc + offset * 3600000);
    var hh = String(target.getHours()).replace(/^(\d)$/, '0$1');
    var mm = String(target.getMinutes()).replace(/^(\d)$/, '0$1');
    var ss = String(target.getSeconds()).replace(/^(\d)$/, '0$1');
    return hh + ':' + mm + ':' + ss;
  }

  function renderCommandCenter() {
    var html = '';

    // Top row: DEFCON gauge + Threat Map
    html += '<div class="pm-cc-top">';

    // DEFCON gauge panel
    html += '<div class="pm-panel pm-defcon-panel">';
    html += '<div class="pm-panel-hdr">DEFENSE CONDITION</div>';
    html += '<canvas id="pm-defcon-canvas" width="220" height="220"></canvas>';
    html += '<div class="pm-defcon-btns">';
    var di;
    for (di = 1; di <= 5; di++) {
      var sel = (state.defcon === di) ? ' pm-defcon-btn-active' : '';
      html += '<button class="pm-defcon-btn' + sel + '" data-level="' + di + '">' + di + '</button>';
    }
    html += '</div>';
    html += '</div>';

    // Global threat map
    html += '<div class="pm-panel pm-map-panel">';
    html += '<div class="pm-panel-hdr">GLOBAL THREAT MAP</div>';
    html += '<canvas id="pm-threat-map-canvas" width="700" height="320"></canvas>';
    html += '</div>';

    html += '</div>'; // .pm-cc-top

    // Second row: Alert Feed + Domain Status
    html += '<div class="pm-cc-mid">';

    // Live alert feed
    html += '<div class="pm-panel pm-alerts-panel">';
    html += '<div class="pm-panel-hdr">EXERCISE ALERT FEED <span class="pm-alert-count">' + state.alerts.length + ' EVENTS</span></div>';
    html += '<div id="pm-alert-feed" class="pm-alert-feed">';
    var sevColorMap = { CRITICAL: '#ff0040', HIGH: '#ff6600', MEDIUM: '#ffcc00', LOW: '#00cc66', INFO: '#4488ff' };
    var ai;
    for (ai = 0; ai < Math.min(state.alerts.length, 20); ai++) {
      var a = state.alerts[ai];
      var ac = sevColorMap[a.severity] || '#4488ff';
      html += '<div class="pm-alert-row" style="border-left:3px solid ' + ac + '">';
      html += '<span class="pm-alert-time">' + esc(a.time) + '</span>';
      html += '<span class="pm-alert-sev" style="background:' + ac + '">' + esc(a.severity) + '</span>';
      html += '<span class="pm-alert-id">' + esc(a.id) + '</span>';
      html += '<span class="pm-alert-msg">' + esc(a.message) + '</span>';
      html += '</div>';
    }
    html += '</div>';
    html += '</div>';

    // Domain status grid
    html += '<div class="pm-panel pm-domain-panel">';
    html += '<div class="pm-panel-hdr">CRITICAL INFRASTRUCTURE STATUS</div>';
    html += '<div class="pm-domain-grid">';
    var dsi;
    for (dsi = 0; dsi < domainStatuses.length; dsi++) {
      var ds = domainStatuses[dsi];
      var dotColor = ds.status === 'green' ? '#00ff66' : (ds.status === 'yellow' ? '#ffcc00' : '#ff0040');
      html += '<div class="pm-domain-card">';
      html += '<div class="pm-domain-dot" style="background:' + dotColor + ';box-shadow:0 0 6px ' + dotColor + '"></div>';
      html += '<div class="pm-domain-info">';
      html += '<div class="pm-domain-name">' + esc(ds.name) + '</div>';
      html += '<div class="pm-domain-text" style="color:' + dotColor + '">' + esc(ds.text) + '</div>';
      html += '</div>';
      html += '</div>';
    }
    html += '</div>';
    html += '</div>';

    html += '</div>'; // .pm-cc-mid

    // Third row: Missions + System Health + Clocks
    html += '<div class="pm-cc-bot">';

    // Active missions
    html += '<div class="pm-panel pm-missions-panel">';
    html += '<div class="pm-panel-hdr">ACTIVE MISSIONS</div>';
    var mi;
    for (mi = 0; mi < activeMissions.length; mi++) {
      var m = activeMissions[mi];
      var mColor = m.status === 'ACTIVE' ? '#00ff66' : (m.status === 'STANDBY' ? '#ffcc00' : '#4488ff');
      html += '<div class="pm-mission-row">';
      html += '<div class="pm-mission-top">';
      html += '<span class="pm-mission-name">' + esc(m.codename) + '</span>';
      html += '<span class="pm-mission-type">' + esc(m.type) + '</span>';
      html += '<span class="pm-mission-status" style="color:' + mColor + '">' + esc(m.status) + '</span>';
      html += '</div>';
      html += '<div class="pm-progress-bar">';
      html += '<div class="pm-progress-fill" style="width:' + m.progress + '%;background:' + mColor + '"></div>';
      html += '</div>';
      html += '<div class="pm-mission-pct">' + m.progress + '% COMPLETE</div>';
      html += '</div>';
    }
    html += '</div>';

    // System health sparklines
    html += '<div class="pm-panel pm-health-panel">';
    html += '<div class="pm-panel-hdr">SYSTEM HEALTH</div>';
    var healthItems = [
      { id: 'pm-spark-cpu', label: 'CPU', color: '#00ff66', key: 'cpu' },
      { id: 'pm-spark-mem', label: 'MEMORY', color: '#4488ff', key: 'mem' },
      { id: 'pm-spark-disk', label: 'DISK I/O', color: '#ffcc00', key: 'disk' },
      { id: 'pm-spark-net', label: 'NETWORK', color: '#ff6600', key: 'net' }
    ];
    var hi;
    for (hi = 0; hi < healthItems.length; hi++) {
      var hItem = healthItems[hi];
      html += '<div class="pm-spark-row">';
      html += '<span class="pm-spark-label">' + esc(hItem.label) + '</span>';
      html += '<canvas id="' + hItem.id + '" width="200" height="40" class="pm-spark-canvas"></canvas>';
      html += '</div>';
    }
    html += '</div>';

    // Multi-timezone clocks
    html += '<div class="pm-panel pm-clocks-panel">';
    html += '<div class="pm-panel-hdr">OPERATIONAL CLOCKS</div>';
    var zones = [
      { label: 'UTC', offset: 0, id: 'pm-clock-utc' },
      { label: 'WASHINGTON DC', offset: -5, id: 'pm-clock-dc' },
      { label: 'LONDON', offset: 0, id: 'pm-clock-lon' },
      { label: 'MOSCOW', offset: 3, id: 'pm-clock-msk' },
      { label: 'BEIJING', offset: 8, id: 'pm-clock-bj' },
      { label: 'TEHRAN', offset: 3.5, id: 'pm-clock-thr' }
    ];
    html += '<div class="pm-clocks-grid">';
    var zi;
    for (zi = 0; zi < zones.length; zi++) {
      var z = zones[zi];
      html += '<div class="pm-clock-item">';
      html += '<div class="pm-clock-label">' + esc(z.label) + '</div>';
      html += '<div class="pm-clock-time" id="' + z.id + '">' + formatTZ(z.offset) + '</div>';
      html += '</div>';
    }
    html += '</div>';
    html += '</div>';

    html += '</div>'; // .pm-cc-bot

    return html;
  }

  function bindCommandCenter() {
    // DEFCON canvas
    drawDefconGauge();

    // Threat map
    drawThreatMap();
    var mapInterval = setInterval(function() {
      if (state.activeTab !== 'command') return;
      drawThreatMap();
    }, 800);
    state.intervals.push(mapInterval);

    // DEFCON buttons
    var defBtns = main.querySelectorAll('.pm-defcon-btn');
    var bi;
    for (bi = 0; bi < defBtns.length; bi++) {
      defBtns[bi].addEventListener('click', function() {
        state.defcon = parseInt(this.getAttribute('data-level'), 10);
        saveState();
        // Update button active state
        var allBtns = main.querySelectorAll('.pm-defcon-btn');
        var ab;
        for (ab = 0; ab < allBtns.length; ab++) {
          allBtns[ab].classList.remove('pm-defcon-btn-active');
        }
        this.classList.add('pm-defcon-btn-active');
        drawDefconGauge();
      });
    }

    // Alert generation
    var alertInterval = setInterval(function() {
      if (state.activeTab !== 'command') return;
      var alert = generateAlert();
      addAlert(alert);
    }, 4000);
    state.intervals.push(alertInterval);

    // Sparkline data generation and drawing
    function updateSparklines() {
      var keys = ['cpu', 'mem', 'disk', 'net'];
      var ranges = [[30, 85], [40, 78], [10, 60], [15, 95]];
      var colors = ['#00ff66', '#4488ff', '#ffcc00', '#ff6600'];
      var ids = ['pm-spark-cpu', 'pm-spark-mem', 'pm-spark-disk', 'pm-spark-net'];
      var ki;
      for (ki = 0; ki < keys.length; ki++) {
        var arr = sparkData[keys[ki]];
        var lo = ranges[ki][0];
        var hi2 = ranges[ki][1];
        var lastVal = arr.length > 0 ? arr[arr.length - 1] : (lo + hi2) / 2;
        var newVal = Math.max(lo, Math.min(hi2, lastVal + (Math.random() - 0.5) * 12));
        arr.push(Math.round(newVal));
        if (arr.length > 40) arr.shift();
        drawSparkline(ids[ki], arr, colors[ki]);
      }
    }
    updateSparklines();
    var sparkInterval = setInterval(function() {
      if (state.activeTab !== 'command') return;
      updateSparklines();
    }, 2000);
    state.intervals.push(sparkInterval);

    // Clock updates
    function updateClocks() {
      var zones2 = [
        { offset: 0, id: 'pm-clock-utc' },
        { offset: -5, id: 'pm-clock-dc' },
        { offset: 0, id: 'pm-clock-lon' },
        { offset: 3, id: 'pm-clock-msk' },
        { offset: 8, id: 'pm-clock-bj' },
        { offset: 3.5, id: 'pm-clock-thr' }
      ];
      var ci;
      for (ci = 0; ci < zones2.length; ci++) {
        var el = main.querySelector('#' + zones2[ci].id);
        if (el) el.textContent = formatTZ(zones2[ci].offset);
      }
    }
    var clockInterval = setInterval(function() {
      if (state.activeTab !== 'command') return;
      updateClocks();
    }, 1000);
    state.intervals.push(clockInterval);

    // Initial seed of alerts
    if (state.alerts.length === 0) {
      var si;
      for (si = 0; si < 8; si++) {
        var seedAlert = generateAlert();
        state.alerts.push(seedAlert);
      }
      var feed = main.querySelector('#pm-alert-feed');
      if (feed) {
        var feedHtml = '';
        var sevColorMap2 = { CRITICAL: '#ff0040', HIGH: '#ff6600', MEDIUM: '#ffcc00', LOW: '#00cc66', INFO: '#4488ff' };
        var fi;
        for (fi = 0; fi < state.alerts.length; fi++) {
          var fa = state.alerts[fi];
          var fc = sevColorMap2[fa.severity] || '#4488ff';
          feedHtml += '<div class="pm-alert-row" style="border-left:3px solid ' + fc + '">';
          feedHtml += '<span class="pm-alert-time">' + esc(fa.time) + '</span>';
          feedHtml += '<span class="pm-alert-sev" style="background:' + fc + '">' + esc(fa.severity) + '</span>';
          feedHtml += '<span class="pm-alert-id">' + esc(fa.id) + '</span>';
          feedHtml += '<span class="pm-alert-msg">' + esc(fa.message) + '</span>';
          feedHtml += '</div>';
        }
        feed.innerHTML = feedHtml;
      }
    }
  }

  // =========================================================================
  // TAB 2: DIGITAL TWIN
  // =========================================================================

  var twinState = {
    selectedSector: null,
    selectedNode: null,
    simRunning: false,
    simResults: null,
    searchQuery: ''
  };

  function getSectorNodes(sectorName) {
    var result = [];
    var ni;
    for (ni = 0; ni < INFRA_NODES.length; ni++) {
      if (INFRA_NODES[ni].sector === sectorName) result.push(INFRA_NODES[ni]);
    }
    return result;
  }

  function getSectorStats() {
    var sectors = {};
    var ni;
    for (ni = 0; ni < INFRA_NODES.length; ni++) {
      var node = INFRA_NODES[ni];
      if (!sectors[node.sector]) {
        sectors[node.sector] = { name: node.sector, count: 0, healthy: 0, degraded: 0, failed: 0 };
      }
      sectors[node.sector].count++;
      if (node.status === 'online') sectors[node.sector].healthy++;
      else if (node.status === 'degraded') sectors[node.sector].degraded++;
      else sectors[node.sector].failed++;
    }
    var result = [];
    var key;
    for (key in sectors) {
      if (sectors.hasOwnProperty(key)) {
        var s = sectors[key];
        s.health = s.count > 0 ? Math.round((s.healthy / s.count) * 100) : 0;
        result.push(s);
      }
    }
    return result;
  }

  function getNodeById(nodeId) {
    var ni;
    for (ni = 0; ni < INFRA_NODES.length; ni++) {
      if (INFRA_NODES[ni].id === nodeId) return INFRA_NODES[ni];
    }
    return null;
  }

  function getDependents(nodeId) {
    var result = [];
    var ni;
    for (ni = 0; ni < INFRA_NODES.length; ni++) {
      if (INFRA_NODES[ni].dependencies && INFRA_NODES[ni].dependencies.indexOf(nodeId) !== -1) {
        result.push(INFRA_NODES[ni]);
      }
    }
    return result;
  }

  function simulateAttack(nodeId, attackType) {
    var visited = {};
    var timeline = [];
    var queue = [{ id: nodeId, minute: 0, cause: 'Direct ' + attackType }];
    var totalPop = 0;
    var totalEcon = 0;
    var degradedCount = 0;

    while (queue.length > 0) {
      var current = queue.shift();
      if (visited[current.id]) continue;
      visited[current.id] = true;

      var node = getNodeById(current.id);
      if (!node) continue;

      var impact = attackType === 'Destroy' ? 'DESTROYED' :
                   attackType === 'Compromise' ? 'COMPROMISED' :
                   attackType === 'Degrade' ? 'DEGRADED' : 'DENIED';

      timeline.push({
        minute: current.minute,
        nodeName: node.name,
        nodeId: node.id,
        sector: node.sector,
        impact: impact,
        cause: current.cause,
        criticality: node.criticality
      });

      totalPop += (node.criticality === 'critical' ? 250000 : node.criticality === 'high' ? 100000 : 25000);
      totalEcon += (node.criticality === 'critical' ? 50000000 : node.criticality === 'high' ? 10000000 : 1000000);
      degradedCount++;

      // Cascade to dependents
      var deps = getDependents(current.id);
      var depI;
      for (depI = 0; depI < deps.length; depI++) {
        if (!visited[deps[depI].id]) {
          var cascadeProb = node.criticality === 'critical' ? 0.9 : node.criticality === 'high' ? 0.7 : 0.4;
          if (Math.random() < cascadeProb) {
            queue.push({
              id: deps[depI].id,
              minute: current.minute + 1 + Math.floor(Math.random() * 3),
              cause: 'Cascade from ' + node.name
            });
          }
        }
      }
    }

    timeline.sort(function(a, b) { return a.minute - b.minute; });
    return {
      timeline: timeline,
      totalPop: totalPop,
      totalEcon: totalEcon,
      degradedCount: degradedCount,
      attackType: attackType,
      targetNode: nodeId
    };
  }

  function renderDigitalTwin() {
    var html = '';
    var sectorStats = getSectorStats();

    // Search bar
    html += '<div class="pm-twin-search">';
    html += '<input type="text" id="pm-twin-search-input" class="pm-input" placeholder="SEARCH INFRASTRUCTURE NODES..." value="' + esc(twinState.searchQuery) + '">';
    html += '</div>';

    // Sector overview cards
    html += '<div class="pm-panel-hdr">INFRASTRUCTURE SECTORS</div>';
    html += '<div class="pm-sector-grid">';
    var si;
    for (si = 0; si < sectorStats.length; si++) {
      var s = sectorStats[si];
      var hpct = s.health;
      var hclr = hpct >= 80 ? '#00ff66' : hpct >= 50 ? '#ffcc00' : '#ff0040';
      var sActive = (twinState.selectedSector === s.name) ? ' pm-sector-active' : '';
      html += '<div class="pm-sector-card' + sActive + '" data-sector="' + esc(s.name) + '">';
      html += '<div class="pm-sector-name">' + esc(s.name) + '</div>';
      html += '<div class="pm-sector-count">' + s.count + ' NODES</div>';
      html += '<div class="pm-sector-health-bar">';
      html += '<div class="pm-sector-health-fill" style="width:' + hpct + '%;background:' + hclr + '"></div>';
      html += '</div>';
      html += '<div class="pm-sector-health-text" style="color:' + hclr + '">' + hpct + '% HEALTHY</div>';
      html += '<div class="pm-sector-breakdown">';
      html += '<span style="color:#00ff66">' + s.healthy + ' UP</span> ';
      html += '<span style="color:#ffcc00">' + s.degraded + ' DEG</span> ';
      html += '<span style="color:#ff0040">' + s.failed + ' DOWN</span>';
      html += '</div>';
      html += '</div>';
    }
    html += '</div>';

    // Node table for selected sector
    if (twinState.selectedSector) {
      var sectorNodes = getSectorNodes(twinState.selectedSector);
      if (twinState.searchQuery) {
        var q = twinState.searchQuery.toLowerCase();
        sectorNodes = sectorNodes.filter(function(n) {
          return n.name.toLowerCase().indexOf(q) !== -1 ||
                 n.type.toLowerCase().indexOf(q) !== -1 ||
                 n.id.toLowerCase().indexOf(q) !== -1;
        });
      }

      html += '<div class="pm-panel pm-nodes-panel">';
      html += '<div class="pm-panel-hdr">' + esc(twinState.selectedSector) + ' SECTOR — ' + sectorNodes.length + ' NODES</div>';
      html += '<table class="pm-table">';
      html += '<thead><tr>';
      html += '<th>NODE ID</th><th>NAME</th><th>TYPE</th><th>STATUS</th><th>CRITICALITY</th><th>DEPENDENCIES</th>';
      html += '</tr></thead>';
      html += '<tbody>';
      var ni;
      for (ni = 0; ni < sectorNodes.length; ni++) {
        var n = sectorNodes[ni];
        var statusClr = n.status === 'online' ? '#00ff66' : n.status === 'degraded' ? '#ffcc00' : '#ff0040';
        var critClr = n.criticality === 'critical' ? '#ff0040' : n.criticality === 'high' ? '#ff6600' : '#ffcc00';
        var depCount = n.dependencies ? n.dependencies.length : 0;
        var nActive = (twinState.selectedNode === n.id) ? ' pm-node-selected' : '';
        html += '<tr class="pm-node-row' + nActive + '" data-nodeid="' + esc(n.id) + '">';
        html += '<td class="pm-mono">' + esc(n.id) + '</td>';
        html += '<td>' + esc(n.name) + '</td>';
        html += '<td>' + esc(n.type) + '</td>';
        html += '<td style="color:' + statusClr + '">' + esc(n.status.toUpperCase()) + '</td>';
        html += '<td style="color:' + critClr + '">' + esc(n.criticality.toUpperCase()) + '</td>';
        html += '<td>' + depCount + '</td>';
        html += '</tr>';
      }
      html += '</tbody></table>';
      html += '</div>';
    }

    // Dependency info for selected node
    if (twinState.selectedNode) {
      var selNode = getNodeById(twinState.selectedNode);
      if (selNode) {
        var nodeDeps = (selNode.dependencies || []).map(function(d) { return getNodeById(d); }).filter(Boolean);
        var nodeDependents = getDependents(selNode.id);

        html += '<div class="pm-panel pm-dep-panel">';
        html += '<div class="pm-panel-hdr">DEPENDENCY GRAPH: ' + esc(selNode.name) + '</div>';
        html += '<div class="pm-dep-grid">';

        // Dependencies (what this node needs)
        html += '<div class="pm-dep-col">';
        html += '<div class="pm-dep-hdr">DEPENDS ON (' + nodeDeps.length + ')</div>';
        var ddi;
        for (ddi = 0; ddi < nodeDeps.length; ddi++) {
          var dd = nodeDeps[ddi];
          var ddClr = dd.status === 'online' ? '#00ff66' : dd.status === 'degraded' ? '#ffcc00' : '#ff0040';
          html += '<div class="pm-dep-item" style="border-left:3px solid ' + ddClr + '">';
          html += '<span class="pm-dep-item-name">' + esc(dd.name) + '</span>';
          html += '<span class="pm-dep-item-sector">' + esc(dd.sector) + '</span>';
          html += '</div>';
        }
        if (nodeDeps.length === 0) html += '<div class="pm-dep-none">No dependencies</div>';
        html += '</div>';

        // Dependents (what depends on this node)
        html += '<div class="pm-dep-col">';
        html += '<div class="pm-dep-hdr">DEPENDED ON BY (' + nodeDependents.length + ')</div>';
        var dei;
        for (dei = 0; dei < nodeDependents.length; dei++) {
          var de = nodeDependents[dei];
          var deClr = de.status === 'online' ? '#00ff66' : de.status === 'degraded' ? '#ffcc00' : '#ff0040';
          html += '<div class="pm-dep-item" style="border-left:3px solid ' + deClr + '">';
          html += '<span class="pm-dep-item-name">' + esc(de.name) + '</span>';
          html += '<span class="pm-dep-item-sector">' + esc(de.sector) + '</span>';
          html += '</div>';
        }
        if (nodeDependents.length === 0) html += '<div class="pm-dep-none">No dependents</div>';
        html += '</div>';

        html += '</div>';
        html += '</div>';
      }
    }

    // Attack simulation controls
    html += '<div class="pm-panel pm-sim-panel">';
    html += '<div class="pm-panel-hdr">ATTACK OPERATIONS</div>';
    html += '<div class="pm-sim-controls">';
    html += '<div class="pm-sim-field">';
    html += '<label class="pm-label">TARGET NODE</label>';
    html += '<select id="pm-sim-node" class="pm-select">';
    html += '<option value="">-- Select Target --</option>';
    var sni;
    for (sni = 0; sni < INFRA_NODES.length; sni++) {
      var sn = INFRA_NODES[sni];
      html += '<option value="' + esc(sn.id) + '">' + esc(sn.name) + ' (' + esc(sn.sector) + ')</option>';
    }
    html += '</select>';
    html += '</div>';
    html += '<div class="pm-sim-field">';
    html += '<label class="pm-label">ATTACK TYPE</label>';
    html += '<select id="pm-sim-type" class="pm-select">';
    html += '<option value="Compromise">COMPROMISE</option>';
    html += '<option value="Destroy">DESTROY</option>';
    html += '<option value="Degrade">DEGRADE</option>';
    html += '<option value="Deny">DENY</option>';
    html += '</select>';
    html += '</div>';
    html += '<button id="pm-sim-exec" class="pm-btn pm-btn-danger">EXECUTE OPERATION</button>';
    html += '</div>';

    // Simulation results
    if (twinState.simResults) {
      var sim = twinState.simResults;
      html += '<div class="pm-sim-results">';

      // Impact summary
      html += '<div class="pm-sim-impact">';
      html += '<div class="pm-sim-impact-item">';
      html += '<div class="pm-sim-impact-val" style="color:#ff0040">' + sim.degradedCount + '</div>';
      html += '<div class="pm-sim-impact-label">NODES AFFECTED</div>';
      html += '</div>';
      html += '<div class="pm-sim-impact-item">';
      html += '<div class="pm-sim-impact-val" style="color:#ff6600">' + (sim.totalPop > 1000000 ? (sim.totalPop / 1000000).toFixed(1) + 'M' : Math.round(sim.totalPop / 1000) + 'K') + '</div>';
      html += '<div class="pm-sim-impact-label">POPULATION AFFECTED</div>';
      html += '</div>';
      html += '<div class="pm-sim-impact-item">';
      html += '<div class="pm-sim-impact-val" style="color:#ffcc00">$' + (sim.totalEcon > 1000000 ? (sim.totalEcon / 1000000).toFixed(1) + 'M' : Math.round(sim.totalEcon / 1000) + 'K') + '</div>';
      html += '<div class="pm-sim-impact-label">ECONOMIC DAMAGE</div>';
      html += '</div>';
      html += '</div>';

      // Cascade timeline
      html += '<div class="pm-panel-hdr">CASCADE TIMELINE</div>';
      html += '<div class="pm-cascade-timeline">';
      var ti;
      for (ti = 0; ti < sim.timeline.length; ti++) {
        var t = sim.timeline[ti];
        var tClr = t.impact === 'DESTROYED' ? '#ff0040' : t.impact === 'COMPROMISED' ? '#ff6600' : t.impact === 'DEGRADED' ? '#ffcc00' : '#4488ff';
        html += '<div class="pm-cascade-event" style="border-left:3px solid ' + tClr + '">';
        html += '<span class="pm-cascade-time">T+' + t.minute + 'min</span>';
        html += '<span class="pm-cascade-node">' + esc(t.nodeName) + '</span>';
        html += '<span class="pm-cascade-impact" style="color:' + tClr + '">' + esc(t.impact) + '</span>';
        html += '<span class="pm-cascade-cause">' + esc(t.cause) + '</span>';
        html += '<span class="pm-cascade-sector">[' + esc(t.sector) + ']</span>';
        html += '</div>';
      }
      html += '</div>';
      html += '</div>';
    }

    html += '</div>'; // .pm-sim-panel

    return html;
  }

  function bindDigitalTwin() {
    // Sector card click
    var sectorCards = main.querySelectorAll('.pm-sector-card');
    var sci;
    for (sci = 0; sci < sectorCards.length; sci++) {
      sectorCards[sci].addEventListener('click', function() {
        var sectorName = this.getAttribute('data-sector');
        twinState.selectedSector = (twinState.selectedSector === sectorName) ? null : sectorName;
        twinState.selectedNode = null;
        renderActiveTab();
      });
    }

    // Node row click
    var nodeRows = main.querySelectorAll('.pm-node-row');
    var nri;
    for (nri = 0; nri < nodeRows.length; nri++) {
      nodeRows[nri].addEventListener('click', function() {
        var nodeId = this.getAttribute('data-nodeid');
        twinState.selectedNode = (twinState.selectedNode === nodeId) ? null : nodeId;
        renderActiveTab();
      });
    }

    // Search input
    var searchInput = main.querySelector('#pm-twin-search-input');
    if (searchInput) {
      searchInput.addEventListener('input', function() {
        twinState.searchQuery = this.value;
        renderActiveTab();
      });
    }

    // Simulation execute button
    var simBtn = main.querySelector('#pm-sim-exec');
    if (simBtn) {
      simBtn.addEventListener('click', function() {
        var nodeSelect = main.querySelector('#pm-sim-node');
        var typeSelect = main.querySelector('#pm-sim-type');
        if (!nodeSelect || !typeSelect || !nodeSelect.value) return;
        twinState.simResults = simulateAttack(nodeSelect.value, typeSelect.value);
        renderActiveTab();
      });
    }
  }

  // =========================================================================
  // TAB 3: CYBER TERRAIN
  // =========================================================================

  var terrainState = {
    selectedAsset: null,
    attackPathSource: '',
    attackPathTarget: '',
    attackPathResult: null,
    sortCol: null,
    sortAsc: true
  };

  var serviceDistribution = [
    { service: 'HTTP/HTTPS', count: 48, color: '#00ff66' },
    { service: 'SSH', count: 35, color: '#4488ff' },
    { service: 'DNS', count: 22, color: '#ffcc00' },
    { service: 'SMTP', count: 14, color: '#ff6600' },
    { service: 'RDP', count: 18, color: '#ff0040' },
    { service: 'SMB', count: 12, color: '#cc44ff' },
    { service: 'FTP', count: 8, color: '#00cccc' },
    { service: 'LDAP', count: 10, color: '#88ff00' },
    { service: 'MySQL', count: 15, color: '#ff88cc' },
    { service: 'PostgreSQL', count: 9, color: '#44ccff' },
    { service: 'SNMP', count: 7, color: '#ccaa00' },
    { service: 'Telnet', count: 3, color: '#ff4444' }
  ];

  var bgpTopology = [
    { asn: 'AS64512', name: 'DARKNODE-CORE', prefixes: 24, peers: 8, transit: 'Yes', status: 'Active' },
    { asn: 'AS64513', name: 'DARKNODE-EDGE', prefixes: 16, peers: 12, transit: 'Yes', status: 'Active' },
    { asn: 'AS64514', name: 'GOV-TRANSIT-1', prefixes: 128, peers: 34, transit: 'Yes', status: 'Active' },
    { asn: 'AS64515', name: 'MIL-BACKBONE', prefixes: 64, peers: 6, transit: 'No', status: 'Active' },
    { asn: 'AS64516', name: 'INTEL-SECURE', prefixes: 8, peers: 3, transit: 'No', status: 'Active' },
    { asn: 'AS64517', name: 'CRIT-INFRA-NET', prefixes: 96, peers: 22, transit: 'Yes', status: 'Active' },
    { asn: 'AS64518', name: 'CLOUD-BRIDGE', prefixes: 48, peers: 18, transit: 'Yes', status: 'Degraded' },
    { asn: 'AS64519', name: 'SCADA-ISOLATED', prefixes: 4, peers: 2, transit: 'No', status: 'Active' }
  ];

  var vulnHeatmap = [
    { service: 'Web Servers', critical: 12, high: 28, medium: 45, low: 34 },
    { service: 'Email Systems', critical: 5, high: 14, medium: 22, low: 18 },
    { service: 'Databases', critical: 8, high: 19, medium: 31, low: 26 },
    { service: 'VPN/Remote', critical: 15, high: 22, medium: 18, low: 12 },
    { service: 'DNS Servers', critical: 3, high: 8, medium: 14, low: 10 },
    { service: 'File Shares', critical: 6, high: 11, medium: 20, low: 16 },
    { service: 'SCADA/ICS', critical: 18, high: 25, medium: 32, low: 8 },
    { service: 'Auth Services', critical: 10, high: 16, medium: 24, low: 14 }
  ];

  function generateIP(index) {
    var octets = [
      10 + (index % 4),
      Math.floor(index / 4) % 256,
      (index * 7 + 3) % 256,
      (index * 13 + 1) % 254 + 1
    ];
    return octets[0] + '.' + octets[1] + '.' + octets[2] + '.' + octets[3];
  }

  function generateServices(node) {
    var base = ['SSH'];
    if (node.type === 'server' || node.type === 'web_server') base.push('HTTP', 'HTTPS');
    if (node.type === 'database') base.push('MySQL', 'PostgreSQL');
    if (node.type === 'router' || node.type === 'switch' || node.type === 'firewall') base.push('SNMP');
    if (node.type === 'mail_server') base.push('SMTP', 'IMAP');
    if (node.type === 'dns_server') base.push('DNS');
    if (node.type === 'scada' || node.type === 'plc') base.push('Modbus', 'OPC-UA');
    if (node.type === 'workstation') base.push('RDP');
    return base;
  }

  function generateOS(node) {
    var osMap = {
      server: 'RHEL 9.2', web_server: 'Ubuntu 22.04', database: 'CentOS 8',
      router: 'Cisco IOS 17.x', switch: 'Cisco NX-OS', firewall: 'PAN-OS 11',
      mail_server: 'Windows Server 2022', dns_server: 'BIND 9.18', workstation: 'Windows 11',
      scada: 'Windows 10 LTSC', plc: 'Firmware v3.7', controller: 'RTOS 5.4',
      sensor: 'Embedded Linux', gateway: 'pfSense 2.7', load_balancer: 'F5 BIG-IP',
      vpn: 'FortiOS 7.4', ids: 'Security Onion', siem: 'Elastic 8.x',
      backup: 'Veeam B&R 12', storage: 'NetApp ONTAP 9'
    };
    return osMap[node.type] || 'Linux 6.x';
  }

  function generateExposureScore(node) {
    var base = 20;
    if (node.criticality === 'critical') base += 30;
    else if (node.criticality === 'high') base += 20;
    else base += 10;
    if (node.status === 'degraded') base += 15;
    if (node.status === 'offline') base += 25;
    base += Math.floor(Math.random() * 20);
    return Math.min(100, base);
  }

  function calculateAttackPath(sourceId, targetId) {
    if (sourceId === targetId) return null;
    var source = getNodeById(sourceId);
    var target = getNodeById(targetId);
    if (!source || !target) return null;

    // BFS-like path through infrastructure
    var path = [{ node: source, action: 'Initial access via ' + (source.type === 'web_server' ? 'web exploit' : 'SSH brute force') }];

    // Generate 2-4 intermediate hops
    var hopCount = 2 + Math.floor(Math.random() * 3);
    var visited = {};
    visited[sourceId] = true;
    visited[targetId] = true;

    var techniques = [
      'Lateral movement via Pass-the-Hash',
      'Privilege escalation through misconfigured sudo',
      'Pivoting through compromised VPN tunnel',
      'Exploiting trust relationship',
      'Credential reuse from memory dump',
      'RDP session hijacking',
      'WMI remote execution',
      'SMB relay attack',
      'Kerberos delegation abuse',
      'SSH key theft and reuse'
    ];

    var candidates = [];
    var ci;
    for (ci = 0; ci < INFRA_NODES.length; ci++) {
      if (!visited[INFRA_NODES[ci].id]) candidates.push(INFRA_NODES[ci]);
    }

    var hi;
    for (hi = 0; hi < hopCount && candidates.length > 0; hi++) {
      var idx = Math.floor(Math.random() * candidates.length);
      var hop = candidates.splice(idx, 1)[0];
      var tech = techniques[Math.floor(Math.random() * techniques.length)];
      path.push({ node: hop, action: tech });
    }

    path.push({ node: target, action: 'Target reached — ' + (target.type === 'database' ? 'data exfiltration' : 'objective achieved') });

    return {
      path: path,
      totalHops: path.length,
      estimatedTime: (path.length * 15 + Math.floor(Math.random() * 30)) + ' minutes',
      difficulty: path.length > 4 ? 'HIGH' : path.length > 3 ? 'MEDIUM' : 'LOW',
      detectionRisk: Math.floor(Math.random() * 40 + 30) + '%'
    };
  }

  function renderCyberTerrain() {
    var html = '';

    // Network topology table
    html += '<div class="pm-panel">';
    html += '<div class="pm-panel-hdr">NETWORK TOPOLOGY — ASSET INVENTORY</div>';
    html += '<div class="pm-table-wrap">';
    html += '<table class="pm-table" id="pm-topo-table">';
    html += '<thead><tr>';
    html += '<th data-sort="ip" class="pm-sortable">IP ADDRESS</th>';
    html += '<th data-sort="name" class="pm-sortable">HOSTNAME</th>';
    html += '<th data-sort="os">OS / FIRMWARE</th>';
    html += '<th>SERVICES</th>';
    html += '<th data-sort="vulns" class="pm-sortable">VULNS</th>';
    html += '<th data-sort="exposure" class="pm-sortable">EXPOSURE</th>';
    html += '</tr></thead>';
    html += '<tbody>';

    var topoNodes = INFRA_NODES.slice(0, 30);
    var ti;
    for (ti = 0; ti < topoNodes.length; ti++) {
      var tn = topoNodes[ti];
      var ip = generateIP(ti);
      var os = generateOS(tn);
      var services = generateServices(tn);
      var vulnCount = Math.floor(Math.random() * 12);
      var exposure = generateExposureScore(tn);
      var expClr = exposure >= 70 ? '#ff0040' : exposure >= 40 ? '#ffcc00' : '#00ff66';
      var selClass = (terrainState.selectedAsset === tn.id) ? ' pm-row-selected' : '';

      html += '<tr class="pm-topo-row' + selClass + '" data-nodeid="' + esc(tn.id) + '">';
      html += '<td class="pm-mono">' + esc(ip) + '</td>';
      html += '<td>' + esc(tn.name) + '</td>';
      html += '<td>' + esc(os) + '</td>';
      html += '<td class="pm-svc-cell">';
      var svi;
      for (svi = 0; svi < services.length; svi++) {
        html += '<span class="pm-svc-badge">' + esc(services[svi]) + '</span>';
      }
      html += '</td>';
      html += '<td style="color:' + (vulnCount > 5 ? '#ff0040' : vulnCount > 2 ? '#ffcc00' : '#00ff66') + '">' + vulnCount + '</td>';
      html += '<td>';
      html += '<div class="pm-exposure-bar-wrap">';
      html += '<div class="pm-exposure-bar" style="width:' + exposure + '%;background:' + expClr + '"></div>';
      html += '</div>';
      html += '<span class="pm-exposure-val" style="color:' + expClr + '">' + exposure + '</span>';
      html += '</td>';
      html += '</tr>';
    }
    html += '</tbody></table>';
    html += '</div>';
    html += '</div>';

    // Attack path calculator
    html += '<div class="pm-panel">';
    html += '<div class="pm-panel-hdr">ATTACK PATH CALCULATOR</div>';
    html += '<div class="pm-path-controls">';
    html += '<div class="pm-path-field">';
    html += '<label class="pm-label">SOURCE NODE</label>';
    html += '<select id="pm-path-source" class="pm-select">';
    html += '<option value="">-- Select Source --</option>';
    var psi;
    for (psi = 0; psi < INFRA_NODES.length; psi++) {
      var ps = INFRA_NODES[psi];
      var psSel = (terrainState.attackPathSource === ps.id) ? ' selected' : '';
      html += '<option value="' + esc(ps.id) + '"' + psSel + '>' + esc(ps.name) + '</option>';
    }
    html += '</select>';
    html += '</div>';

    html += '<div class="pm-path-arrow">&#9654;</div>';

    html += '<div class="pm-path-field">';
    html += '<label class="pm-label">TARGET NODE</label>';
    html += '<select id="pm-path-target" class="pm-select">';
    html += '<option value="">-- Select Target --</option>';
    var pti;
    for (pti = 0; pti < INFRA_NODES.length; pti++) {
      var pt = INFRA_NODES[pti];
      var ptSel = (terrainState.attackPathTarget === pt.id) ? ' selected' : '';
      html += '<option value="' + esc(pt.id) + '"' + ptSel + '>' + esc(pt.name) + '</option>';
    }
    html += '</select>';
    html += '</div>';

    html += '<button id="pm-path-calc" class="pm-btn pm-btn-primary">CALCULATE PATH</button>';
    html += '</div>';

    // Attack path results
    if (terrainState.attackPathResult) {
      var apr = terrainState.attackPathResult;
      html += '<div class="pm-path-result">';
      html += '<div class="pm-path-meta">';
      html += '<span>HOPS: <strong>' + apr.totalHops + '</strong></span>';
      html += '<span>EST. TIME: <strong>' + esc(apr.estimatedTime) + '</strong></span>';
      html += '<span>DIFFICULTY: <strong style="color:' + (apr.difficulty === 'HIGH' ? '#ff0040' : apr.difficulty === 'MEDIUM' ? '#ffcc00' : '#00ff66') + '">' + esc(apr.difficulty) + '</strong></span>';
      html += '<span>DETECTION RISK: <strong style="color:#ff6600">' + esc(apr.detectionRisk) + '</strong></span>';
      html += '</div>';
      html += '<div class="pm-path-chain">';
      var phi;
      for (phi = 0; phi < apr.path.length; phi++) {
        var ph = apr.path[phi];
        html += '<div class="pm-path-hop">';
        html += '<div class="pm-path-hop-num">HOP ' + (phi + 1) + '</div>';
        html += '<div class="pm-path-hop-name">' + esc(ph.node.name) + '</div>';
        html += '<div class="pm-path-hop-action">' + esc(ph.action) + '</div>';
        html += '<div class="pm-path-hop-sector">' + esc(ph.node.sector) + ' / ' + esc(ph.node.type) + '</div>';
        html += '</div>';
        if (phi < apr.path.length - 1) {
          html += '<div class="pm-path-connector">&#9660;</div>';
        }
      }
      html += '</div>';
      html += '</div>';
    }
    html += '</div>';

    // AS/BGP topology
    html += '<div class="pm-panel">';
    html += '<div class="pm-panel-hdr">AS/BGP TOPOLOGY SUMMARY</div>';
    html += '<table class="pm-table">';
    html += '<thead><tr>';
    html += '<th>ASN</th><th>NAME</th><th>PREFIXES</th><th>PEERS</th><th>TRANSIT</th><th>STATUS</th>';
    html += '</tr></thead><tbody>';
    var bi;
    for (bi = 0; bi < bgpTopology.length; bi++) {
      var b = bgpTopology[bi];
      var bClr = b.status === 'Active' ? '#00ff66' : '#ffcc00';
      html += '<tr>';
      html += '<td class="pm-mono">' + esc(b.asn) + '</td>';
      html += '<td>' + esc(b.name) + '</td>';
      html += '<td>' + b.prefixes + '</td>';
      html += '<td>' + b.peers + '</td>';
      html += '<td>' + esc(b.transit) + '</td>';
      html += '<td style="color:' + bClr + '">' + esc(b.status) + '</td>';
      html += '</tr>';
    }
    html += '</tbody></table>';
    html += '</div>';

    // Service distribution
    html += '<div class="pm-terrain-bottom">';
    html += '<div class="pm-panel pm-svc-dist-panel">';
    html += '<div class="pm-panel-hdr">SERVICE DISTRIBUTION</div>';
    var maxCount = 0;
    var sdi;
    for (sdi = 0; sdi < serviceDistribution.length; sdi++) {
      if (serviceDistribution[sdi].count > maxCount) maxCount = serviceDistribution[sdi].count;
    }
    for (sdi = 0; sdi < serviceDistribution.length; sdi++) {
      var sd = serviceDistribution[sdi];
      var barW = maxCount > 0 ? Math.round((sd.count / maxCount) * 100) : 0;
      html += '<div class="pm-svc-bar-row">';
      html += '<span class="pm-svc-bar-label">' + esc(sd.service) + '</span>';
      html += '<div class="pm-svc-bar-track">';
      html += '<div class="pm-svc-bar-fill" style="width:' + barW + '%;background:' + sd.color + '"></div>';
      html += '</div>';
      html += '<span class="pm-svc-bar-count">' + sd.count + '</span>';
      html += '</div>';
    }
    html += '</div>';

    // Vulnerability heat map
    html += '<div class="pm-panel pm-vuln-heat-panel">';
    html += '<div class="pm-panel-hdr">VULNERABILITY HEAT MAP</div>';
    html += '<table class="pm-table pm-heatmap-table">';
    html += '<thead><tr>';
    html += '<th>SERVICE TYPE</th><th>CRITICAL</th><th>HIGH</th><th>MEDIUM</th><th>LOW</th><th>TOTAL</th>';
    html += '</tr></thead><tbody>';
    var vhi;
    for (vhi = 0; vhi < vulnHeatmap.length; vhi++) {
      var vh = vulnHeatmap[vhi];
      var total = vh.critical + vh.high + vh.medium + vh.low;
      html += '<tr>';
      html += '<td>' + esc(vh.service) + '</td>';
      html += '<td class="pm-heat-cell" style="background:rgba(255,0,64,' + Math.min(vh.critical / 20, 1) * 0.6 + ')">' + vh.critical + '</td>';
      html += '<td class="pm-heat-cell" style="background:rgba(255,102,0,' + Math.min(vh.high / 30, 1) * 0.6 + ')">' + vh.high + '</td>';
      html += '<td class="pm-heat-cell" style="background:rgba(255,204,0,' + Math.min(vh.medium / 45, 1) * 0.5 + ')">' + vh.medium + '</td>';
      html += '<td class="pm-heat-cell" style="background:rgba(68,136,255,' + Math.min(vh.low / 35, 1) * 0.4 + ')">' + vh.low + '</td>';
      html += '<td><strong>' + total + '</strong></td>';
      html += '</tr>';
    }
    html += '</tbody></table>';
    html += '</div>';
    html += '</div>';

    // Exposure breakdown for selected asset
    if (terrainState.selectedAsset) {
      var selAsset = getNodeById(terrainState.selectedAsset);
      if (selAsset) {
        var factors = [
          { name: 'Open Ports', score: 10 + Math.floor(Math.random() * 30), max: 25 },
          { name: 'Known Vulnerabilities', score: 5 + Math.floor(Math.random() * 35), max: 30 },
          { name: 'Internet Exposure', score: selAsset.type === 'web_server' ? 20 : 5, max: 20 },
          { name: 'Patch Status', score: Math.floor(Math.random() * 15), max: 15 },
          { name: 'Encryption', score: Math.floor(Math.random() * 10), max: 10 }
        ];

        html += '<div class="pm-panel">';
        html += '<div class="pm-panel-hdr">EXPOSURE BREAKDOWN: ' + esc(selAsset.name) + '</div>';
        var efi;
        for (efi = 0; efi < factors.length; efi++) {
          var f = factors[efi];
          var fpct = Math.round((f.score / f.max) * 100);
          var fclr = fpct >= 70 ? '#ff0040' : fpct >= 40 ? '#ffcc00' : '#00ff66';
          html += '<div class="pm-exposure-factor">';
          html += '<span class="pm-factor-name">' + esc(f.name) + '</span>';
          html += '<div class="pm-factor-bar-wrap">';
          html += '<div class="pm-factor-bar" style="width:' + fpct + '%;background:' + fclr + '"></div>';
          html += '</div>';
          html += '<span class="pm-factor-score">' + f.score + '/' + f.max + '</span>';
          html += '</div>';
        }
        html += '</div>';
      }
    }

    return html;
  }

  function bindCyberTerrain() {
    // Topology row click for exposure breakdown
    var topoRows = main.querySelectorAll('.pm-topo-row');
    var tri;
    for (tri = 0; tri < topoRows.length; tri++) {
      topoRows[tri].addEventListener('click', function() {
        var nodeId = this.getAttribute('data-nodeid');
        terrainState.selectedAsset = (terrainState.selectedAsset === nodeId) ? null : nodeId;
        renderActiveTab();
      });
    }

    // Attack path calculator
    var pathCalc = main.querySelector('#pm-path-calc');
    if (pathCalc) {
      pathCalc.addEventListener('click', function() {
        var srcSel = main.querySelector('#pm-path-source');
        var tgtSel = main.querySelector('#pm-path-target');
        if (!srcSel || !tgtSel || !srcSel.value || !tgtSel.value) return;
        terrainState.attackPathSource = srcSel.value;
        terrainState.attackPathTarget = tgtSel.value;
        terrainState.attackPathResult = calculateAttackPath(srcSel.value, tgtSel.value);
        renderActiveTab();
      });
    }

    // Sort handlers (simplified: just toggle sort state and re-render)
    var sortHeaders = main.querySelectorAll('.pm-sortable');
    var shi;
    for (shi = 0; shi < sortHeaders.length; shi++) {
      sortHeaders[shi].addEventListener('click', function() {
        var col = this.getAttribute('data-sort');
        if (terrainState.sortCol === col) {
          terrainState.sortAsc = !terrainState.sortAsc;
        } else {
          terrainState.sortCol = col;
          terrainState.sortAsc = true;
        }
        renderActiveTab();
      });
    }
  }



  // =========================================================================
  // TAB 4: SIGINT FUSION
  // =========================================================================

  var INTEL_TYPE_COLORS = {
    SIGINT: '#00bfff',
    OSINT: '#00ff88',
    CYBINT: '#ffaa00',
    HUMINT: '#ff4444'
  };

  var SOURCE_RATINGS = [
    { code: 'A', label: 'Completely Reliable', desc: 'No doubt of authenticity, trustworthiness, or competency; has a history of complete reliability', color: '#00ff88' },
    { code: 'B', label: 'Usually Reliable', desc: 'Minor doubt about authenticity, trustworthiness, or competency; has a history of valid information most of the time', color: '#88ff00' },
    { code: 'C', label: 'Fairly Reliable', desc: 'Doubt of authenticity, trustworthiness, or competency but has provided valid information in the past', color: '#ffff00' },
    { code: 'D', label: 'Not Usually Reliable', desc: 'Significant doubt about authenticity, trustworthiness, or competency but has provided valid information in the past', color: '#ffaa00' },
    { code: 'E', label: 'Unreliable', desc: 'Lacking in authenticity, trustworthiness, and competency; history of invalid information', color: '#ff6600' },
    { code: 'F', label: 'Cannot Be Judged', desc: 'No basis exists for evaluating the reliability of the source', color: '#888888' }
  ];

  var CORRELATION_ALERTS = [
    { id: 'CORR-001', title: 'Coordinated APT Activity Targeting Energy Sector', sources: ['SIGINT-NSA-4482', 'CYBINT-US-CERT-2291', 'OSINT-MAND-1187'], confidence: 92, action: 'Elevate to DEFCON 3 posture; brief SECDEF on coordinated campaign', timestamp: '2026-09-13T08:22:00Z' },
    { id: 'CORR-002', title: 'Pre-positioning Activity in Financial Networks', sources: ['HUMINT-CIA-0093', 'SIGINT-GCHQ-1144', 'CYBINT-FBI-3301'], confidence: 85, action: 'Activate enhanced monitoring on SWIFT gateways; coordinate with Treasury', timestamp: '2026-09-13T07:45:00Z' },
    { id: 'CORR-003', title: 'Submarine Cable Reconnaissance Operations', sources: ['SIGINT-NSA-4501', 'OSINT-RUSI-0221', 'HUMINT-DIA-0187'], confidence: 78, action: 'Increase maritime ISR near cable landing sites; coordinate with Navy', timestamp: '2026-09-13T06:30:00Z' },
    { id: 'CORR-004', title: 'Supply Chain Compromise in Defense Contractors', sources: ['CYBINT-CISA-8812', 'OSINT-MAND-1201', 'SIGINT-NSA-4455'], confidence: 71, action: 'Issue emergency directive to DIB partners; initiate forensic sweep', timestamp: '2026-09-13T05:15:00Z' },
    { id: 'CORR-005', title: 'Influence Operation Targeting Election Infrastructure', sources: ['OSINT-DHS-0445', 'HUMINT-FBI-2200', 'CYBINT-NSA-3390', 'SIGINT-GCHQ-1198'], confidence: 88, action: 'Brief election officials; activate counter-influence protocols', timestamp: '2026-09-13T04:00:00Z' }
  ];

  function renderSigint() {
    var html = '';
    html += '<div class="pm-section-header">SIGINT FUSION CENTER</div>';

    // Intelligence type filter bar
    html += '<div class="pm-filter-bar">';
    html += '<span class="pm-filter-label">FILTER BY TYPE:</span>';
    html += '<button class="pm-filter-btn pm-filter-active" data-sigint-filter="ALL">ALL</button>';
    html += '<button class="pm-filter-btn" data-sigint-filter="SIGINT" style="border-color:#00bfff">SIGINT</button>';
    html += '<button class="pm-filter-btn" data-sigint-filter="OSINT" style="border-color:#00ff88">OSINT</button>';
    html += '<button class="pm-filter-btn" data-sigint-filter="CYBINT" style="border-color:#ffaa00">CYBINT</button>';
    html += '<button class="pm-filter-btn" data-sigint-filter="HUMINT" style="border-color:#ff4444">HUMINT</button>';
    html += '</div>';

    // Main grid: intel feed left, correlation alerts right
    html += '<div class="pm-sigint-grid">';

    // Left: Intelligence feed
    html += '<div class="pm-sigint-feed">';
    html += '<div class="pm-panel-title">MULTI-SOURCE INTELLIGENCE FEED</div>';
    html += '<div class="pm-intel-scroll" id="pm-intel-scroll">';
    for (var i = 0; i < INTEL_FEEDS.length; i++) {
      var feed = INTEL_FEEDS[i];
      var typeColor = INTEL_TYPE_COLORS[feed.type] || '#888';
      html += '<div class="pm-intel-entry" data-intel-type="' + esc(feed.type) + '" data-intel-idx="' + i + '">';
      html += '<div class="pm-intel-class-banner" style="background:' + (feed.classification === 'TOP SECRET/SCI' ? '#cc0000' : feed.classification === 'SECRET' ? '#ff6600' : '#ffaa00') + '">';
      html += esc(feed.classification);
      html += '</div>';
      html += '<div class="pm-intel-header">';
      html += '<span class="pm-intel-type-badge" style="background:' + typeColor + ';color:#000">' + esc(feed.type) + '</span>';
      html += '<span class="pm-intel-id">' + esc(feed.id) + '</span>';
      html += '<span class="pm-intel-timestamp">' + esc(feed.timestamp) + '</span>';
      html += '</div>';
      html += '<div class="pm-intel-source">SOURCE: ' + esc(feed.source) + '</div>';
      html += '<div class="pm-intel-summary">' + esc(feed.summary) + '</div>';
      html += '<div class="pm-intel-scores">';
      html += '<span class="pm-score-item">RELIABILITY: <strong style="color:' + (feed.reliability >= 80 ? '#00ff88' : feed.reliability >= 50 ? '#ffaa00' : '#ff4444') + '">' + esc(feed.reliability) + '%</strong></span>';
      html += '<span class="pm-score-item">CREDIBILITY: <strong style="color:' + (feed.credibility >= 80 ? '#00ff88' : feed.credibility >= 50 ? '#ffaa00' : '#ff4444') + '">' + esc(feed.credibility) + '%</strong></span>';
      html += '</div>';
      html += '</div>';
    }
    html += '</div>'; // pm-intel-scroll
    html += '</div>'; // pm-sigint-feed

    // Right: Correlation alerts
    html += '<div class="pm-sigint-corr">';
    html += '<div class="pm-panel-title">CORRELATION ALERTS</div>';
    for (var c = 0; c < CORRELATION_ALERTS.length; c++) {
      var corr = CORRELATION_ALERTS[c];
      html += '<div class="pm-corr-alert" data-corr-idx="' + c + '">';
      html += '<div class="pm-corr-header">';
      html += '<span class="pm-corr-id">' + esc(corr.id) + '</span>';
      html += '<span class="pm-corr-confidence" style="color:' + (corr.confidence >= 85 ? '#ff4444' : corr.confidence >= 70 ? '#ffaa00' : '#00bfff') + '">';
      html += esc(corr.confidence) + '% CONFIDENCE</span>';
      html += '</div>';
      html += '<div class="pm-corr-title">' + esc(corr.title) + '</div>';
      html += '<div class="pm-corr-sources">';
      html += '<span class="pm-corr-src-label">CORROBORATING SOURCES:</span>';
      for (var s = 0; s < corr.sources.length; s++) {
        html += '<span class="pm-corr-src-tag">' + esc(corr.sources[s]) + '</span>';
      }
      html += '</div>';
      html += '<div class="pm-corr-action" style="display:none" data-corr-detail="' + c + '">';
      html += '<div class="pm-corr-action-label">RECOMMENDED ACTION:</div>';
      html += '<div class="pm-corr-action-text">' + esc(corr.action) + '</div>';
      html += '<div class="pm-corr-timestamp">GENERATED: ' + esc(corr.timestamp) + '</div>';
      html += '</div>';
      html += '<button class="pm-corr-expand-btn" data-corr-toggle="' + c + '">EXPAND</button>';
      html += '</div>';
    }
    html += '</div>'; // pm-sigint-corr
    html += '</div>'; // pm-sigint-grid

    // Intelligence timeline
    html += '<div class="pm-section-sub">INTELLIGENCE TIMELINE</div>';
    html += '<div class="pm-intel-timeline">';
    html += '<div class="pm-timeline-track" id="pm-intel-timeline-track">';
    for (var t = 0; t < INTEL_FEEDS.length; t++) {
      var tf = INTEL_FEEDS[t];
      var tColor = INTEL_TYPE_COLORS[tf.type] || '#888';
      var leftPct = (t / INTEL_FEEDS.length) * 100;
      html += '<div class="pm-timeline-dot" style="left:' + leftPct + '%;background:' + tColor + '" title="' + esc(tf.id + ': ' + tf.summary.substring(0, 60)) + '" data-timeline-idx="' + t + '"></div>';
    }
    html += '</div>';
    html += '<div class="pm-timeline-labels">';
    html += '<span>72H AGO</span><span>48H AGO</span><span>24H AGO</span><span>NOW</span>';
    html += '</div>';
    html += '</div>';
    html += '<div class="pm-timeline-detail" id="pm-timeline-detail" style="display:none"></div>';

    // Source reliability scoring
    html += '<div class="pm-section-sub">SOURCE RELIABILITY SCORING (NATO STANDARD)</div>';
    html += '<table class="pm-table">';
    html += '<thead><tr><th>CODE</th><th>RATING</th><th>DESCRIPTION</th></tr></thead>';
    html += '<tbody>';
    for (var r = 0; r < SOURCE_RATINGS.length; r++) {
      var rating = SOURCE_RATINGS[r];
      html += '<tr>';
      html += '<td style="color:' + rating.color + ';font-weight:bold;font-size:1.2em;text-align:center">' + esc(rating.code) + '</td>';
      html += '<td style="color:' + rating.color + '">' + esc(rating.label) + '</td>';
      html += '<td>' + esc(rating.desc) + '</td>';
      html += '</tr>';
    }
    html += '</tbody></table>';

    // Analyst workspace + Intel product generator
    html += '<div class="pm-sigint-bottom-grid">';

    // Analyst workspace
    html += '<div class="pm-analyst-workspace">';
    html += '<div class="pm-panel-title">ANALYST WORKSPACE</div>';
    html += '<div class="pm-form-group">';
    html += '<label class="pm-label">CLASSIFICATION</label>';
    html += '<select class="pm-select" id="pm-analyst-class">';
    html += '<option value="UNCLASSIFIED">UNCLASSIFIED</option>';
    html += '<option value="CONFIDENTIAL">CONFIDENTIAL</option>';
    html += '<option value="SECRET">SECRET</option>';
    html += '<option value="TOP SECRET">TOP SECRET</option>';
    html += '<option value="TOP SECRET/SCI" selected>TOP SECRET/SCI</option>';
    html += '</select>';
    html += '</div>';
    html += '<div class="pm-form-group">';
    html += '<label class="pm-label">ASSESSMENT</label>';
    html += '<textarea class="pm-textarea" id="pm-analyst-assessment" rows="6" placeholder="Enter intelligence assessment..."></textarea>';
    html += '</div>';
    html += '<div class="pm-form-group">';
    html += '<label class="pm-label">DISSEMINATION</label>';
    html += '<div class="pm-checkbox-group">';
    var dissemTargets = ['CYBERCOM', 'NSA/CSS', 'DIA', 'CIA', 'FBI/CyD', 'CISA', 'FVEY PARTNERS', 'NATO ALLIES', 'SECTOR ISACs'];
    for (var d = 0; d < dissemTargets.length; d++) {
      html += '<label class="pm-checkbox-label">';
      html += '<input type="checkbox" class="pm-checkbox" value="' + esc(dissemTargets[d]) + '"';
      if (d < 3) html += ' checked';
      html += '> ' + esc(dissemTargets[d]);
      html += '</label>';
    }
    html += '</div>';
    html += '</div>';
    html += '<button class="pm-btn pm-btn-primary" id="pm-publish-assessment">PUBLISH ASSESSMENT</button>';
    html += '</div>';

    // Intel product generator
    html += '<div class="pm-intel-product">';
    html += '<div class="pm-panel-title">INTELLIGENCE PRODUCT GENERATOR</div>';
    html += '<div class="pm-product-buttons">';
    html += '<button class="pm-btn pm-btn-accent" id="pm-gen-intrep">GENERATE INTREP</button>';
    html += '<button class="pm-btn pm-btn-warning" id="pm-gen-spot">GENERATE SPOT REPORT</button>';
    html += '</div>';
    html += '<div class="pm-product-output" id="pm-product-output">';
    html += '<div class="pm-product-placeholder">Select a report type to generate an intelligence product template.</div>';
    html += '</div>';
    html += '</div>';

    html += '</div>'; // pm-sigint-bottom-grid

    return html;
  }

  function bindSigint() {
    // Intel type filter buttons
    var filterBtns = main.querySelectorAll('[data-sigint-filter]');
    for (var i = 0; i < filterBtns.length; i++) {
      filterBtns[i].addEventListener('click', function() {
        var filterVal = this.getAttribute('data-sigint-filter');
        var allBtns = main.querySelectorAll('[data-sigint-filter]');
        for (var j = 0; j < allBtns.length; j++) {
          allBtns[j].classList.remove('pm-filter-active');
        }
        this.classList.add('pm-filter-active');
        var entries = main.querySelectorAll('.pm-intel-entry');
        for (var k = 0; k < entries.length; k++) {
          var entryType = entries[k].getAttribute('data-intel-type');
          if (filterVal === 'ALL' || entryType === filterVal) {
            entries[k].style.display = '';
          } else {
            entries[k].style.display = 'none';
          }
        }
      });
    }

    // Correlation alert expand/collapse
    var corrToggles = main.querySelectorAll('[data-corr-toggle]');
    for (var c = 0; c < corrToggles.length; c++) {
      corrToggles[c].addEventListener('click', function() {
        var idx = this.getAttribute('data-corr-toggle');
        var detail = main.querySelector('[data-corr-detail="' + idx + '"]');
        if (detail) {
          var isHidden = detail.style.display === 'none';
          detail.style.display = isHidden ? 'block' : 'none';
          this.textContent = isHidden ? 'COLLAPSE' : 'EXPAND';
        }
      });
    }

    // Timeline dot click
    var timelineDots = main.querySelectorAll('.pm-timeline-dot');
    for (var td = 0; td < timelineDots.length; td++) {
      timelineDots[td].addEventListener('click', function() {
        var idx = parseInt(this.getAttribute('data-timeline-idx'));
        var feed = INTEL_FEEDS[idx];
        if (!feed) return;
        var detailEl = main.querySelector('#pm-timeline-detail');
        if (detailEl) {
          var typeColor = INTEL_TYPE_COLORS[feed.type] || '#888';
          var dhtml = '';
          dhtml += '<div class="pm-timeline-detail-inner" style="border-left:3px solid ' + typeColor + '">';
          dhtml += '<strong>' + esc(feed.id) + '</strong> [' + esc(feed.type) + '] — ' + esc(feed.source);
          dhtml += '<br>' + esc(feed.summary);
          dhtml += '<br><span style="color:#888">Reliability: ' + esc(feed.reliability) + '% | Credibility: ' + esc(feed.credibility) + '%</span>';
          dhtml += '</div>';
          detailEl.innerHTML = dhtml;
          detailEl.style.display = 'block';
        }
      });
    }

    // Publish assessment
    var publishBtn = main.querySelector('#pm-publish-assessment');
    if (publishBtn) {
      publishBtn.addEventListener('click', function() {
        var classEl = main.querySelector('#pm-analyst-class');
        var assessEl = main.querySelector('#pm-analyst-assessment');
        var classification = classEl ? classEl.value : 'UNCLASSIFIED';
        var assessment = assessEl ? assessEl.value : '';
        if (!assessment.trim()) {
          alert('Assessment text is required.');
          return;
        }
        var checked = main.querySelectorAll('.pm-checkbox:checked');
        var targets = [];
        for (var x = 0; x < checked.length; x++) {
          targets.push(checked[x].value);
        }
        alert('Assessment published at ' + classification + ' to: ' + targets.join(', '));
        if (assessEl) assessEl.value = '';
      });
    }

    // INTREP generator
    var intrepBtn = main.querySelector('#pm-gen-intrep');
    if (intrepBtn) {
      intrepBtn.addEventListener('click', function() {
        var output = main.querySelector('#pm-product-output');
        if (!output) return;
        var now = new Date().toISOString();
        var rhtml = '';
        rhtml += '<div class="pm-report-template">';
        rhtml += '<div class="pm-report-banner" style="background:#cc0000">TOP SECRET/SCI//NOFORN</div>';
        rhtml += '<div class="pm-report-title">INTELLIGENCE REPORT (INTREP)</div>';
        rhtml += '<div class="pm-report-line"><strong>DTG:</strong> ' + esc(now) + '</div>';
        rhtml += '<div class="pm-report-line"><strong>FROM:</strong> USCYBERCOM / J2 / PROMETHEUS FUSION CENTER</div>';
        rhtml += '<div class="pm-report-line"><strong>TO:</strong> DISTRIBUTION LIST ALPHA</div>';
        rhtml += '<div class="pm-report-line"><strong>SUBJ:</strong> INTREP — CYBER THREAT ASSESSMENT</div>';
        rhtml += '<hr class="pm-report-hr">';
        rhtml += '<div class="pm-report-line"><strong>1. (TS/SCI) SITUATION:</strong></div>';
        rhtml += '<div class="pm-report-body">Multiple intelligence streams indicate coordinated adversary cyber operations targeting critical infrastructure. Analysis of SIGINT, CYBINT, and HUMINT sources reveals pre-positioning activity consistent with preparation for destructive cyber attacks.</div>';
        rhtml += '<div class="pm-report-line"><strong>2. (TS/SCI) KEY JUDGMENTS:</strong></div>';
        rhtml += '<div class="pm-report-body">a. HIGH CONFIDENCE: Nation-state actor conducting reconnaissance against energy sector SCADA/ICS systems.<br>';
        rhtml += 'b. MODERATE CONFIDENCE: Timeline for potential attack estimated at 48-72 hours.<br>';
        rhtml += 'c. LOW CONFIDENCE: Secondary targets may include water treatment and transportation systems.</div>';
        rhtml += '<div class="pm-report-line"><strong>3. (S) SOURCES:</strong></div>';
        rhtml += '<div class="pm-report-body">' + esc(INTEL_FEEDS.length) + ' intelligence products from ' + esc(CORRELATION_ALERTS.length) + ' correlated streams.</div>';
        rhtml += '<div class="pm-report-line"><strong>4. (U) RECOMMENDATIONS:</strong></div>';
        rhtml += '<div class="pm-report-body">Elevate sector-specific threat level. Activate enhanced monitoring protocols. Coordinate with allied cyber commands.</div>';
        rhtml += '<div class="pm-report-banner" style="background:#cc0000">TOP SECRET/SCI//NOFORN</div>';
        rhtml += '</div>';
        output.innerHTML = rhtml;
      });
    }

    // SPOT report generator
    var spotBtn = main.querySelector('#pm-gen-spot');
    if (spotBtn) {
      spotBtn.addEventListener('click', function() {
        var output = main.querySelector('#pm-product-output');
        if (!output) return;
        var now = new Date().toISOString();
        var rhtml = '';
        rhtml += '<div class="pm-report-template">';
        rhtml += '<div class="pm-report-banner" style="background:#ff6600">SECRET//REL TO USA, FVEY</div>';
        rhtml += '<div class="pm-report-title">SPOT REPORT (SPOTREP)</div>';
        rhtml += '<div class="pm-report-line"><strong>DTG:</strong> ' + esc(now) + '</div>';
        rhtml += '<div class="pm-report-line"><strong>UNIT:</strong> PROMETHEUS CYBER FUSION</div>';
        rhtml += '<hr class="pm-report-hr">';
        rhtml += '<div class="pm-report-line"><strong>LINE 1 — DATE/TIME:</strong> ' + esc(now) + '</div>';
        rhtml += '<div class="pm-report-line"><strong>LINE 2 — UNIT/ACTIVITY:</strong> Adversary cyber unit conducting active operations</div>';
        rhtml += '<div class="pm-report-line"><strong>LINE 3 — SIZE:</strong> Estimated 15-25 operators across multiple cells</div>';
        rhtml += '<div class="pm-report-line"><strong>LINE 4 — EQUIPMENT:</strong> Custom implants, zero-day exploits, C2 infrastructure spanning 12 countries</div>';
        rhtml += '<div class="pm-report-line"><strong>LINE 5 — LOCATION:</strong> Cyberspace — targeting US critical infrastructure sectors</div>';
        rhtml += '<div class="pm-report-line"><strong>LINE 6 — ACTIVITY:</strong> Reconnaissance and pre-positioning for potential destructive attack</div>';
        rhtml += '<div class="pm-report-line"><strong>LINE 7 — TIME OBSERVED:</strong> Ongoing — first detected 72 hours ago</div>';
        rhtml += '<div class="pm-report-line"><strong>LINE 8 — REPORTING:</strong> SIGINT/CYBINT/HUMINT convergence</div>';
        rhtml += '<div class="pm-report-line"><strong>LINE 9 — NARRATIVE:</strong></div>';
        rhtml += '<div class="pm-report-body">Adversary cyber operations unit has been detected conducting multi-phase intrusion campaign against US critical infrastructure. Initial access vectors include spearphishing with custom payloads and exploitation of edge device vulnerabilities. Pre-positioned implants identified in energy sector networks. Assessment: HIGH probability of escalation within 48 hours. Recommend immediate defensive posture adjustment.</div>';
        rhtml += '<div class="pm-report-banner" style="background:#ff6600">SECRET//REL TO USA, FVEY</div>';
        rhtml += '</div>';
        output.innerHTML = rhtml;
      });
    }
  }

  // =========================================================================
  // TAB 5: PREDICTIVE THREATS
  // =========================================================================

  function renderPredict() {
    var html = '';
    html += '<div class="pm-section-header">PREDICTIVE THREAT ENGINE</div>';

    // Horizon filter
    html += '<div class="pm-filter-bar">';
    html += '<span class="pm-filter-label">FORECAST HORIZON:</span>';
    html += '<button class="pm-filter-btn pm-filter-active" data-predict-horizon="ALL">ALL</button>';
    html += '<button class="pm-filter-btn" data-predict-horizon="24h">24 HOURS</button>';
    html += '<button class="pm-filter-btn" data-predict-horizon="48h">48 HOURS</button>';
    html += '<button class="pm-filter-btn" data-predict-horizon="72h">72 HOURS</button>';
    html += '</div>';

    // Historical accuracy metrics
    html += '<div class="pm-accuracy-bar">';
    html += '<div class="pm-accuracy-item">';
    html += '<span class="pm-accuracy-label">24H ACCURACY</span>';
    html += '<span class="pm-accuracy-value" style="color:#00ff88">87%</span>';
    html += '<span class="pm-accuracy-trend" style="color:#00ff88">&#9650; +2.1%</span>';
    html += '</div>';
    html += '<div class="pm-accuracy-item">';
    html += '<span class="pm-accuracy-label">48H ACCURACY</span>';
    html += '<span class="pm-accuracy-value" style="color:#ffaa00">73%</span>';
    html += '<span class="pm-accuracy-trend" style="color:#ffaa00">&#9650; +0.8%</span>';
    html += '</div>';
    html += '<div class="pm-accuracy-item">';
    html += '<span class="pm-accuracy-label">72H ACCURACY</span>';
    html += '<span class="pm-accuracy-value" style="color:#ff6600">61%</span>';
    html += '<span class="pm-accuracy-trend" style="color:#ff4444">&#9660; -1.3%</span>';
    html += '</div>';
    html += '<div class="pm-accuracy-item">';
    html += '<span class="pm-accuracy-label">TOTAL PREDICTIONS</span>';
    html += '<span class="pm-accuracy-value" style="color:#00bfff">' + esc(THREAT_PREDICTIONS.length) + '</span>';
    html += '<span class="pm-accuracy-trend" style="color:#888">ACTIVE</span>';
    html += '</div>';
    html += '</div>';

    // Active prediction alerts (confidence > 70%)
    var highConf = [];
    for (var h = 0; h < THREAT_PREDICTIONS.length; h++) {
      if (THREAT_PREDICTIONS[h].confidence > 70) highConf.push(THREAT_PREDICTIONS[h]);
    }
    if (highConf.length > 0) {
      html += '<div class="pm-alert-box pm-alert-critical">';
      html += '<div class="pm-alert-box-title">&#9888; ACTIVE HIGH-CONFIDENCE PREDICTIONS (' + highConf.length + ')</div>';
      for (var a = 0; a < highConf.length; a++) {
        html += '<div class="pm-alert-line">';
        html += '<span class="pm-dot" style="background:' + (highConf[a].confidence >= 85 ? '#ff4444' : '#ffaa00') + '"></span> ';
        html += esc(highConf[a].name) + ' — <strong>' + esc(highConf[a].confidence) + '%</strong> confidence';
        html += ' — Horizon: ' + esc(highConf[a].horizon);
        html += '</div>';
      }
      html += '</div>';
    }

    // Threat forecast cards
    html += '<div class="pm-section-sub">THREAT FORECAST</div>';
    html += '<div class="pm-predict-grid" id="pm-predict-grid">';
    for (var p = 0; p < THREAT_PREDICTIONS.length; p++) {
      var pred = THREAT_PREDICTIONS[p];
      var confColor = pred.confidence >= 80 ? '#ff4444' : pred.confidence >= 60 ? '#ffaa00' : '#00bfff';
      var statusColor = pred.status === 'ACTIVE' ? '#ff4444' : pred.status === 'MONITORING' ? '#ffaa00' : '#00ff88';
      html += '<div class="pm-predict-card" data-predict-horizon="' + esc(pred.horizon) + '" data-predict-idx="' + p + '">';
      html += '<div class="pm-predict-card-header">';
      html += '<span class="pm-predict-horizon-badge" style="background:' + (pred.horizon === '24h' ? '#ff4444' : pred.horizon === '48h' ? '#ffaa00' : '#00bfff') + '">';
      html += esc(pred.horizon) + '</span>';
      html += '<span class="pm-predict-status" style="color:' + statusColor + '">' + esc(pred.status) + '</span>';
      html += '</div>';
      html += '<div class="pm-predict-name">' + esc(pred.name) + '</div>';

      // Confidence ring (SVG)
      var circR = 30;
      var circC = 2 * Math.PI * circR;
      var confDash = (pred.confidence / 100) * circC;
      html += '<div class="pm-predict-ring">';
      html += '<svg width="80" height="80" viewBox="0 0 80 80">';
      html += '<circle cx="40" cy="40" r="' + circR + '" fill="none" stroke="#222" stroke-width="5"/>';
      html += '<circle cx="40" cy="40" r="' + circR + '" fill="none" stroke="' + confColor + '" stroke-width="5" ';
      html += 'stroke-dasharray="' + confDash.toFixed(1) + ' ' + circC.toFixed(1) + '" ';
      html += 'stroke-linecap="round" transform="rotate(-90 40 40)"/>';
      html += '<text x="40" y="44" text-anchor="middle" fill="' + confColor + '" font-size="14" font-family="monospace">';
      html += esc(pred.confidence) + '%</text>';
      html += '</svg>';
      html += '</div>';

      html += '<div class="pm-predict-detail" style="display:none" data-predict-detail="' + p + '">';
      html += '<div class="pm-predict-field"><span class="pm-label-sm">TARGETS:</span> ' + esc(pred.targets.join(', ')) + '</div>';
      html += '<div class="pm-predict-field"><span class="pm-label-sm">INDICATORS:</span> ' + esc(pred.indicators.join(', ')) + '</div>';
      html += '<div class="pm-predict-field"><span class="pm-label-sm">ACTOR:</span> ' + esc(pred.actor || 'Unknown') + '</div>';
      html += '<div class="pm-predict-field"><span class="pm-label-sm">IMPACT:</span> ' + esc(pred.impact || 'Assessment pending') + '</div>';
      html += '</div>';
      html += '<button class="pm-predict-expand" data-predict-toggle="' + p + '">DETAILS</button>';
      html += '</div>';
    }
    html += '</div>'; // pm-predict-grid

    // Geopolitical trigger correlation
    html += '<div class="pm-section-sub">GEOPOLITICAL TRIGGER CORRELATION</div>';
    html += '<table class="pm-table">';
    html += '<thead><tr><th>REGION</th><th>EVENT</th><th>PROBABILITY</th><th>IMPACT AREAS</th><th>ESCALATION RISK</th></tr></thead>';
    html += '<tbody>';
    for (var g = 0; g < GEO_TRIGGERS.length; g++) {
      var geo = GEO_TRIGGERS[g];
      var probColor = geo.probability >= 70 ? '#ff4444' : geo.probability >= 40 ? '#ffaa00' : '#00ff88';
      var escRiskColor = geo.escalationRisk === 'CRITICAL' ? '#ff4444' : geo.escalationRisk === 'HIGH' ? '#ff6600' : geo.escalationRisk === 'MEDIUM' ? '#ffaa00' : '#00ff88';
      html += '<tr>';
      html += '<td>' + esc(geo.region) + '</td>';
      html += '<td>' + esc(geo.event) + '</td>';
      html += '<td>';
      html += '<div class="pm-prob-bar-container">';
      html += '<div class="pm-prob-bar" style="width:' + geo.probability + '%;background:' + probColor + '"></div>';
      html += '</div>';
      html += '<span style="color:' + probColor + '">' + esc(geo.probability) + '%</span>';
      html += '</td>';
      html += '<td>' + esc(geo.impactAreas.join(', ')) + '</td>';
      html += '<td><span class="pm-risk-badge" style="background:' + escRiskColor + ';color:#000">' + esc(geo.escalationRisk) + '</span></td>';
      html += '</tr>';
    }
    html += '</tbody></table>';

    // Threat trend graph
    html += '<div class="pm-section-sub">THREAT TREND (LAST 30 DAYS)</div>';
    html += '<canvas id="pm-trend-canvas" class="pm-canvas" width="900" height="250"></canvas>';

    // What-if scenario tool
    html += '<div class="pm-section-sub">WHAT-IF SCENARIO ANALYSIS</div>';
    html += '<div class="pm-whatif-panel">';
    html += '<div class="pm-whatif-inputs">';
    html += '<div class="pm-form-group">';
    html += '<label class="pm-label">EVENT TYPE</label>';
    html += '<select class="pm-select" id="pm-whatif-event">';
    html += '<option value="sanctions">Economic Sanctions Imposed</option>';
    html += '<option value="military">Military Escalation</option>';
    html += '<option value="cyber_attack">Major Cyber Attack</option>';
    html += '<option value="election">Election Interference Detected</option>';
    html += '<option value="infrastructure">Infrastructure Failure</option>';
    html += '<option value="treaty">Treaty Withdrawal</option>';
    html += '<option value="espionage">Espionage Exposure</option>';
    html += '</select>';
    html += '</div>';
    html += '<div class="pm-form-group">';
    html += '<label class="pm-label">TARGET REGION</label>';
    html += '<select class="pm-select" id="pm-whatif-region">';
    html += '<option value="east_asia">East Asia</option>';
    html += '<option value="europe">Europe</option>';
    html += '<option value="middle_east">Middle East</option>';
    html += '<option value="south_asia">South Asia</option>';
    html += '<option value="americas">Americas</option>';
    html += '<option value="africa">Africa</option>';
    html += '<option value="global">Global</option>';
    html += '</select>';
    html += '</div>';
    html += '<div class="pm-form-group">';
    html += '<label class="pm-label">SEVERITY: <span id="pm-whatif-sev-display">5</span>/10</label>';
    html += '<input type="range" class="pm-range" id="pm-whatif-severity" min="1" max="10" value="5">';
    html += '</div>';
    html += '<button class="pm-btn pm-btn-primary" id="pm-whatif-analyze">ANALYZE SCENARIO</button>';
    html += '</div>';
    html += '<div class="pm-whatif-output" id="pm-whatif-output">';
    html += '<div class="pm-product-placeholder">Configure scenario parameters and run analysis.</div>';
    html += '</div>';
    html += '</div>';

    return html;
  }

  function drawTrendGraph() {
    var canvas = main.querySelector('#pm-trend-canvas');
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var w = canvas.width;
    var h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    // Background grid
    ctx.strokeStyle = '#1a3a1a';
    ctx.lineWidth = 0.5;
    for (var gy = 0; gy < h; gy += 25) {
      ctx.beginPath();
      ctx.moveTo(0, gy);
      ctx.lineTo(w, gy);
      ctx.stroke();
    }
    for (var gx = 0; gx < w; gx += 30) {
      ctx.beginPath();
      ctx.moveTo(gx, 0);
      ctx.lineTo(gx, h);
      ctx.stroke();
    }

    // Generate 30 days of synthetic threat data
    var data = [];
    var base = 12;
    for (var d = 0; d < 30; d++) {
      base += Math.floor(Math.random() * 7) - 3;
      if (base < 3) base = 3;
      if (base > 30) base = 30;
      data.push(base);
    }

    var maxVal = 35;
    var padL = 50;
    var padR = 20;
    var padT = 20;
    var padB = 30;
    var plotW = w - padL - padR;
    var plotH = h - padT - padB;

    // Y-axis labels
    ctx.fillStyle = '#888';
    ctx.font = '10px monospace';
    ctx.textAlign = 'right';
    for (var yl = 0; yl <= maxVal; yl += 5) {
      var yy = padT + plotH - (yl / maxVal) * plotH;
      ctx.fillText(String(yl), padL - 8, yy + 3);
      ctx.strokeStyle = '#1a3a1a';
      ctx.beginPath();
      ctx.moveTo(padL, yy);
      ctx.lineTo(w - padR, yy);
      ctx.stroke();
    }

    // X-axis labels
    ctx.textAlign = 'center';
    for (var xl = 0; xl < 30; xl += 5) {
      var xx = padL + (xl / 29) * plotW;
      ctx.fillText((xl - 29) + 'd', xx, h - 5);
    }

    // Area fill
    ctx.beginPath();
    ctx.moveTo(padL, padT + plotH);
    for (var i = 0; i < data.length; i++) {
      var px = padL + (i / 29) * plotW;
      var py = padT + plotH - (data[i] / maxVal) * plotH;
      ctx.lineTo(px, py);
    }
    ctx.lineTo(padL + plotW, padT + plotH);
    ctx.closePath();
    var grad = ctx.createLinearGradient(0, padT, 0, padT + plotH);
    grad.addColorStop(0, 'rgba(255,68,68,0.3)');
    grad.addColorStop(1, 'rgba(255,68,68,0.02)');
    ctx.fillStyle = grad;
    ctx.fill();

    // Line
    ctx.beginPath();
    ctx.strokeStyle = '#ff4444';
    ctx.lineWidth = 2;
    for (var j = 0; j < data.length; j++) {
      var lx = padL + (j / 29) * plotW;
      var ly = padT + plotH - (data[j] / maxVal) * plotH;
      if (j === 0) ctx.moveTo(lx, ly);
      else ctx.lineTo(lx, ly);
    }
    ctx.stroke();

    // Data points
    for (var k = 0; k < data.length; k++) {
      var dx = padL + (k / 29) * plotW;
      var dy = padT + plotH - (data[k] / maxVal) * plotH;
      ctx.beginPath();
      ctx.arc(dx, dy, 3, 0, Math.PI * 2);
      ctx.fillStyle = data[k] > 20 ? '#ff4444' : data[k] > 12 ? '#ffaa00' : '#00ff88';
      ctx.fill();
    }

    // Title
    ctx.fillStyle = '#00ff88';
    ctx.font = 'bold 12px monospace';
    ctx.textAlign = 'left';
    ctx.fillText('DAILY THREAT COUNT', padL, 14);
  }

  function bindPredict() {
    // Horizon filter buttons
    var horizonBtns = main.querySelectorAll('[data-predict-horizon]');
    var isBtn = function(el) { return el.tagName === 'BUTTON'; };
    for (var i = 0; i < horizonBtns.length; i++) {
      if (!isBtn(horizonBtns[i])) continue;
      horizonBtns[i].addEventListener('click', function() {
        var horizon = this.getAttribute('data-predict-horizon');
        var allBtns = main.querySelectorAll('button[data-predict-horizon]');
        for (var j = 0; j < allBtns.length; j++) {
          allBtns[j].classList.remove('pm-filter-active');
        }
        this.classList.add('pm-filter-active');
        var cards = main.querySelectorAll('.pm-predict-card');
        for (var k = 0; k < cards.length; k++) {
          var cardHorizon = cards[k].getAttribute('data-predict-horizon');
          if (horizon === 'ALL' || cardHorizon === horizon) {
            cards[k].style.display = '';
          } else {
            cards[k].style.display = 'none';
          }
        }
      });
    }

    // Prediction card expand/collapse
    var predToggles = main.querySelectorAll('[data-predict-toggle]');
    for (var p = 0; p < predToggles.length; p++) {
      predToggles[p].addEventListener('click', function() {
        var idx = this.getAttribute('data-predict-toggle');
        var detail = main.querySelector('[data-predict-detail="' + idx + '"]');
        if (detail) {
          var isHidden = detail.style.display === 'none';
          detail.style.display = isHidden ? 'block' : 'none';
          this.textContent = isHidden ? 'COLLAPSE' : 'DETAILS';
        }
      });
    }

    // Severity slider display
    var sevSlider = main.querySelector('#pm-whatif-severity');
    var sevDisplay = main.querySelector('#pm-whatif-sev-display');
    if (sevSlider && sevDisplay) {
      sevSlider.addEventListener('input', function() {
        sevDisplay.textContent = this.value;
      });
    }

    // What-if analysis
    var whatifBtn = main.querySelector('#pm-whatif-analyze');
    if (whatifBtn) {
      whatifBtn.addEventListener('click', function() {
        var eventEl = main.querySelector('#pm-whatif-event');
        var regionEl = main.querySelector('#pm-whatif-region');
        var sevEl = main.querySelector('#pm-whatif-severity');
        var outputEl = main.querySelector('#pm-whatif-output');
        if (!eventEl || !regionEl || !sevEl || !outputEl) return;

        var eventType = eventEl.value;
        var region = regionEl.value;
        var severity = parseInt(sevEl.value);

        var eventLabels = {
          sanctions: 'Economic Sanctions', military: 'Military Escalation',
          cyber_attack: 'Major Cyber Attack', election: 'Election Interference',
          infrastructure: 'Infrastructure Failure', treaty: 'Treaty Withdrawal',
          espionage: 'Espionage Exposure'
        };
        var regionLabels = {
          east_asia: 'East Asia', europe: 'Europe', middle_east: 'Middle East',
          south_asia: 'South Asia', americas: 'Americas', africa: 'Africa', global: 'Global'
        };

        var cyberProb = Math.min(95, 30 + severity * 7);
        var econImpact = (severity * 12.5).toFixed(1);
        var escRisk = severity >= 8 ? 'CRITICAL' : severity >= 5 ? 'HIGH' : severity >= 3 ? 'MODERATE' : 'LOW';
        var escColor = severity >= 8 ? '#ff4444' : severity >= 5 ? '#ff6600' : severity >= 3 ? '#ffaa00' : '#00ff88';
        var timeframe = severity >= 7 ? '24-48 hours' : severity >= 4 ? '48-96 hours' : '1-2 weeks';

        var ohtml = '';
        ohtml += '<div class="pm-whatif-result">';
        ohtml += '<div class="pm-whatif-result-title">SCENARIO ANALYSIS RESULTS</div>';
        ohtml += '<div class="pm-whatif-scenario-desc">';
        ohtml += 'Event: <strong>' + esc(eventLabels[eventType] || eventType) + '</strong> | ';
        ohtml += 'Region: <strong>' + esc(regionLabels[region] || region) + '</strong> | ';
        ohtml += 'Severity: <strong>' + esc(severity) + '/10</strong>';
        ohtml += '</div>';
        ohtml += '<div class="pm-whatif-metrics">';
        ohtml += '<div class="pm-metric-card">';
        ohtml += '<div class="pm-metric-label">CYBER RETALIATION PROBABILITY</div>';
        ohtml += '<div class="pm-metric-value" style="color:' + (cyberProb >= 70 ? '#ff4444' : '#ffaa00') + '">' + esc(cyberProb) + '%</div>';
        ohtml += '</div>';
        ohtml += '<div class="pm-metric-card">';
        ohtml += '<div class="pm-metric-label">ESTIMATED ECONOMIC IMPACT</div>';
        ohtml += '<div class="pm-metric-value" style="color:#ffaa00">$' + esc(econImpact) + 'B</div>';
        ohtml += '</div>';
        ohtml += '<div class="pm-metric-card">';
        ohtml += '<div class="pm-metric-label">ESCALATION RISK</div>';
        ohtml += '<div class="pm-metric-value" style="color:' + escColor + '">' + esc(escRisk) + '</div>';
        ohtml += '</div>';
        ohtml += '<div class="pm-metric-card">';
        ohtml += '<div class="pm-metric-label">EXPECTED TIMEFRAME</div>';
        ohtml += '<div class="pm-metric-value" style="color:#00bfff">' + esc(timeframe) + '</div>';
        ohtml += '</div>';
        ohtml += '</div>';
        ohtml += '<div class="pm-whatif-assessment">';
        ohtml += '<strong>ASSESSMENT:</strong> ';
        if (severity >= 7) {
          ohtml += 'HIGH PROBABILITY of retaliatory cyber operations within ' + esc(timeframe) + '. ';
          ohtml += 'Recommend immediate defensive posture elevation, critical infrastructure hardening, and allied coordination. ';
          ohtml += 'Potential for cascading effects across multiple sectors.';
        } else if (severity >= 4) {
          ohtml += 'MODERATE PROBABILITY of adversary cyber response within ' + esc(timeframe) + '. ';
          ohtml += 'Recommend enhanced monitoring and preparation of response playbooks. ';
          ohtml += 'Targeted operations against specific sectors most likely.';
        } else {
          ohtml += 'LOW PROBABILITY of significant cyber retaliation in near term. ';
          ohtml += 'Recommend maintaining baseline monitoring posture. ';
          ohtml += 'Diplomatic channels may mitigate escalation potential.';
        }
        ohtml += '</div>';
        ohtml += '</div>';
        outputEl.innerHTML = ohtml;
      });
    }

    // Draw trend graph
    drawTrendGraph();
  }

  // =========================================================================
  // TAB 6: ENGAGEMENT PLANNER
  // =========================================================================

  var ATTACK_PHASES = [
    { id: 'recon', name: 'RECONNAISSANCE', techniques: ['Open Source Collection', 'Active Scanning', 'Social Engineering Recon', 'DNS Enumeration', 'Network Mapping'], duration: '2-5 days', icon: '[R]' },
    { id: 'initial', name: 'INITIAL ACCESS', techniques: ['Spearphishing', 'Exploit Public-Facing App', 'Supply Chain Compromise', 'Valid Credentials', 'External Remote Services'], duration: '1-3 days', icon: '[+]' },
    { id: 'persist', name: 'PERSISTENCE', techniques: ['Web Shell', 'Scheduled Task', 'Registry Run Keys', 'Create Account', 'Implant'], duration: '1-2 days', icon: '&#9875;' },
    { id: 'privesc', name: 'PRIVILEGE ESCALATION', techniques: ['Exploit Vulnerability', 'Token Manipulation', 'Bypass UAC', 'Sudo Exploitation', 'Kernel Exploit'], duration: '1-3 days', icon: '&#9889;' },
    { id: 'collect', name: 'COLLECTION', techniques: ['Keylogging', 'Screen Capture', 'Email Collection', 'Database Dump', 'Clipboard Data'], duration: '3-7 days', icon: '[C]' },
    { id: 'exfil', name: 'EXFILTRATION', techniques: ['C2 Channel', 'DNS Tunneling', 'Steganography', 'Cloud Storage', 'Physical Medium'], duration: '1-2 days', icon: '[E]' }
  ];

  var ROE_RULES = [
    { id: 'roe-1', rule: 'Minimize civilian impact', desc: 'Operations must avoid disruption to civilian services where possible' },
    { id: 'roe-2', rule: 'Proportional response', desc: 'Response must be proportional to the threat posed' },
    { id: 'roe-3', rule: 'Legal authority confirmed', desc: 'Proper legal authority (Title 10/50) must be verified' },
    { id: 'roe-4', rule: 'Collateral damage assessed', desc: 'Potential collateral effects must be evaluated and documented' },
    { id: 'roe-5', rule: 'Attribution confidence threshold', desc: 'Minimum 80% attribution confidence before engagement' },
    { id: 'roe-6', rule: 'Diplomatic notification', desc: 'Relevant diplomatic channels must be notified per policy' },
    { id: 'roe-7', rule: 'Reversibility preference', desc: 'Prefer reversible effects over irreversible when mission allows' },
    { id: 'roe-8', rule: 'Coalition partner coordination', desc: 'Allied partners must be informed of operations in their AOR' },
    { id: 'roe-9', rule: 'Escalation de-confliction', desc: 'Operations must not trigger unintended escalation' },
    { id: 'roe-10', rule: 'Evidence preservation', desc: 'Sufficient evidence must be preserved for post-operation review' }
  ];

  var LEGAL_AUTHORITY_MATRIX = [
    { operation: 'Defensive Cyber Operations (DCO)', authority: 'Title 10 SECDEF EXORD', level: 2, authorized: true },
    { operation: 'Offensive Cyber Operations (OCO)', authority: 'Title 10 Presidential EXORD', level: 4, authorized: false },
    { operation: 'Intelligence Collection', authority: 'Title 50 / EO 12333', level: 2, authorized: true },
    { operation: 'Covert Action', authority: 'Title 50 Presidential Finding', level: 5, authorized: false },
    { operation: 'Hunt Forward Operations', authority: 'Title 10 Partner Nation Agreement', level: 3, authorized: true },
    { operation: 'Emergency Cyber Defense', authority: 'Title 10 Standing EXORD', level: 1, authorized: true },
    { operation: 'Cyber Effects Against Infrastructure', authority: 'Title 10 Presidential Auth', level: 5, authorized: false },
    { operation: 'Counter-Intelligence Ops', authority: 'Title 50 / FBI Lead', level: 3, authorized: true }
  ];

  function renderEngage() {
    var html = '';
    html += '<div class="pm-section-header">ENGAGEMENT PLANNER</div>';

    html += '<div class="pm-engage-grid">';

    // Target selection
    html += '<div class="pm-engage-target">';
    html += '<div class="pm-panel-title">TARGET SELECTION</div>';
    html += '<div class="pm-form-group">';
    html += '<label class="pm-label">SELECT TARGET</label>';
    html += '<select class="pm-select" id="pm-engage-target-select">';
    html += '<option value="">— Select Target —</option>';
    var sectors = {};
    for (var n = 0; n < INFRA_NODES.length; n++) {
      var node = INFRA_NODES[n];
      if (!sectors[node.sector]) sectors[node.sector] = [];
      sectors[node.sector].push(node);
    }
    var sectorKeys = Object.keys(sectors);
    for (var sk = 0; sk < sectorKeys.length; sk++) {
      html += '<optgroup label="' + esc(sectorKeys[sk]) + '">';
      var sectorNodes = sectors[sectorKeys[sk]];
      for (var sn = 0; sn < sectorNodes.length; sn++) {
        html += '<option value="' + esc(sectorNodes[sn].id) + '">' + esc(sectorNodes[sn].name) + '</option>';
      }
      html += '</optgroup>';
    }
    html += '</select>';
    html += '</div>';
    html += '<div class="pm-target-detail" id="pm-target-detail">';
    html += '<div class="pm-product-placeholder">Select a target to view details.</div>';
    html += '</div>';
    html += '</div>'; // pm-engage-target

    // Collateral damage estimator
    html += '<div class="pm-engage-collateral">';
    html += '<div class="pm-panel-title">COLLATERAL DAMAGE ESTIMATE</div>';
    html += '<div class="pm-cde-metrics" id="pm-cde-metrics">';
    html += '<div class="pm-metric-card"><div class="pm-metric-label">POPULATION IMPACT</div><div class="pm-metric-value" style="color:#888">N/A</div></div>';
    html += '<div class="pm-metric-card"><div class="pm-metric-label">ECONOMIC COST</div><div class="pm-metric-value" style="color:#888">N/A</div></div>';
    html += '<div class="pm-metric-card"><div class="pm-metric-label">SERVICE DISRUPTION</div><div class="pm-metric-value" style="color:#888">N/A</div></div>';
    html += '<div class="pm-metric-card"><div class="pm-metric-label">RECOVERY TIME</div><div class="pm-metric-value" style="color:#888">N/A</div></div>';
    html += '</div>';
    html += '</div>';

    html += '</div>'; // pm-engage-grid

    // Attack phase builder
    html += '<div class="pm-section-sub">ATTACK PHASE BUILDER</div>';
    html += '<div class="pm-phase-timeline">';
    for (var ph = 0; ph < ATTACK_PHASES.length; ph++) {
      var phase = ATTACK_PHASES[ph];
      html += '<div class="pm-phase-step">';
      html += '<div class="pm-phase-icon">' + phase.icon + '</div>';
      html += '<div class="pm-phase-name">' + esc(phase.name) + '</div>';
      html += '<div class="pm-phase-duration">' + esc(phase.duration) + '</div>';
      html += '<select class="pm-select pm-phase-technique" data-phase-id="' + esc(phase.id) + '">';
      html += '<option value="">— Select Technique —</option>';
      for (var pt = 0; pt < phase.techniques.length; pt++) {
        html += '<option value="' + esc(phase.techniques[pt]) + '">' + esc(phase.techniques[pt]) + '</option>';
      }
      html += '</select>';
      html += '<textarea class="pm-textarea pm-phase-notes" data-phase-notes="' + esc(phase.id) + '" rows="2" placeholder="Notes..."></textarea>';
      if (ph < ATTACK_PHASES.length - 1) {
        html += '<div class="pm-phase-connector">&#9654;</div>';
      }
      html += '</div>';
    }
    html += '</div>';

    // ROE compliance checker
    html += '<div class="pm-section-sub">RULES OF ENGAGEMENT COMPLIANCE</div>';
    html += '<div class="pm-roe-grid" id="pm-roe-grid">';
    for (var r = 0; r < ROE_RULES.length; r++) {
      var roe = ROE_RULES[r];
      var roePass = r < 4 || r === 9;
      html += '<div class="pm-roe-item">';
      html += '<span class="pm-roe-icon" style="color:' + (roePass ? '#00ff88' : '#ff4444') + '">' + (roePass ? '&#10004;' : '&#10008;') + '</span>';
      html += '<div class="pm-roe-text">';
      html += '<div class="pm-roe-rule">' + esc(roe.rule) + '</div>';
      html += '<div class="pm-roe-desc">' + esc(roe.desc) + '</div>';
      html += '</div>';
      html += '</div>';
    }
    html += '</div>';

    // Operation timeline
    html += '<div class="pm-section-sub">OPERATION TIMELINE (ESTIMATED)</div>';
    html += '<div class="pm-op-timeline" id="pm-op-timeline">';
    var totalDays = 0;
    for (var ot = 0; ot < ATTACK_PHASES.length; ot++) {
      var otPhase = ATTACK_PHASES[ot];
      var daysMatch = otPhase.duration.match(/(\d+)-(\d+)/);
      var avgDays = daysMatch ? Math.ceil((parseInt(daysMatch[1]) + parseInt(daysMatch[2])) / 2) : 3;
      html += '<div class="pm-op-tl-item">';
      html += '<div class="pm-op-tl-bar" style="width:' + (avgDays * 40) + 'px;background:' + (ot % 2 === 0 ? '#00bfff' : '#00ff88') + '">';
      html += esc(otPhase.name);
      html += '</div>';
      html += '<span class="pm-op-tl-days">Day ' + esc(totalDays) + '-' + esc(totalDays + avgDays) + '</span>';
      html += '</div>';
      totalDays += avgDays;
    }
    html += '<div class="pm-op-total">TOTAL ESTIMATED DURATION: ' + esc(totalDays) + ' DAYS</div>';
    html += '</div>';

    // Legal authority verification
    html += '<div class="pm-section-sub">LEGAL AUTHORITY VERIFICATION</div>';
    html += '<table class="pm-table">';
    html += '<thead><tr><th>OPERATION TYPE</th><th>REQUIRED AUTHORITY</th><th>AUTH LEVEL</th><th>STATUS</th></tr></thead>';
    html += '<tbody>';
    for (var la = 0; la < LEGAL_AUTHORITY_MATRIX.length; la++) {
      var legal = LEGAL_AUTHORITY_MATRIX[la];
      html += '<tr>';
      html += '<td>' + esc(legal.operation) + '</td>';
      html += '<td>' + esc(legal.authority) + '</td>';
      html += '<td>LEVEL ' + esc(legal.level) + '</td>';
      html += '<td style="color:' + (legal.authorized ? '#00ff88' : '#ff4444') + ';font-weight:bold">' + (legal.authorized ? '&#10004; AUTHORIZED' : '&#10008; NOT AUTHORIZED') + '</td>';
      html += '</tr>';
    }
    html += '</tbody></table>';

    // Plan export
    html += '<div class="pm-section-sub">EXPORT OPERATION PLAN</div>';
    html += '<button class="pm-btn pm-btn-primary" id="pm-export-plan">EXPORT PLAN</button>';
    html += '<textarea class="pm-textarea pm-plan-output" id="pm-plan-output" rows="12" readonly style="display:none"></textarea>';

    return html;
  }

  function bindEngage() {
    // Target selection handler
    var targetSelect = main.querySelector('#pm-engage-target-select');
    if (targetSelect) {
      targetSelect.addEventListener('change', function() {
        var targetId = this.value;
        var detailEl = main.querySelector('#pm-target-detail');
        var cdeEl = main.querySelector('#pm-cde-metrics');
        if (!targetId) {
          if (detailEl) detailEl.innerHTML = '<div class="pm-product-placeholder">Select a target to view details.</div>';
          return;
        }
        var target = null;
        for (var i = 0; i < INFRA_NODES.length; i++) {
          if (INFRA_NODES[i].id === targetId) { target = INFRA_NODES[i]; break; }
        }
        if (!target || !detailEl) return;
        var dhtml = '';
        dhtml += '<div class="pm-target-info">';
        dhtml += '<div class="pm-target-name">' + esc(target.name) + '</div>';
        dhtml += '<div class="pm-target-field">SECTOR: ' + esc(target.sector) + '</div>';
        dhtml += '<div class="pm-target-field">TYPE: ' + esc(target.type) + '</div>';
        dhtml += '<div class="pm-target-field">STATUS: <span style="color:' + (target.status === 'operational' ? '#00ff88' : target.status === 'degraded' ? '#ffaa00' : '#ff4444') + '">' + esc(target.status).toUpperCase() + '</span></div>';
        dhtml += '<div class="pm-target-field">CRITICALITY: ' + esc(target.criticality) + '/10</div>';
        dhtml += '<div class="pm-target-field">POPULATION SERVED: ' + esc((target.population || 0).toLocaleString()) + '</div>';
        if (target.dependencies && target.dependencies.length > 0) {
          dhtml += '<div class="pm-target-field">DEPENDENCIES: ' + esc(target.dependencies.join(', ')) + '</div>';
        }
        dhtml += '</div>';
        detailEl.innerHTML = dhtml;

        // Update collateral damage estimate
        if (cdeEl) {
          var pop = target.population || 50000;
          var econ = (pop * 0.0015).toFixed(1);
          var services = Math.min(Math.ceil(target.criticality * 1.5), 12);
          var recovery = target.criticality >= 8 ? '14-30 days' : target.criticality >= 5 ? '7-14 days' : '2-7 days';
          var chtml = '';
          chtml += '<div class="pm-metric-card"><div class="pm-metric-label">POPULATION IMPACT</div><div class="pm-metric-value" style="color:#ff4444">' + esc(pop.toLocaleString()) + '</div></div>';
          chtml += '<div class="pm-metric-card"><div class="pm-metric-label">ECONOMIC COST</div><div class="pm-metric-value" style="color:#ffaa00">$' + esc(econ) + 'M</div></div>';
          chtml += '<div class="pm-metric-card"><div class="pm-metric-label">SERVICES DISRUPTED</div><div class="pm-metric-value" style="color:#00bfff">' + esc(services) + '</div></div>';
          chtml += '<div class="pm-metric-card"><div class="pm-metric-label">RECOVERY TIME</div><div class="pm-metric-value" style="color:#ff6600">' + esc(recovery) + '</div></div>';
          cdeEl.innerHTML = chtml;
        }
      });
    }

    // Export plan
    var exportBtn = main.querySelector('#pm-export-plan');
    if (exportBtn) {
      exportBtn.addEventListener('click', function() {
        var outputEl = main.querySelector('#pm-plan-output');
        if (!outputEl) return;
        var targetEl = main.querySelector('#pm-engage-target-select');
        var targetName = targetEl ? targetEl.options[targetEl.selectedIndex].text : 'N/A';

        var plan = '';
        plan += '========================================\n';
        plan += 'OPERATION PLAN — PROMETHEUS GENERATED\n';
        plan += '========================================\n';
        plan += 'CLASSIFICATION: TOP SECRET/SCI\n';
        plan += 'DTG: ' + new Date().toISOString() + '\n';
        plan += 'TARGET: ' + targetName + '\n\n';

        var techniques = main.querySelectorAll('.pm-phase-technique');
        var notes = main.querySelectorAll('.pm-phase-notes');
        for (var i = 0; i < ATTACK_PHASES.length; i++) {
          plan += 'PHASE ' + (i + 1) + ': ' + ATTACK_PHASES[i].name + '\n';
          plan += '  Duration: ' + ATTACK_PHASES[i].duration + '\n';
          if (techniques[i]) plan += '  Technique: ' + (techniques[i].value || 'Not selected') + '\n';
          if (notes[i]) plan += '  Notes: ' + (notes[i].value || 'None') + '\n';
          plan += '\n';
        }

        plan += 'ROE COMPLIANCE: See engagement planner ROE section\n';
        plan += 'LEGAL AUTHORITY: Verify before execution\n';
        plan += '========================================\n';
        plan += 'END OPERATION PLAN\n';

        outputEl.value = plan;
        outputEl.style.display = 'block';
      });
    }
  }

  // =========================================================================
  // TAB 7: WARGAME THEATER
  // =========================================================================

  var EXERCISE_EVENTS = [
    { time: 'T+00:00', team: 'WHITE', text: 'Exercise CYBER STORM IX commenced. Scenario: Nation-state APT campaign targeting critical infrastructure.' },
    { time: 'T+00:05', team: 'RED', text: 'Initiated spearphishing campaign against energy sector employees. 500 emails sent with weaponized attachments.' },
    { time: 'T+00:12', team: 'RED', text: 'Established initial foothold via compromised user workstation in Sector A. C2 beacon activated.' },
    { time: 'T+00:15', team: 'BLUE', text: 'EDR alert triggered on anomalous process execution. SOC Tier 1 analyst investigating.' },
    { time: 'T+00:22', team: 'RED', text: 'Lateral movement to domain controller using Pass-the-Hash. Dumping NTDS.dit.' },
    { time: 'T+00:25', team: 'BLUE', text: 'Identified suspicious Kerberos activity. Escalated to Tier 2 analyst.' },
    { time: 'T+00:30', team: 'WHITE', text: 'INJECT: Media reports of similar attacks on allied nation infrastructure. Public pressure increasing.' },
    { time: 'T+00:35', team: 'RED', text: 'Deployed custom implant on 3 SCADA engineering workstations. OT network access achieved.' },
    { time: 'T+00:40', team: 'BLUE', text: 'Network segmentation alert — unauthorized traffic from IT to OT network. Incident declared.' },
    { time: 'T+00:45', team: 'RED', text: 'Reconnaissance of ICS/SCADA systems. Mapping PLC configurations and HMI interfaces.' },
    { time: 'T+00:50', team: 'BLUE', text: 'CIRT activated. Containment strategy: isolate affected segments. Starting forensic collection.' },
    { time: 'T+00:55', team: 'WHITE', text: 'INJECT: Second APT group detected exploiting same vulnerability. Multi-actor scenario activated.' },
    { time: 'T+01:00', team: 'RED', text: 'Initiated modification of PLC logic on water treatment system. Changed chemical dosing parameters.' },
    { time: 'T+01:05', team: 'BLUE', text: 'Anomalous PLC write detected by OT monitoring. Emergency manual override initiated.' },
    { time: 'T+01:10', team: 'RED', text: 'Data exfiltration via DNS tunneling — 2.3GB of classified documents staged for extraction.' },
    { time: 'T+01:15', team: 'BLUE', text: 'DNS anomaly detection flagged high-entropy queries. Sinkhole deployed. Exfil channel disrupted.' },
    { time: 'T+01:20', team: 'WHITE', text: 'INJECT: Congressional inquiry — briefing required within 2 hours. Prepare executive summary.' },
    { time: 'T+01:25', team: 'RED', text: 'Ransomware payload deployed to 150 endpoints as diversionary tactic.' },
    { time: 'T+01:30', team: 'BLUE', text: 'Ransomware containment: network isolation successful. 23 endpoints encrypted. Backup restoration initiated.' },
    { time: 'T+01:35', team: 'BLUE', text: 'Full threat actor TTPs mapped to MITRE ATT&CK. Attribution confidence: 85%. Threat intel shared with ISAC.' }
  ];

  function renderWargame() {
    var html = '';
    html += '<div class="pm-section-header">WARGAME THEATER</div>';

    // Scenario library
    html += '<div class="pm-section-sub">SCENARIO LIBRARY</div>';
    html += '<div class="pm-wargame-scenarios" id="pm-wargame-scenarios">';
    for (var w = 0; w < WARGAME_SCENARIOS.length; w++) {
      var scen = WARGAME_SCENARIOS[w];
      var diffColor = scen.difficulty === 'Expert' ? '#ff4444' : scen.difficulty === 'Hard' ? '#ff6600' : scen.difficulty === 'Medium' ? '#ffaa00' : '#00ff88';
      html += '<div class="pm-scenario-card" data-scenario-idx="' + w + '">';
      html += '<div class="pm-scenario-header">';
      html += '<span class="pm-scenario-name">' + esc(scen.name) + '</span>';
      html += '<span class="pm-scenario-diff" style="background:' + diffColor + ';color:#000">' + esc(scen.difficulty) + '</span>';
      html += '</div>';
      html += '<div class="pm-scenario-desc">' + esc(scen.description) + '</div>';
      html += '<div class="pm-scenario-meta">';
      html += '<span>DURATION: ' + esc(scen.duration) + '</span>';
      html += '<span>TEAMS: ' + esc(scen.teams.join(', ')) + '</span>';
      html += '</div>';
      html += '<button class="pm-btn pm-btn-accent pm-scenario-select" data-scenario-select="' + w + '">SELECT SCENARIO</button>';
      html += '</div>';
    }
    html += '</div>';

    // Team assignment
    html += '<div class="pm-section-sub">TEAM ASSIGNMENT</div>';
    html += '<div class="pm-team-grid">';
    var teams = [
      { name: 'RED TEAM', role: 'OFFENSE', desc: 'Execute adversary tactics, techniques, and procedures to test defensive capabilities.', color: '#ff4444', icon: '&#9876;' },
      { name: 'BLUE TEAM', role: 'DEFENSE', desc: 'Detect, respond, and recover from red team attacks using available defensive tools and procedures.', color: '#00bfff', icon: '[D]' },
      { name: 'WHITE TEAM', role: 'CONTROL', desc: 'Manage exercise flow, inject scenarios, evaluate performance, and ensure safety.', color: '#ffffff', icon: '&#9878;' }
    ];
    for (var tm = 0; tm < teams.length; tm++) {
      var team = teams[tm];
      html += '<div class="pm-team-card" style="border-color:' + team.color + '">';
      html += '<div class="pm-team-icon" style="color:' + team.color + '">' + team.icon + '</div>';
      html += '<div class="pm-team-name" style="color:' + team.color + '">' + esc(team.name) + '</div>';
      html += '<div class="pm-team-role">' + esc(team.role) + '</div>';
      html += '<div class="pm-team-desc">' + esc(team.desc) + '</div>';
      html += '<div class="pm-form-group">';
      html += '<label class="pm-label">PERSONNEL COUNT</label>';
      html += '<input type="number" class="pm-input pm-team-count" value="' + (tm === 0 ? '8' : tm === 1 ? '12' : '4') + '" min="1" max="50">';
      html += '</div>';
      html += '</div>';
    }
    html += '</div>';

    // Exercise control panel
    html += '<div class="pm-section-sub">EXERCISE CONTROL</div>';
    html += '<div class="pm-exercise-controls">';
    html += '<div class="pm-ctrl-buttons">';
    html += '<button class="pm-btn pm-btn-primary" id="pm-ex-start">&#9654; START</button>';
    html += '<button class="pm-btn pm-btn-warning" id="pm-ex-pause">&#10074;&#10074; PAUSE</button>';
    html += '<button class="pm-btn pm-btn-danger" id="pm-ex-reset">&#9632; RESET</button>';
    html += '</div>';
    html += '<div class="pm-ctrl-speed">';
    html += '<span class="pm-label">SPEED:</span>';
    html += '<button class="pm-speed-btn pm-speed-active" data-speed="1">1x</button>';
    html += '<button class="pm-speed-btn" data-speed="2">2x</button>';
    html += '<button class="pm-speed-btn" data-speed="5">5x</button>';
    html += '<button class="pm-speed-btn" data-speed="10">10x</button>';
    html += '</div>';
    html += '<div class="pm-ctrl-inject">';
    html += '<select class="pm-select" id="pm-inject-select">';
    html += '<option value="">— Select Event Inject —</option>';
    html += '<option value="media">Media Leak / Public Disclosure</option>';
    html += '<option value="second_actor">Second Threat Actor Emerges</option>';
    html += '<option value="insider">Insider Threat Detected</option>';
    html += '<option value="physical">Physical Attack Coincides</option>';
    html += '<option value="comms_loss">Communications Loss</option>';
    html += '<option value="legal">Legal Challenge to Response</option>';
    html += '<option value="supply">Supply Chain Compromise</option>';
    html += '<option value="ransom">Ransom Demand Received</option>';
    html += '</select>';
    html += '<button class="pm-btn pm-btn-accent" id="pm-inject-btn">INJECT</button>';
    html += '</div>';
    html += '<div class="pm-exercise-status" id="pm-exercise-status">';
    html += '<span class="pm-ex-status-dot" style="background:#888"></span> STANDBY — Select scenario and press START';
    html += '</div>';
    html += '</div>';

    // Live exercise timeline
    html += '<div class="pm-section-sub">EXERCISE TIMELINE</div>';
    html += '<div class="pm-exercise-timeline" id="pm-exercise-timeline">';
    for (var ev = 0; ev < EXERCISE_EVENTS.length; ev++) {
      var evt = EXERCISE_EVENTS[ev];
      var evtColor = evt.team === 'RED' ? '#ff4444' : evt.team === 'BLUE' ? '#00bfff' : '#ffffff';
      html += '<div class="pm-ex-event" data-ex-team="' + esc(evt.team) + '">';
      html += '<div class="pm-ex-event-time">' + esc(evt.time) + '</div>';
      html += '<div class="pm-ex-event-marker" style="background:' + evtColor + '"></div>';
      html += '<div class="pm-ex-event-content">';
      html += '<span class="pm-ex-event-team" style="color:' + evtColor + '">[' + esc(evt.team) + ']</span> ';
      html += esc(evt.text);
      html += '</div>';
      html += '</div>';
    }
    html += '</div>';

    // Scoring dashboard
    html += '<div class="pm-section-sub">SCORING DASHBOARD</div>';
    html += '<div class="pm-scoring-grid">';

    html += '<div class="pm-score-panel" style="border-color:#ff4444">';
    html += '<div class="pm-score-team-name" style="color:#ff4444">RED TEAM</div>';
    html += '<div class="pm-score-total" style="color:#ff4444">2,847</div>';
    html += '<div class="pm-score-breakdown">';
    html += '<div class="pm-score-item-row"><span>Initial Access</span><span>450</span></div>';
    html += '<div class="pm-score-item-row"><span>Lateral Movement</span><span>380</span></div>';
    html += '<div class="pm-score-item-row"><span>Privilege Escalation</span><span>520</span></div>';
    html += '<div class="pm-score-item-row"><span>Data Exfiltration</span><span>600</span></div>';
    html += '<div class="pm-score-item-row"><span>ICS/OT Access</span><span>700</span></div>';
    html += '<div class="pm-score-item-row"><span>Evasion Bonus</span><span>197</span></div>';
    html += '</div>';
    html += '</div>';

    html += '<div class="pm-score-panel" style="border-color:#00bfff">';
    html += '<div class="pm-score-team-name" style="color:#00bfff">BLUE TEAM</div>';
    html += '<div class="pm-score-total" style="color:#00bfff">3,215</div>';
    html += '<div class="pm-score-breakdown">';
    html += '<div class="pm-score-item-row"><span>Detection Speed</span><span>520</span></div>';
    html += '<div class="pm-score-item-row"><span>Containment Time</span><span>480</span></div>';
    html += '<div class="pm-score-item-row"><span>Forensic Quality</span><span>390</span></div>';
    html += '<div class="pm-score-item-row"><span>Recovery Speed</span><span>450</span></div>';
    html += '<div class="pm-score-item-row"><span>Threat Intel Sharing</span><span>375</span></div>';
    html += '<div class="pm-score-item-row"><span>Communication</span><span>580</span></div>';
    html += '<div class="pm-score-item-row"><span>Response Quality</span><span>420</span></div>';
    html += '</div>';
    html += '</div>';

    html += '</div>'; // pm-scoring-grid

    // After Action Review
    html += '<div class="pm-section-sub">AFTER ACTION REVIEW</div>';
    html += '<div class="pm-aar-panel" id="pm-aar-panel">';
    html += '<div class="pm-aar-section">';
    html += '<div class="pm-aar-title">KEY FINDINGS</div>';
    html += '<div class="pm-aar-item">1. Initial phishing detection took 15 minutes — within acceptable threshold but below benchmark.</div>';
    html += '<div class="pm-aar-item">2. IT/OT network segmentation was bypassed via compromised engineering workstation credentials.</div>';
    html += '<div class="pm-aar-item">3. DNS tunneling exfiltration was detected and disrupted within 15 minutes of initiation.</div>';
    html += '<div class="pm-aar-item">4. Ransomware containment was effective — limited to 23 of 500+ endpoints.</div>';
    html += '<div class="pm-aar-item">5. MITRE ATT&CK mapping completed with 85% attribution confidence within exercise timeframe.</div>';
    html += '</div>';
    html += '<div class="pm-aar-section">';
    html += '<div class="pm-aar-title">LESSONS LEARNED</div>';
    html += '<div class="pm-aar-item">&#8226; OT network monitoring requires dedicated tooling — IT-focused EDR missed lateral movement to SCADA systems.</div>';
    html += '<div class="pm-aar-item">&#8226; Incident communication procedures need streamlining — executive briefing took 45 minutes to prepare.</div>';
    html += '<div class="pm-aar-item">&#8226; Cross-sector information sharing improved response time by an estimated 20%.</div>';
    html += '<div class="pm-aar-item">&#8226; Manual override procedures for ICS systems were effective but required physical access.</div>';
    html += '</div>';
    html += '<div class="pm-aar-section">';
    html += '<div class="pm-aar-title">RECOMMENDATIONS</div>';
    html += '<div class="pm-aar-item">&#8226; Deploy OT-specific network detection and response (NDR) capabilities.</div>';
    html += '<div class="pm-aar-item">&#8226; Implement automated executive briefing template system.</div>';
    html += '<div class="pm-aar-item">&#8226; Conduct monthly tabletop exercises for IT/OT convergence scenarios.</div>';
    html += '<div class="pm-aar-item">&#8226; Establish dedicated communication channel for multi-sector incidents.</div>';
    html += '<div class="pm-aar-item">&#8226; Review and update ICS manual override procedures quarterly.</div>';
    html += '</div>';
    html += '</div>';

    return html;
  }

  function bindWargame() {
    // Scenario select
    var scenBtns = main.querySelectorAll('[data-scenario-select]');
    for (var i = 0; i < scenBtns.length; i++) {
      scenBtns[i].addEventListener('click', function() {
        var idx = parseInt(this.getAttribute('data-scenario-select'));
        var scen = WARGAME_SCENARIOS[idx];
        if (!scen) return;
        var allCards = main.querySelectorAll('.pm-scenario-card');
        for (var j = 0; j < allCards.length; j++) {
          allCards[j].style.borderColor = '#333';
        }
        this.parentElement.style.borderColor = '#00ff88';
        state.selectedScenario = idx;
        var statusEl = main.querySelector('#pm-exercise-status');
        if (statusEl) {
          statusEl.innerHTML = '<span class="pm-ex-status-dot" style="background:#ffaa00"></span> SCENARIO LOADED: ' + esc(scen.name) + ' — Press START to begin';
        }
      });
    }

    // Exercise start
    var startBtn = main.querySelector('#pm-ex-start');
    if (startBtn) {
      startBtn.addEventListener('click', function() {
        var statusEl = main.querySelector('#pm-exercise-status');
        if (statusEl) {
          statusEl.innerHTML = '<span class="pm-ex-status-dot" style="background:#00ff88"></span> EXERCISE IN PROGRESS';
        }
        state.exerciseRunning = true;
      });
    }

    // Exercise pause
    var pauseBtn = main.querySelector('#pm-ex-pause');
    if (pauseBtn) {
      pauseBtn.addEventListener('click', function() {
        var statusEl = main.querySelector('#pm-exercise-status');
        if (statusEl) {
          statusEl.innerHTML = '<span class="pm-ex-status-dot" style="background:#ffaa00"></span> EXERCISE PAUSED';
        }
        state.exerciseRunning = false;
      });
    }

    // Exercise reset
    var resetBtn = main.querySelector('#pm-ex-reset');
    if (resetBtn) {
      resetBtn.addEventListener('click', function() {
        var statusEl = main.querySelector('#pm-exercise-status');
        if (statusEl) {
          statusEl.innerHTML = '<span class="pm-ex-status-dot" style="background:#888"></span> STANDBY — Select scenario and press START';
        }
        state.exerciseRunning = false;
        state.selectedScenario = null;
        var allCards = main.querySelectorAll('.pm-scenario-card');
        for (var j = 0; j < allCards.length; j++) {
          allCards[j].style.borderColor = '#333';
        }
      });
    }

    // Speed control
    var speedBtns = main.querySelectorAll('[data-speed]');
    for (var s = 0; s < speedBtns.length; s++) {
      speedBtns[s].addEventListener('click', function() {
        var allSpeed = main.querySelectorAll('[data-speed]');
        for (var j = 0; j < allSpeed.length; j++) {
          allSpeed[j].classList.remove('pm-speed-active');
        }
        this.classList.add('pm-speed-active');
        state.exerciseSpeed = parseInt(this.getAttribute('data-speed'));
      });
    }

    // Event inject
    var injectBtn = main.querySelector('#pm-inject-btn');
    if (injectBtn) {
      injectBtn.addEventListener('click', function() {
        var selectEl = main.querySelector('#pm-inject-select');
        if (!selectEl || !selectEl.value) return;
        var injectText = selectEl.options[selectEl.selectedIndex].text;
        var timeline = main.querySelector('#pm-exercise-timeline');
        if (timeline) {
          var evDiv = document.createElement('div');
          evDiv.className = 'pm-ex-event';
          evDiv.setAttribute('data-ex-team', 'WHITE');
          var evHtml = '';
          evHtml += '<div class="pm-ex-event-time">T+INJECT</div>';
          evHtml += '<div class="pm-ex-event-marker" style="background:#ffffff"></div>';
          evHtml += '<div class="pm-ex-event-content">';
          evHtml += '<span class="pm-ex-event-team" style="color:#ffffff">[WHITE]</span> ';
          evHtml += 'INJECT: ' + esc(injectText);
          evHtml += '</div>';
          evDiv.innerHTML = evHtml;
          timeline.appendChild(evDiv);
          timeline.scrollTop = timeline.scrollHeight;
        }
        selectEl.value = '';
      });
    }
  }

  // =========================================================================
  // TAB 8: CASCADE ANALYZER
  // =========================================================================

  var CASCADE_ATTACK_TYPES = [
    { id: 'compromise', name: 'COMPROMISE', desc: 'Gain unauthorized access and control of the target system', color: '#ff4444' },
    { id: 'destroy', name: 'DESTROY', desc: 'Permanently render the target system inoperable', color: '#ff0000' },
    { id: 'degrade', name: 'DEGRADE', desc: 'Reduce the target system performance or capability', color: '#ff6600' },
    { id: 'deny', name: 'DENY', desc: 'Prevent access to or use of the target system', color: '#ffaa00' }
  ];

  function renderCascade() {
    var html = '';
    html += '<div class="pm-section-header">CASCADE ANALYZER</div>';

    html += '<div class="pm-cascade-controls">';

    // Node selector
    html += '<div class="pm-cascade-ctrl-group">';
    html += '<label class="pm-label">TARGET NODE</label>';
    html += '<select class="pm-select" id="pm-cascade-node">';
    html += '<option value="">— Select Node —</option>';
    var cascadeSectors = {};
    for (var cn = 0; cn < INFRA_NODES.length; cn++) {
      var cnode = INFRA_NODES[cn];
      if (!cascadeSectors[cnode.sector]) cascadeSectors[cnode.sector] = [];
      cascadeSectors[cnode.sector].push(cnode);
    }
    var cSectorKeys = Object.keys(cascadeSectors);
    for (var csk = 0; csk < cSectorKeys.length; csk++) {
      html += '<optgroup label="' + esc(cSectorKeys[csk]) + '">';
      var cNodes = cascadeSectors[cSectorKeys[csk]];
      for (var csn = 0; csn < cNodes.length; csn++) {
        html += '<option value="' + esc(cNodes[csn].id) + '">' + esc(cNodes[csn].name) + ' (Crit: ' + esc(cNodes[csn].criticality) + ')</option>';
      }
      html += '</optgroup>';
    }
    html += '</select>';
    html += '</div>';

    // Attack type selector
    html += '<div class="pm-cascade-ctrl-group">';
    html += '<label class="pm-label">ATTACK TYPE</label>';
    html += '<div class="pm-radio-group">';
    for (var at = 0; at < CASCADE_ATTACK_TYPES.length; at++) {
      var atype = CASCADE_ATTACK_TYPES[at];
      html += '<label class="pm-radio-label" style="border-color:' + atype.color + '">';
      html += '<input type="radio" name="pm-cascade-type" value="' + esc(atype.id) + '"' + (at === 0 ? ' checked' : '') + '>';
      html += '<span style="color:' + atype.color + '">' + esc(atype.name) + '</span>';
      html += '<div class="pm-radio-desc">' + esc(atype.desc) + '</div>';
      html += '</label>';
    }
    html += '</div>';
    html += '</div>';

    html += '<div class="pm-cascade-ctrl-group">';
    html += '<button class="pm-btn pm-btn-danger" id="pm-run-cascade">RUN CASCADE ANALYSIS</button>';
    html += '<button class="pm-btn pm-btn-accent" id="pm-add-scenario" style="margin-left:8px">+ ADD COMPARISON SCENARIO</button>';
    html += '</div>';

    html += '</div>'; // pm-cascade-controls

    // Cascade visualization canvas
    html += '<div class="pm-section-sub">CASCADE PROPAGATION VISUALIZATION</div>';
    html += '<canvas id="pm-cascade-canvas" class="pm-canvas" width="900" height="400"></canvas>';

    // Impact timeline
    html += '<div class="pm-section-sub">IMPACT TIMELINE</div>';
    html += '<div class="pm-cascade-timeline-container">';
    html += '<table class="pm-table" id="pm-cascade-timeline-table">';
    html += '<thead><tr><th>TIME</th><th>AFFECTED NODE</th><th>SECTOR</th><th>EFFECT</th><th>POPULATION IMPACT</th></tr></thead>';
    html += '<tbody id="pm-cascade-timeline-body">';
    html += '<tr><td colspan="5" style="text-align:center;color:#888">Run cascade analysis to generate timeline</td></tr>';
    html += '</tbody></table>';
    html += '</div>';

    // Sector-by-sector breakdown
    html += '<div class="pm-section-sub">SECTOR IMPACT BREAKDOWN</div>';
    html += '<div class="pm-sector-breakdown" id="pm-sector-breakdown">';
    var allSectors = ['Energy', 'Water', 'Transportation', 'Communications', 'Financial', 'Healthcare', 'Government', 'Defense'];
    for (var sb = 0; sb < allSectors.length; sb++) {
      var sectorCount = 0;
      for (var sc = 0; sc < INFRA_NODES.length; sc++) {
        if (INFRA_NODES[sc].sector === allSectors[sb]) sectorCount++;
      }
      html += '<div class="pm-sector-card">';
      html += '<div class="pm-sector-name">' + esc(allSectors[sb]) + '</div>';
      html += '<div class="pm-sector-stats">';
      html += '<span class="pm-sector-affected" id="pm-sector-affected-' + sb + '">0</span>';
      html += '<span class="pm-sector-sep"> / </span>';
      html += '<span class="pm-sector-total">' + esc(sectorCount) + '</span>';
      html += '</div>';
      html += '<div class="pm-sector-bar-bg">';
      html += '<div class="pm-sector-bar" id="pm-sector-bar-' + sb + '" style="width:0%"></div>';
      html += '</div>';
      html += '<div class="pm-sector-pct" id="pm-sector-pct-' + sb + '">0%</div>';
      html += '</div>';
    }
    html += '</div>';

    // Population impact
    html += '<div class="pm-section-sub">TOTAL POPULATION IMPACT</div>';
    html += '<div class="pm-pop-impact" id="pm-pop-impact">';
    html += '<div class="pm-metric-card"><div class="pm-metric-label">DIRECTLY AFFECTED</div><div class="pm-metric-value" id="pm-pop-direct" style="color:#ff4444">0</div></div>';
    html += '<div class="pm-metric-card"><div class="pm-metric-label">INDIRECTLY AFFECTED</div><div class="pm-metric-value" id="pm-pop-indirect" style="color:#ffaa00">0</div></div>';
    html += '<div class="pm-metric-card"><div class="pm-metric-label">TOTAL IMPACT</div><div class="pm-metric-value" id="pm-pop-total" style="color:#ff0000">0</div></div>';
    html += '<div class="pm-metric-card"><div class="pm-metric-label">ECONOMIC DAMAGE</div><div class="pm-metric-value" id="pm-econ-damage" style="color:#ff6600">$0</div></div>';
    html += '</div>';

    // Comparison mode
    html += '<div class="pm-section-sub">SCENARIO COMPARISON</div>';
    html += '<div class="pm-comparison" id="pm-comparison">';
    html += '<div class="pm-product-placeholder">Run cascade analysis and click "ADD COMPARISON SCENARIO" to compare two scenarios side by side.</div>';
    html += '</div>';

    return html;
  }

  function traceCascade(startNodeId, attackType) {
    var affected = [];
    var visited = {};
    var queue = [{ id: startNodeId, time: 0, effect: attackType }];
    visited[startNodeId] = true;

    while (queue.length > 0) {
      var current = queue.shift();
      var node = null;
      for (var i = 0; i < INFRA_NODES.length; i++) {
        if (INFRA_NODES[i].id === current.id) { node = INFRA_NODES[i]; break; }
      }
      if (!node) continue;
      affected.push({ node: node, time: current.time, effect: current.effect });

      // Find nodes that depend on this one
      for (var j = 0; j < INFRA_NODES.length; j++) {
        var depNode = INFRA_NODES[j];
        if (visited[depNode.id]) continue;
        if (depNode.dependencies && depNode.dependencies.indexOf(node.id) !== -1) {
          visited[depNode.id] = true;
          var delay = Math.ceil(Math.random() * 5) + 2;
          queue.push({ id: depNode.id, time: current.time + delay, effect: 'degraded' });
        }
      }
    }

    affected.sort(function(a, b) { return a.time - b.time; });
    return affected;
  }

  function drawCascadeViz(affected) {
    var canvas = main.querySelector('#pm-cascade-canvas');
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var w = canvas.width;
    var h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    // Background
    ctx.fillStyle = '#0a0a0a';
    ctx.fillRect(0, 0, w, h);

    // Grid
    ctx.strokeStyle = '#1a1a1a';
    ctx.lineWidth = 0.5;
    for (var gx = 0; gx < w; gx += 30) {
      ctx.beginPath(); ctx.moveTo(gx, 0); ctx.lineTo(gx, h); ctx.stroke();
    }
    for (var gy = 0; gy < h; gy += 30) {
      ctx.beginPath(); ctx.moveTo(0, gy); ctx.lineTo(w, gy); ctx.stroke();
    }

    if (!affected || affected.length === 0) {
      ctx.fillStyle = '#888';
      ctx.font = '14px monospace';
      ctx.textAlign = 'center';
      ctx.fillText('Select a node and run cascade analysis', w / 2, h / 2);
      return;
    }

    var nodePositions = {};
    var cols = Math.ceil(Math.sqrt(affected.length));
    var padX = 60;
    var padY = 50;
    var spacingX = (w - padX * 2) / Math.max(cols, 1);
    var spacingY = (h - padY * 2) / Math.max(Math.ceil(affected.length / cols), 1);

    for (var i = 0; i < affected.length; i++) {
      var col = i % cols;
      var row = Math.floor(i / cols);
      nodePositions[affected[i].node.id] = {
        x: padX + col * spacingX + spacingX / 2,
        y: padY + row * spacingY + spacingY / 2
      };
    }

    // Draw connections
    ctx.strokeStyle = '#333';
    ctx.lineWidth = 1;
    for (var c = 0; c < affected.length; c++) {
      var aNode = affected[c].node;
      if (aNode.dependencies) {
        for (var d = 0; d < aNode.dependencies.length; d++) {
          var depId = aNode.dependencies[d];
          if (nodePositions[depId] && nodePositions[aNode.id]) {
            ctx.beginPath();
            ctx.moveTo(nodePositions[depId].x, nodePositions[depId].y);
            ctx.lineTo(nodePositions[aNode.id].x, nodePositions[aNode.id].y);
            ctx.stroke();
          }
        }
      }
    }

    // Draw nodes
    for (var n = 0; n < affected.length; n++) {
      var an = affected[n];
      var pos = nodePositions[an.node.id];
      if (!pos) continue;
      var nodeColor = n === 0 ? '#ff0000' : an.time < 10 ? '#ff4444' : an.time < 20 ? '#ff6600' : '#ffaa00';
      var radius = n === 0 ? 12 : 8;

      ctx.beginPath();
      ctx.arc(pos.x, pos.y, radius, 0, Math.PI * 2);
      ctx.fillStyle = nodeColor;
      ctx.fill();
      ctx.strokeStyle = '#fff';
      ctx.lineWidth = 1;
      ctx.stroke();

      ctx.fillStyle = '#ccc';
      ctx.font = '9px monospace';
      ctx.textAlign = 'center';
      var label = an.node.name.length > 15 ? an.node.name.substring(0, 15) + '..' : an.node.name;
      ctx.fillText(label, pos.x, pos.y + radius + 12);
      ctx.fillStyle = '#888';
      ctx.fillText('T+' + an.time + 'm', pos.x, pos.y + radius + 22);
    }

    // Title
    ctx.fillStyle = '#ff4444';
    ctx.font = 'bold 12px monospace';
    ctx.textAlign = 'left';
    ctx.fillText('CASCADE PROPAGATION — ' + affected.length + ' NODES AFFECTED', 10, 16);
  }

  function bindCascade() {
    // Run cascade button
    var runBtn = main.querySelector('#pm-run-cascade');
    if (runBtn) {
      runBtn.addEventListener('click', function() {
        var nodeSelect = main.querySelector('#pm-cascade-node');
        if (!nodeSelect || !nodeSelect.value) {
          alert('Select a target node first.');
          return;
        }
        var typeRadios = main.querySelectorAll('input[name="pm-cascade-type"]');
        var attackType = 'compromise';
        for (var r = 0; r < typeRadios.length; r++) {
          if (typeRadios[r].checked) { attackType = typeRadios[r].value; break; }
        }

        var affected = traceCascade(nodeSelect.value, attackType);
        state.lastCascade = affected;

        // Draw visualization
        drawCascadeViz(affected);

        // Update timeline table
        var tbody = main.querySelector('#pm-cascade-timeline-body');
        if (tbody) {
          var thtml = '';
          for (var t = 0; t < affected.length; t++) {
            var a = affected[t];
            var effectColor = t === 0 ? '#ff0000' : a.effect === 'degraded' ? '#ffaa00' : '#ff4444';
            thtml += '<tr>';
            thtml += '<td>T+' + esc(a.time) + ' min</td>';
            thtml += '<td>' + esc(a.node.name) + '</td>';
            thtml += '<td>' + esc(a.node.sector) + '</td>';
            thtml += '<td style="color:' + effectColor + '">' + esc(t === 0 ? attackType.toUpperCase() : 'DEGRADED') + '</td>';
            thtml += '<td>' + esc((a.node.population || 0).toLocaleString()) + '</td>';
            thtml += '</tr>';
          }
          tbody.innerHTML = thtml;
        }

        // Update sector breakdown
        var allSectors = ['Energy', 'Water', 'Transportation', 'Communications', 'Financial', 'Healthcare', 'Government', 'Defense'];
        for (var sb = 0; sb < allSectors.length; sb++) {
          var totalInSector = 0;
          var affectedInSector = 0;
          for (var sc = 0; sc < INFRA_NODES.length; sc++) {
            if (INFRA_NODES[sc].sector === allSectors[sb]) {
              totalInSector++;
              for (var af = 0; af < affected.length; af++) {
                if (affected[af].node.id === INFRA_NODES[sc].id) { affectedInSector++; break; }
              }
            }
          }
          var pct = totalInSector > 0 ? Math.round((affectedInSector / totalInSector) * 100) : 0;
          var affEl = main.querySelector('#pm-sector-affected-' + sb);
          var barEl = main.querySelector('#pm-sector-bar-' + sb);
          var pctEl = main.querySelector('#pm-sector-pct-' + sb);
          if (affEl) affEl.textContent = String(affectedInSector);
          if (barEl) {
            barEl.style.width = pct + '%';
            barEl.style.background = pct >= 50 ? '#ff4444' : pct >= 25 ? '#ffaa00' : '#00ff88';
          }
          if (pctEl) {
            pctEl.textContent = pct + '%';
            pctEl.style.color = pct >= 50 ? '#ff4444' : pct >= 25 ? '#ffaa00' : '#00ff88';
          }
        }

        // Update population impact
        var directPop = 0;
        for (var dp = 0; dp < affected.length; dp++) {
          directPop += affected[dp].node.population || 0;
        }
        var indirectPop = Math.round(directPop * 1.8);
        var totalPop = directPop + indirectPop;
        var econDamage = (totalPop * 0.0012).toFixed(1);

        var directEl = main.querySelector('#pm-pop-direct');
        var indirectEl = main.querySelector('#pm-pop-indirect');
        var totalEl = main.querySelector('#pm-pop-total');
        var econEl = main.querySelector('#pm-econ-damage');
        if (directEl) directEl.textContent = directPop.toLocaleString();
        if (indirectEl) indirectEl.textContent = indirectPop.toLocaleString();
        if (totalEl) totalEl.textContent = totalPop.toLocaleString();
        if (econEl) econEl.textContent = '$' + econDamage + 'M';
      });
    }

    // Add comparison scenario
    var addScenBtn = main.querySelector('#pm-add-scenario');
    if (addScenBtn) {
      addScenBtn.addEventListener('click', function() {
        var compEl = main.querySelector('#pm-comparison');
        if (!compEl) return;
        if (!state.lastCascade || state.lastCascade.length === 0) {
          alert('Run a primary cascade analysis first.');
          return;
        }

        var primary = state.lastCascade;
        // Run a comparison with a random different node
        var altIdx = Math.floor(Math.random() * INFRA_NODES.length);
        var altNode = INFRA_NODES[altIdx];
        var altCascade = traceCascade(altNode.id, 'compromise');

        var chtml = '';
        chtml += '<div class="pm-comparison-grid">';

        // Primary scenario
        chtml += '<div class="pm-comp-panel">';
        chtml += '<div class="pm-comp-title" style="color:#ff4444">SCENARIO A (PRIMARY)</div>';
        chtml += '<div class="pm-comp-stat">Target: ' + esc(primary[0].node.name) + '</div>';
        chtml += '<div class="pm-comp-stat">Nodes Affected: ' + esc(primary.length) + '</div>';
        var popA = 0;
        for (var pa = 0; pa < primary.length; pa++) popA += primary[pa].node.population || 0;
        chtml += '<div class="pm-comp-stat">Population: ' + esc(popA.toLocaleString()) + '</div>';
        chtml += '<div class="pm-comp-stat">Max Cascade Time: T+' + esc(primary[primary.length - 1].time) + ' min</div>';
        chtml += '</div>';

        // Comparison scenario
        chtml += '<div class="pm-comp-panel">';
        chtml += '<div class="pm-comp-title" style="color:#00bfff">SCENARIO B (COMPARISON)</div>';
        chtml += '<div class="pm-comp-stat">Target: ' + esc(altNode.name) + '</div>';
        chtml += '<div class="pm-comp-stat">Nodes Affected: ' + esc(altCascade.length) + '</div>';
        var popB = 0;
        for (var pb = 0; pb < altCascade.length; pb++) popB += altCascade[pb].node.population || 0;
        chtml += '<div class="pm-comp-stat">Population: ' + esc(popB.toLocaleString()) + '</div>';
        if (altCascade.length > 0) {
          chtml += '<div class="pm-comp-stat">Max Cascade Time: T+' + esc(altCascade[altCascade.length - 1].time) + ' min</div>';
        }
        chtml += '</div>';

        chtml += '</div>'; // pm-comparison-grid

        // Delta
        var delta = primary.length - altCascade.length;
        var deltaColor = delta > 0 ? '#ff4444' : delta < 0 ? '#00ff88' : '#888';
        chtml += '<div class="pm-comp-delta" style="color:' + deltaColor + '">';
        chtml += 'DELTA: Scenario A affects ' + (delta > 0 ? esc(delta) + ' MORE' : delta < 0 ? esc(Math.abs(delta)) + ' FEWER' : 'SAME NUMBER OF') + ' nodes than Scenario B';
        chtml += '</div>';

        compEl.innerHTML = chtml;
      });
    }

    // Initialize canvas with empty state
    drawCascadeViz(null);
  }

  // =========================================================================
  // TAB 9: COUNTER-INTELLIGENCE
  // =========================================================================

  var RECON_ACTIVITIES = [
    { ts: '2026-09-13 02:14:33', srcIp: '185.220.101.34', technique: 'Port Scan', target: 'DMZ Perimeter', status: 'blocked', severity: 'high' },
    { ts: '2026-09-13 01:58:11', srcIp: '91.219.237.88', technique: 'Web Crawl', target: 'Public Web Servers', status: 'monitoring', severity: 'medium' },
    { ts: '2026-09-13 01:42:07', srcIp: '45.155.205.19', technique: 'DNS Enumeration', target: 'DNS Infrastructure', status: 'active', severity: 'high' },
    { ts: '2026-09-13 01:27:55', srcIp: '194.26.29.102', technique: 'Social Engineering', target: 'HR Department', status: 'active', severity: 'critical' },
    { ts: '2026-09-13 01:15:22', srcIp: '103.75.201.44', technique: 'Physical Surveillance', target: 'Data Center Alpha', status: 'monitoring', severity: 'medium' },
    { ts: '2026-09-13 00:58:19', srcIp: '162.247.74.27', technique: 'Port Scan', target: 'Internal Switches', status: 'blocked', severity: 'low' },
    { ts: '2026-09-12 23:44:08', srcIp: '77.247.181.165', technique: 'Web Crawl', target: 'API Gateway', status: 'monitoring', severity: 'medium' },
    { ts: '2026-09-12 23:22:31', srcIp: '198.96.155.3', technique: 'DNS Enumeration', target: 'Mail Servers', status: 'blocked', severity: 'high' },
    { ts: '2026-09-12 22:11:54', srcIp: '5.2.69.50', technique: 'Port Scan', target: 'SCADA Network', status: 'active', severity: 'critical' },
    { ts: '2026-09-12 21:38:40', srcIp: '89.234.157.254', technique: 'Social Engineering', target: 'Executive Staff', status: 'active', severity: 'critical' },
    { ts: '2026-09-12 20:55:17', srcIp: '185.100.87.206', technique: 'Web Crawl', target: 'Intranet Portal', status: 'blocked', severity: 'medium' },
    { ts: '2026-09-12 19:42:33', srcIp: '51.15.235.11', technique: 'Physical Surveillance', target: 'Backup Facility', status: 'monitoring', severity: 'low' },
    { ts: '2026-09-12 18:29:05', srcIp: '209.141.33.42', technique: 'DNS Enumeration', target: 'VPN Endpoints', status: 'active', severity: 'high' },
    { ts: '2026-09-12 17:14:28', srcIp: '176.10.99.200', technique: 'Port Scan', target: 'Cloud Infrastructure', status: 'blocked', severity: 'medium' },
    { ts: '2026-09-12 16:02:11', srcIp: '46.166.139.111', technique: 'Social Engineering', target: 'IT Helpdesk', status: 'monitoring', severity: 'high' }
  ];

  var DECEPTION_OPS = [
    { name: 'HONEYPOT-ALPHA', type: 'Honeypot', deployed: '2026-08-15', triggers: 47, lastTrigger: '2026-09-13 01:22:14', status: 'active', sector: 'DMZ', description: 'High-interaction SSH/HTTP honeypot mimicking production web server' },
    { name: 'TOKEN-BRAVO', type: 'Honey Token', deployed: '2026-08-20', triggers: 12, lastTrigger: '2026-09-12 18:45:33', status: 'active', sector: 'Internal', description: 'Embedded credentials in source code repositories and shared drives' },
    { name: 'DOC-CHARLIE', type: 'Fake Document', deployed: '2026-08-25', triggers: 8, lastTrigger: '2026-09-11 09:12:00', status: 'active', sector: 'Executive', description: 'Planted strategic plans with tracking beacons in metadata' },
    { name: 'DECOY-DELTA', type: 'Decoy Network', deployed: '2026-09-01', triggers: 23, lastTrigger: '2026-09-13 00:58:47', status: 'active', sector: 'SCADA', description: 'ICS/SCADA decoy environment with realistic PLC responses' },
    { name: 'CANARY-ECHO', type: 'Canary Account', deployed: '2026-09-03', triggers: 5, lastTrigger: '2026-09-12 14:33:21', status: 'active', sector: 'Active Directory', description: 'Privileged domain accounts with monitoring for authentication attempts' },
    { name: 'CRED-FOXTROT', type: 'Fake Credentials', deployed: '2026-09-05', triggers: 19, lastTrigger: '2026-09-13 02:01:55', status: 'active', sector: 'Cloud', description: 'AWS/Azure keys with no real permissions but full logging enabled' },
    { name: 'INTEL-GOLF', type: 'Planted Intelligence', deployed: '2026-09-07', triggers: 3, lastTrigger: '2026-09-10 22:17:44', status: 'dormant', sector: 'Comms', description: 'False operational plans seeded in monitored communication channels' },
    { name: 'INFRA-HOTEL', type: 'Decoy Infrastructure', deployed: '2026-09-10', triggers: 31, lastTrigger: '2026-09-13 01:44:09', status: 'active', sector: 'Perimeter', description: 'Fake DNS entries, certificates, and server banners to misdirect attackers' }
  ];

  var ADVERSARY_TIMELINE = [
    { time: '2026-09-13 02:14', action: 'SYN scan of ports 22,80,443,3389,8080 on DMZ range', technique: 'T1046', attackId: 'TA0007', severity: 'high' },
    { time: '2026-09-13 01:58', action: 'Automated crawl of public-facing web applications', technique: 'T1595.002', attackId: 'TA0043', severity: 'medium' },
    { time: '2026-09-13 01:42', action: 'AXFR requests and subdomain brute-force attempts', technique: 'T1596.001', attackId: 'TA0043', severity: 'high' },
    { time: '2026-09-13 01:27', action: 'Spear-phishing email targeting HR with weaponized resume', technique: 'T1566.001', attackId: 'TA0001', severity: 'critical' },
    { time: '2026-09-13 00:58', action: 'UDP port scan of internal subnet from compromised host', technique: 'T1046', attackId: 'TA0007', severity: 'high' },
    { time: '2026-09-12 23:44', action: 'Directory traversal attempts on API endpoints', technique: 'T1083', attackId: 'TA0007', severity: 'medium' },
    { time: '2026-09-12 23:22', action: 'MX record enumeration and SMTP VRFY commands', technique: 'T1589.002', attackId: 'TA0043', severity: 'medium' },
    { time: '2026-09-12 22:11', action: 'Modbus/TCP probing of SCADA controllers', technique: 'T0846', attackId: 'TA0043', severity: 'critical' },
    { time: '2026-09-12 21:38', action: 'LinkedIn social engineering targeting C-suite', technique: 'T1598.003', attackId: 'TA0043', severity: 'critical' },
    { time: '2026-09-12 20:55', action: 'Credential stuffing against intranet login portal', technique: 'T1110.004', attackId: 'TA0006', severity: 'high' },
    { time: '2026-09-12 19:42', action: 'Certificate transparency log mining', technique: 'T1596.004', attackId: 'TA0043', severity: 'low' },
    { time: '2026-09-12 18:29', action: 'VPN endpoint enumeration via IKE scanning', technique: 'T1595.001', attackId: 'TA0043', severity: 'high' },
    { time: '2026-09-12 17:14', action: 'Cloud metadata service probing (169.254.169.254)', technique: 'T1552.005', attackId: 'TA0006', severity: 'medium' },
    { time: '2026-09-12 16:02', action: 'Pretexting call to IT helpdesk for password reset', technique: 'T1598.001', attackId: 'TA0043', severity: 'high' }
  ];

  var PROBE_SOURCES = [
    { ip: '185.220.101.34', country: 'Germany', isp: 'Tor Exit Node', scans: 342, crawls: 0, dnsEnum: 0, socialEng: 0, riskScore: 78 },
    { ip: '91.219.237.88', country: 'Romania', isp: 'M247 Ltd', scans: 15, crawls: 189, dnsEnum: 0, socialEng: 0, riskScore: 65 },
    { ip: '45.155.205.19', country: 'Russia', isp: 'Selectel', scans: 0, crawls: 0, dnsEnum: 456, socialEng: 0, riskScore: 82 },
    { ip: '194.26.29.102', country: 'Iran', isp: 'Afranet', scans: 0, crawls: 0, dnsEnum: 0, socialEng: 14, riskScore: 91 },
    { ip: '103.75.201.44', country: 'China', isp: 'Alibaba Cloud', scans: 128, crawls: 67, dnsEnum: 34, socialEng: 0, riskScore: 74 },
    { ip: '162.247.74.27', country: 'USA', isp: 'Tor Exit Node', scans: 567, crawls: 0, dnsEnum: 0, socialEng: 0, riskScore: 55 },
    { ip: '77.247.181.165', country: 'Netherlands', isp: 'XS4ALL', scans: 0, crawls: 234, dnsEnum: 0, socialEng: 0, riskScore: 48 },
    { ip: '198.96.155.3', country: 'North Korea', isp: 'Star JV', scans: 89, crawls: 0, dnsEnum: 312, socialEng: 0, riskScore: 95 },
    { ip: '5.2.69.50', country: 'Russia', isp: 'VDSINA', scans: 445, crawls: 23, dnsEnum: 78, socialEng: 0, riskScore: 88 },
    { ip: '89.234.157.254', country: 'France', isp: 'FDN Association', scans: 0, crawls: 0, dnsEnum: 0, socialEng: 9, riskScore: 72 },
    { ip: '185.100.87.206', country: 'Luxembourg', isp: 'Tor Exit Node', scans: 201, crawls: 156, dnsEnum: 0, socialEng: 0, riskScore: 62 },
    { ip: '51.15.235.11', country: 'France', isp: 'Scaleway', scans: 34, crawls: 12, dnsEnum: 0, socialEng: 0, riskScore: 35 },
    { ip: '209.141.33.42', country: 'USA', isp: 'FranTech', scans: 0, crawls: 0, dnsEnum: 289, socialEng: 0, riskScore: 71 },
    { ip: '176.10.99.200', country: 'Switzerland', isp: 'PrivEx', scans: 378, crawls: 0, dnsEnum: 0, socialEng: 0, riskScore: 58 },
    { ip: '46.166.139.111', country: 'Ukraine', isp: 'Private Layer', scans: 56, crawls: 45, dnsEnum: 23, socialEng: 7, riskScore: 83 }
  ];

  var CI_REPORTS = [
    { id: 'CI-2026-0147', title: 'APT-BEAR Infrastructure Mapping Campaign', date: '2026-09-12', classification: 'TOP SECRET//SCI', summary: 'Detected coordinated infrastructure mapping campaign attributed to APT-BEAR. Adversary utilized Tor exit nodes and commercial VPN services to conduct systematic DNS enumeration and port scanning of critical infrastructure sectors. Honeypot interactions confirm active targeting of SCADA systems.', fullContent: 'FULL REPORT: Comprehensive analysis of 72-hour campaign including TTPs, IOCs, attribution confidence assessment, recommended defensive posture adjustments, and coordination requirements with allied intelligence services.' },
    { id: 'CI-2026-0146', title: 'Social Engineering Threat to Executive Staff', date: '2026-09-11', classification: 'SECRET//NOFORN', summary: 'Multiple social engineering attempts identified targeting C-suite executives via LinkedIn and corporate email. Techniques include pretexting as vendors, fake conference invitations, and weaponized document delivery. Pattern consistent with APT-PHOENIX operations.', fullContent: 'FULL REPORT: Detailed timeline of social engineering attempts, target profiles, adversary personas analysis, recommended awareness training updates, and technical countermeasures for email and social media platforms.' },
    { id: 'CI-2026-0145', title: 'Deception Operation DELTA Effectiveness Review', date: '2026-09-10', classification: 'TOP SECRET//SCI', summary: 'Quarterly review of DECOY-DELTA SCADA honeypot operations. 23 unique adversary interactions recorded, including 3 instances of advanced lateral movement techniques. Intelligence gathered has informed 7 defensive posture updates across the SCADA sector.', fullContent: 'FULL REPORT: Complete interaction logs, adversary behavior analysis, intelligence products generated, recommendations for honeypot enhancement, and cross-reference with known APT group TTPs.' },
    { id: 'CI-2026-0144', title: 'Supply Chain Compromise Indicator Analysis', date: '2026-09-09', classification: 'SECRET', summary: 'Analysis of anomalous behavior in third-party software components suggests potential supply chain compromise. Behavioral indicators include unexpected outbound connections, elevated privilege requests, and modified cryptographic routines in recent updates from two vendors.', fullContent: 'FULL REPORT: Vendor analysis, compromised component identification, behavioral indicator details, forensic analysis methodology, remediation steps, and vendor notification status.' },
    { id: 'CI-2026-0143', title: 'Counter-Surveillance Detection Summary', date: '2026-09-08', classification: 'CONFIDENTIAL', summary: 'Weekly counter-surveillance summary for physical facilities. Two incidents of unauthorized photography near Data Center Alpha perimeter detected by security cameras. Vehicle registration traces initiated. No confirmed hostile surveillance established at this time.', fullContent: 'FULL REPORT: Incident details, camera footage analysis, vehicle identification attempts, physical security recommendation updates, and liaison with local law enforcement.' }
  ];

  function renderCounterIntel() {
    var h = '';
    h += '<div class="pm-section-header">COUNTER-INTELLIGENCE OPERATIONS CENTER</div>';

    // Recon Detection Dashboard
    h += '<div class="pm-subsection-title">ADVERSARY RECONNAISSANCE DETECTION</div>';
    h += '<div class="pm-ci-filter-bar">';
    h += '<label class="pm-label">FILTER BY TECHNIQUE: </label>';
    h += '<select id="pmCiTechFilter" class="pm-select">';
    h += '<option value="all">ALL TECHNIQUES</option>';
    h += '<option value="Port Scan">PORT SCAN</option>';
    h += '<option value="Web Crawl">WEB CRAWL</option>';
    h += '<option value="DNS Enumeration">DNS ENUMERATION</option>';
    h += '<option value="Social Engineering">SOCIAL ENGINEERING</option>';
    h += '<option value="Physical Surveillance">PHYSICAL SURVEILLANCE</option>';
    h += '</select>';
    h += '</div>';
    h += '<div class="pm-table-wrap"><table class="pm-table" id="pmReconTable">';
    h += '<thead><tr>';
    h += '<th>TIMESTAMP</th><th>SOURCE IP</th><th>TECHNIQUE</th><th>TARGET</th><th>STATUS</th><th>SEVERITY</th>';
    h += '</tr></thead><tbody>';
    for (var i = 0; i < RECON_ACTIVITIES.length; i++) {
      var ra = RECON_ACTIVITIES[i];
      var sevClass = ra.severity === 'critical' ? 'pm-sev-crit' : ra.severity === 'high' ? 'pm-sev-high' : ra.severity === 'medium' ? 'pm-sev-med' : 'pm-sev-low';
      var statusClass = ra.status === 'blocked' ? 'pm-status-green' : ra.status === 'active' ? 'pm-status-red' : 'pm-status-yellow';
      h += '<tr class="pm-recon-row" data-technique="' + esc(ra.technique) + '">';
      h += '<td>' + esc(ra.ts) + '</td>';
      h += '<td class="pm-mono">' + esc(ra.srcIp) + '</td>';
      h += '<td>' + esc(ra.technique) + '</td>';
      h += '<td>' + esc(ra.target) + '</td>';
      h += '<td><span class="' + statusClass + '">' + esc(ra.status.toUpperCase()) + '</span></td>';
      h += '<td><span class="' + sevClass + '">' + esc(ra.severity.toUpperCase()) + '</span></td>';
      h += '</tr>';
    }
    h += '</tbody></table></div>';

    // Deception Operations
    h += '<div class="pm-subsection-title">ACTIVE DECEPTION OPERATIONS</div>';
    h += '<div class="pm-deception-grid">';
    for (var d = 0; d < DECEPTION_OPS.length; d++) {
      var op = DECEPTION_OPS[d];
      var opStatusClass = op.status === 'active' ? 'pm-dot-green' : 'pm-dot-yellow';
      h += '<div class="pm-deception-card">';
      h += '<div class="pm-deception-card-header">';
      h += '<span class="' + opStatusClass + '"></span>';
      h += '<span class="pm-deception-name">' + esc(op.name) + '</span>';
      h += '</div>';
      h += '<div class="pm-deception-type">' + esc(op.type) + '</div>';
      h += '<div class="pm-deception-detail">Sector: ' + esc(op.sector) + '</div>';
      h += '<div class="pm-deception-detail">Deployed: ' + esc(op.deployed) + '</div>';
      h += '<div class="pm-deception-detail">Triggers: <span class="pm-val-accent">' + esc(String(op.triggers)) + '</span></div>';
      h += '<div class="pm-deception-detail">Last Trigger: ' + esc(op.lastTrigger) + '</div>';
      h += '<div class="pm-deception-desc">' + esc(op.description) + '</div>';
      h += '</div>';
    }
    h += '</div>';

    // Adversary Activity Timeline
    h += '<div class="pm-subsection-title">ADVERSARY ACTIVITY TIMELINE (72 HOURS)</div>';
    h += '<div class="pm-timeline-container">';
    for (var t = 0; t < ADVERSARY_TIMELINE.length; t++) {
      var ev = ADVERSARY_TIMELINE[t];
      var tlSevClass = ev.severity === 'critical' ? 'pm-tl-crit' : ev.severity === 'high' ? 'pm-tl-high' : ev.severity === 'medium' ? 'pm-tl-med' : 'pm-tl-low';
      h += '<div class="pm-timeline-item ' + tlSevClass + '" data-idx="' + t + '">';
      h += '<div class="pm-tl-dot"></div>';
      h += '<div class="pm-tl-content">';
      h += '<div class="pm-tl-time">' + esc(ev.time) + '</div>';
      h += '<div class="pm-tl-action">' + esc(ev.action) + '</div>';
      h += '<div class="pm-tl-tags">';
      h += '<span class="pm-tag">MITRE: ' + esc(ev.technique) + '</span>';
      h += '<span class="pm-tag">TACTIC: ' + esc(ev.attackId) + '</span>';
      h += '</div>';
      h += '<div class="pm-tl-expanded" style="display:none">';
      h += '<div class="pm-tl-detail">Full MITRE ATT&amp;CK Reference: ' + esc(ev.technique) + ' (' + esc(ev.attackId) + ')</div>';
      h += '<div class="pm-tl-detail">Severity Classification: ' + esc(ev.severity.toUpperCase()) + '</div>';
      h += '<div class="pm-tl-detail">Correlated with ' + esc(String(Math.floor(Math.random() * 5) + 1)) + ' additional intelligence sources</div>';
      h += '</div>';
      h += '</div>';
      h += '</div>';
    }
    h += '</div>';

    // Probe Source Analysis
    h += '<div class="pm-subsection-title">PROBE SOURCE ANALYSIS</div>';
    h += '<div class="pm-table-wrap"><table class="pm-table">';
    h += '<thead><tr>';
    h += '<th>IP ADDRESS</th><th>COUNTRY</th><th>ISP</th><th>SCANS</th><th>CRAWLS</th><th>DNS ENUM</th><th>SOC. ENG.</th><th>RISK SCORE</th>';
    h += '</tr></thead><tbody>';
    for (var p = 0; p < PROBE_SOURCES.length; p++) {
      var ps = PROBE_SOURCES[p];
      var riskColor = ps.riskScore >= 80 ? 'pm-risk-crit' : ps.riskScore >= 60 ? 'pm-risk-high' : ps.riskScore >= 40 ? 'pm-risk-med' : 'pm-risk-low';
      h += '<tr>';
      h += '<td class="pm-mono">' + esc(ps.ip) + '</td>';
      h += '<td>' + esc(ps.country) + '</td>';
      h += '<td>' + esc(ps.isp) + '</td>';
      h += '<td>' + esc(String(ps.scans)) + '</td>';
      h += '<td>' + esc(String(ps.crawls)) + '</td>';
      h += '<td>' + esc(String(ps.dnsEnum)) + '</td>';
      h += '<td>' + esc(String(ps.socialEng)) + '</td>';
      h += '<td><span class="' + riskColor + '">' + esc(String(ps.riskScore)) + '</span></td>';
      h += '</tr>';
    }
    h += '</tbody></table></div>';

    // Deception Deployment Controls
    h += '<div class="pm-subsection-title">DEPLOY NEW DECEPTION</div>';
    h += '<div class="pm-form-row">';
    h += '<div class="pm-form-group">';
    h += '<label class="pm-label">DECEPTION TYPE</label>';
    h += '<select id="pmDeceptionType" class="pm-select">';
    h += '<option value="honeypot">Honeypot</option>';
    h += '<option value="honeytoken">Honey Token</option>';
    h += '<option value="fakedoc">Fake Document</option>';
    h += '<option value="decoynet">Decoy Network</option>';
    h += '<option value="canary">Canary Account</option>';
    h += '<option value="fakecred">Fake Credentials</option>';
    h += '<option value="plantintel">Planted Intelligence</option>';
    h += '<option value="decoyinfra">Decoy Infrastructure</option>';
    h += '</select>';
    h += '</div>';
    h += '<div class="pm-form-group">';
    h += '<label class="pm-label">TARGET SECTOR</label>';
    h += '<select id="pmDeceptionSector" class="pm-select">';
    h += '<option value="dmz">DMZ / Perimeter</option>';
    h += '<option value="internal">Internal Network</option>';
    h += '<option value="scada">SCADA / ICS</option>';
    h += '<option value="cloud">Cloud Infrastructure</option>';
    h += '<option value="executive">Executive Systems</option>';
    h += '<option value="comms">Communications</option>';
    h += '</select>';
    h += '</div>';
    h += '<div class="pm-form-group">';
    h += '<button id="pmDeployDeception" class="pm-btn pm-btn-accent">DEPLOY DECEPTION</button>';
    h += '</div>';
    h += '</div>';
    h += '<div class="pm-deploy-status">Active Deceptions: <span class="pm-val-accent">' + esc(String(DECEPTION_OPS.filter(function(o) { return o.status === 'active'; }).length)) + '</span> / ' + esc(String(DECEPTION_OPS.length)) + '</div>';
    h += '<div id="pmDeployResult" class="pm-result-box" style="display:none"></div>';

    // Counter-Intel Reports
    h += '<div class="pm-subsection-title">COUNTER-INTELLIGENCE REPORTS</div>';
    h += '<div class="pm-ci-reports">';
    for (var r = 0; r < CI_REPORTS.length; r++) {
      var rp = CI_REPORTS[r];
      var classColor = rp.classification.indexOf('TOP SECRET') !== -1 ? 'pm-class-ts' : rp.classification.indexOf('SECRET') !== -1 ? 'pm-class-s' : 'pm-class-c';
      h += '<div class="pm-ci-report-card">';
      h += '<div class="pm-ci-report-header">';
      h += '<span class="pm-ci-report-id">' + esc(rp.id) + '</span>';
      h += '<span class="' + classColor + '">' + esc(rp.classification) + '</span>';
      h += '</div>';
      h += '<div class="pm-ci-report-title">' + esc(rp.title) + '</div>';
      h += '<div class="pm-ci-report-date">' + esc(rp.date) + '</div>';
      h += '<div class="pm-ci-report-summary">' + esc(rp.summary) + '</div>';
      h += '<div class="pm-ci-report-full" id="pmCiReport' + r + '" style="display:none">';
      h += '<div class="pm-ci-report-fulltext">' + esc(rp.fullContent) + '</div>';
      h += '</div>';
      h += '<button class="pm-btn pm-btn-sm pm-ci-report-toggle" data-report="' + r + '">VIEW FULL REPORT</button>';
      h += '</div>';
    }
    h += '</div>';

    return h;
  }

  function bindCounterIntel() {
    // Deploy deception button
    var deployBtn = main.querySelector('#pmDeployDeception');
    if (deployBtn) {
      deployBtn.addEventListener('click', function() {
        var typeEl = main.querySelector('#pmDeceptionType');
        var sectorEl = main.querySelector('#pmDeceptionSector');
        var resultEl = main.querySelector('#pmDeployResult');
        if (typeEl && sectorEl && resultEl) {
          var opName = 'DECEPTION-' + typeEl.value.toUpperCase().slice(0, 4) + '-' + Math.floor(Math.random() * 9000 + 1000);
          resultEl.style.display = 'block';
          resultEl.innerHTML = '<div class="pm-result-success">' +
            'DECEPTION DEPLOYED: ' + esc(opName) + '<br>' +
            'Type: ' + esc(typeEl.options[typeEl.selectedIndex].text) + '<br>' +
            'Sector: ' + esc(sectorEl.options[sectorEl.selectedIndex].text) + '<br>' +
            'Status: ACTIVE | Monitoring Enabled' +
            '</div>';
        }
      });
    }

    // Report view toggle
    var reportBtns = main.querySelectorAll('.pm-ci-report-toggle');
    for (var i = 0; i < reportBtns.length; i++) {
      reportBtns[i].addEventListener('click', function() {
        var idx = this.getAttribute('data-report');
        var fullEl = main.querySelector('#pmCiReport' + idx);
        if (fullEl) {
          if (fullEl.style.display === 'none') {
            fullEl.style.display = 'block';
            this.textContent = 'HIDE REPORT';
          } else {
            fullEl.style.display = 'none';
            this.textContent = 'VIEW FULL REPORT';
          }
        }
      });
    }

    // Recon filter by technique
    var techFilter = main.querySelector('#pmCiTechFilter');
    if (techFilter) {
      techFilter.addEventListener('change', function() {
        var val = this.value;
        var rows = main.querySelectorAll('.pm-recon-row');
        for (var j = 0; j < rows.length; j++) {
          if (val === 'all' || rows[j].getAttribute('data-technique') === val) {
            rows[j].style.display = '';
          } else {
            rows[j].style.display = 'none';
          }
        }
      });
    }

    // Timeline item expand
    var tlItems = main.querySelectorAll('.pm-timeline-item');
    for (var k = 0; k < tlItems.length; k++) {
      tlItems[k].addEventListener('click', function() {
        var expanded = this.querySelector('.pm-tl-expanded');
        if (expanded) {
          expanded.style.display = expanded.style.display === 'none' ? 'block' : 'none';
        }
      });
    }
  }

  // =========================================================================
  // TAB 10: SUPPLY CHAIN
  // =========================================================================

  function renderSupplyChain() {
    var h = '';
    h += '<div class="pm-section-header">SUPPLY CHAIN RISK MANAGEMENT</div>';

    // SBOM Analysis Summary
    var categories = {};
    var vendors = {};
    var totalVulns = 0;
    var totalAge = 0;
    var licenses = {};
    for (var s = 0; s < SUPPLY_CHAIN.length; s++) {
      var comp = SUPPLY_CHAIN[s];
      if (!categories[comp.category]) categories[comp.category] = [];
      categories[comp.category].push(comp);
      if (!vendors[comp.vendor]) vendors[comp.vendor] = { count: 0, totalRisk: 0, critVulns: 0 };
      vendors[comp.vendor].count++;
      vendors[comp.vendor].totalRisk += comp.riskScore;
      vendors[comp.vendor].critVulns += (comp.riskScore > 70 ? comp.vulns : 0);
      totalVulns += comp.vulns;
      totalAge += (2026 - parseInt(comp.lastAudit.split('-')[0])) * 12 + (9 - parseInt(comp.lastAudit.split('-')[1]));
      var lic = comp.license || 'Proprietary';
      if (!licenses[lic]) licenses[lic] = 0;
      licenses[lic]++;
    }
    var uniqueVendors = Object.keys(vendors).length;
    var avgAge = Math.round(totalAge / SUPPLY_CHAIN.length);
    var vulnDensity = (totalVulns / SUPPLY_CHAIN.length).toFixed(2);

    h += '<div class="pm-subsection-title">SBOM ANALYSIS SUMMARY</div>';
    h += '<div class="pm-stat-row">';
    h += '<div class="pm-stat-card"><div class="pm-stat-val">' + esc(String(SUPPLY_CHAIN.length)) + '</div><div class="pm-stat-label">TOTAL COMPONENTS</div></div>';
    h += '<div class="pm-stat-card"><div class="pm-stat-val">' + esc(String(uniqueVendors)) + '</div><div class="pm-stat-label">UNIQUE VENDORS</div></div>';
    h += '<div class="pm-stat-card"><div class="pm-stat-val">' + esc(String(avgAge)) + ' mo</div><div class="pm-stat-label">AVG AUDIT AGE</div></div>';
    h += '<div class="pm-stat-card"><div class="pm-stat-val">' + esc(String(totalVulns)) + '</div><div class="pm-stat-label">TOTAL VULNS</div></div>';
    h += '<div class="pm-stat-card"><div class="pm-stat-val">' + esc(vulnDensity) + '</div><div class="pm-stat-label">VULN DENSITY</div></div>';
    h += '</div>';

    // License Distribution
    h += '<div class="pm-subsection-title">LICENSE DISTRIBUTION</div>';
    h += '<div class="pm-license-bar">';
    var licKeys = Object.keys(licenses);
    var licColors = ['#00ff41', '#00b4d8', '#ffbe0b', '#ff006e', '#8338ec', '#3a86ff', '#fb5607'];
    for (var l = 0; l < licKeys.length; l++) {
      var pct = (licenses[licKeys[l]] / SUPPLY_CHAIN.length * 100).toFixed(1);
      h += '<div class="pm-license-seg" style="width:' + pct + '%;background:' + licColors[l % licColors.length] + '" title="' + esc(licKeys[l]) + ': ' + esc(String(licenses[licKeys[l]])) + '">';
      if (parseFloat(pct) > 8) {
        h += '<span>' + esc(licKeys[l]) + '</span>';
      }
      h += '</div>';
    }
    h += '</div>';

    // Software Dependency Tree
    h += '<div class="pm-subsection-title">SOFTWARE DEPENDENCY TREE</div>';
    h += '<div class="pm-sc-search"><input id="pmScSearch" class="pm-input" placeholder="Search components..." type="text"></div>';
    h += '<div class="pm-dep-tree" id="pmDepTree">';
    var catKeys = Object.keys(categories);
    for (var c = 0; c < catKeys.length; c++) {
      var catName = catKeys[c];
      var catComps = categories[catName];
      h += '<div class="pm-dep-category" data-cat="' + esc(catName) + '">';
      h += '<div class="pm-dep-cat-header pm-dep-toggle" data-target="pmCat' + c + '">';
      h += '<span class="pm-dep-arrow">&#9654;</span> ' + esc(catName.toUpperCase()) + ' (' + esc(String(catComps.length)) + ' components)';
      h += '</div>';
      h += '<div class="pm-dep-cat-body" id="pmCat' + c + '" style="display:none">';
      for (var cc = 0; cc < catComps.length; cc++) {
        var cm = catComps[cc];
        var riskCls = cm.riskScore > 80 ? 'pm-risk-crit' : cm.riskScore > 60 ? 'pm-risk-high' : cm.riskScore > 30 ? 'pm-risk-med' : 'pm-risk-low';
        h += '<div class="pm-dep-item" data-name="' + esc(cm.name) + '">';
        h += '<span class="pm-dep-name">' + esc(cm.name) + '</span>';
        h += '<span class="pm-dep-ver">v' + esc(cm.version) + '</span>';
        h += '<span class="pm-dep-vendor">' + esc(cm.vendor) + '</span>';
        h += '<span class="' + riskCls + '">' + esc(String(cm.riskScore)) + '</span>';
        if (cm.deps && cm.deps.length > 0) {
          h += '<div class="pm-dep-children">';
          for (var dd = 0; dd < cm.deps.length; dd++) {
            h += '<div class="pm-dep-child">&rarr; ' + esc(cm.deps[dd]) + '</div>';
          }
          h += '</div>';
        }
        h += '</div>';
      }
      h += '</div>';
      h += '</div>';
    }
    h += '</div>';

    // Component Risk Scores Table
    h += '<div class="pm-subsection-title">COMPONENT RISK SCORES</div>';
    h += '<div class="pm-table-wrap"><table class="pm-table" id="pmScTable">';
    h += '<thead><tr>';
    h += '<th class="pm-sortable" data-col="name">NAME</th>';
    h += '<th class="pm-sortable" data-col="vendor">VENDOR</th>';
    h += '<th class="pm-sortable" data-col="version">VERSION</th>';
    h += '<th class="pm-sortable" data-col="category">CATEGORY</th>';
    h += '<th class="pm-sortable" data-col="riskScore">RISK SCORE</th>';
    h += '<th class="pm-sortable" data-col="vulns">VULNS</th>';
    h += '<th class="pm-sortable" data-col="lastAudit">LAST AUDIT</th>';
    h += '</tr></thead><tbody>';
    for (var i = 0; i < SUPPLY_CHAIN.length; i++) {
      var sc = SUPPLY_CHAIN[i];
      var rClass = sc.riskScore > 80 ? 'pm-risk-crit' : sc.riskScore > 60 ? 'pm-risk-high' : sc.riskScore > 30 ? 'pm-risk-med' : 'pm-risk-low';
      h += '<tr class="pm-sc-row" data-name="' + esc(sc.name) + '">';
      h += '<td>' + esc(sc.name) + '</td>';
      h += '<td>' + esc(sc.vendor) + '</td>';
      h += '<td>' + esc(sc.version) + '</td>';
      h += '<td>' + esc(sc.category) + '</td>';
      h += '<td><span class="' + rClass + '">' + esc(String(sc.riskScore)) + '</span></td>';
      h += '<td>' + esc(String(sc.vulns)) + '</td>';
      h += '<td>' + esc(sc.lastAudit) + '</td>';
      h += '</tr>';
    }
    h += '</tbody></table></div>';

    // Vendor Risk Assessment
    h += '<div class="pm-subsection-title">VENDOR RISK ASSESSMENT</div>';
    h += '<div class="pm-table-wrap"><table class="pm-table">';
    h += '<thead><tr>';
    h += '<th>VENDOR</th><th>COMPONENTS</th><th>AVG RISK</th><th>CRITICAL VULNS</th><th>COMPLIANCE</th>';
    h += '</tr></thead><tbody>';
    var vendorKeys = Object.keys(vendors).sort(function(a, b) { return vendors[b].totalRisk / vendors[b].count - vendors[a].totalRisk / vendors[a].count; });
    for (var v = 0; v < Math.min(vendorKeys.length, 20); v++) {
      var vk = vendorKeys[v];
      var vd = vendors[vk];
      var avgRisk = Math.round(vd.totalRisk / vd.count);
      var compStatus = avgRisk < 40 ? 'COMPLIANT' : avgRisk < 70 ? 'PARTIAL' : 'NON-COMPLIANT';
      var compClass = avgRisk < 40 ? 'pm-status-green' : avgRisk < 70 ? 'pm-status-yellow' : 'pm-status-red';
      var avgClass = avgRisk > 70 ? 'pm-risk-crit' : avgRisk > 50 ? 'pm-risk-high' : avgRisk > 30 ? 'pm-risk-med' : 'pm-risk-low';
      h += '<tr>';
      h += '<td>' + esc(vk) + '</td>';
      h += '<td>' + esc(String(vd.count)) + '</td>';
      h += '<td><span class="' + avgClass + '">' + esc(String(avgRisk)) + '</span></td>';
      h += '<td>' + esc(String(vd.critVulns)) + '</td>';
      h += '<td><span class="' + compClass + '">' + esc(compStatus) + '</span></td>';
      h += '</tr>';
    }
    h += '</tbody></table></div>';

    // Vulnerability Cascade Modeling
    h += '<div class="pm-subsection-title">VULNERABILITY CASCADE MODELING</div>';
    h += '<div class="pm-form-row">';
    h += '<div class="pm-form-group">';
    h += '<label class="pm-label">SELECT COMPONENT</label>';
    h += '<select id="pmCascadeComp" class="pm-select">';
    for (var vc = 0; vc < SUPPLY_CHAIN.length; vc++) {
      h += '<option value="' + esc(SUPPLY_CHAIN[vc].name) + '">' + esc(SUPPLY_CHAIN[vc].name) + '</option>';
    }
    h += '</select>';
    h += '</div>';
    h += '<div class="pm-form-group">';
    h += '<button id="pmRunCascade" class="pm-btn pm-btn-warn">ANALYZE CASCADE</button>';
    h += '</div>';
    h += '</div>';
    h += '<div id="pmCascadeResult" class="pm-result-box" style="display:none"></div>';

    // Compromise Propagation Simulator
    h += '<div class="pm-subsection-title">COMPROMISE PROPAGATION ENGINE</div>';
    h += '<div class="pm-form-row">';
    h += '<div class="pm-form-group">';
    h += '<label class="pm-label">COMPROMISE TARGET</label>';
    h += '<select id="pmPropTarget" class="pm-select">';
    for (var pt = 0; pt < SUPPLY_CHAIN.length; pt++) {
      h += '<option value="' + esc(SUPPLY_CHAIN[pt].name) + '">' + esc(SUPPLY_CHAIN[pt].name) + '</option>';
    }
    h += '</select>';
    h += '</div>';
    h += '<div class="pm-form-group">';
    h += '<button id="pmRunPropagation" class="pm-btn pm-btn-danger">EXECUTE COMPROMISE</button>';
    h += '</div>';
    h += '</div>';
    h += '<div id="pmPropResult" class="pm-result-box" style="display:none"></div>';

    return h;
  }

  function bindSupplyChain() {
    // Dependency tree collapse/expand
    var toggles = main.querySelectorAll('.pm-dep-toggle');
    for (var i = 0; i < toggles.length; i++) {
      toggles[i].addEventListener('click', function() {
        var targetId = this.getAttribute('data-target');
        var body = main.querySelector('#' + targetId);
        var arrow = this.querySelector('.pm-dep-arrow');
        if (body) {
          if (body.style.display === 'none') {
            body.style.display = 'block';
            if (arrow) arrow.innerHTML = '&#9660;';
          } else {
            body.style.display = 'none';
            if (arrow) arrow.innerHTML = '&#9654;';
          }
        }
      });
    }

    // Component search
    var searchInput = main.querySelector('#pmScSearch');
    if (searchInput) {
      searchInput.addEventListener('input', function() {
        var q = this.value.toLowerCase();
        var items = main.querySelectorAll('.pm-dep-item');
        for (var j = 0; j < items.length; j++) {
          var name = (items[j].getAttribute('data-name') || '').toLowerCase();
          items[j].style.display = (q === '' || name.indexOf(q) !== -1) ? '' : 'none';
        }
        var rows = main.querySelectorAll('.pm-sc-row');
        for (var k = 0; k < rows.length; k++) {
          var rname = (rows[k].getAttribute('data-name') || '').toLowerCase();
          rows[k].style.display = (q === '' || rname.indexOf(q) !== -1) ? '' : 'none';
        }
      });
    }

    // Table sort
    var sortHeaders = main.querySelectorAll('#pmScTable .pm-sortable');
    for (var s = 0; s < sortHeaders.length; s++) {
      sortHeaders[s].addEventListener('click', function() {
        var col = this.getAttribute('data-col');
        var tbody = main.querySelector('#pmScTable tbody');
        if (!tbody) return;
        var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
        var colIdx = 0;
        var cols = ['name', 'vendor', 'version', 'category', 'riskScore', 'vulns', 'lastAudit'];
        for (var ci = 0; ci < cols.length; ci++) {
          if (cols[ci] === col) { colIdx = ci; break; }
        }
        var asc = this.getAttribute('data-dir') !== 'asc';
        this.setAttribute('data-dir', asc ? 'asc' : 'desc');
        rows.sort(function(a, b) {
          var av = a.cells[colIdx].textContent.trim();
          var bv = b.cells[colIdx].textContent.trim();
          var an = parseFloat(av);
          var bn = parseFloat(bv);
          if (!isNaN(an) && !isNaN(bn)) {
            return asc ? an - bn : bn - an;
          }
          return asc ? av.localeCompare(bv) : bv.localeCompare(av);
        });
        for (var ri = 0; ri < rows.length; ri++) {
          tbody.appendChild(rows[ri]);
        }
      });
    }

    // Cascade analysis
    var cascadeBtn = main.querySelector('#pmRunCascade');
    if (cascadeBtn) {
      cascadeBtn.addEventListener('click', function() {
        var sel = main.querySelector('#pmCascadeComp');
        var resultEl = main.querySelector('#pmCascadeResult');
        if (!sel || !resultEl) return;
        var compName = sel.value;
        var affected = [];
        for (var ci = 0; ci < SUPPLY_CHAIN.length; ci++) {
          if (SUPPLY_CHAIN[ci].deps && SUPPLY_CHAIN[ci].deps.indexOf(compName) !== -1) {
            affected.push(SUPPLY_CHAIN[ci]);
          }
        }
        var out = '<div class="pm-result-title">CASCADE ANALYSIS: ' + esc(compName) + '</div>';
        out += '<div class="pm-result-detail">Directly affected components: ' + esc(String(affected.length)) + '</div>';
        if (affected.length > 0) {
          out += '<div class="pm-table-wrap"><table class="pm-table"><thead><tr><th>COMPONENT</th><th>CATEGORY</th><th>RISK IMPACT</th></tr></thead><tbody>';
          for (var ai = 0; ai < affected.length; ai++) {
            out += '<tr><td>' + esc(affected[ai].name) + '</td><td>' + esc(affected[ai].category) + '</td>';
            out += '<td><span class="pm-risk-high">+' + esc(String(Math.floor(Math.random() * 30 + 10))) + '</span></td></tr>';
          }
          out += '</tbody></table></div>';
        } else {
          out += '<div class="pm-result-detail">No direct dependents found. Component is a leaf node.</div>';
        }
        resultEl.style.display = 'block';
        resultEl.innerHTML = out;
      });
    }

    // Propagation simulator
    var propBtn = main.querySelector('#pmRunPropagation');
    if (propBtn) {
      propBtn.addEventListener('click', function() {
        var sel = main.querySelector('#pmPropTarget');
        var resultEl = main.querySelector('#pmPropResult');
        if (!sel || !resultEl) return;
        var compName = sel.value;
        var steps = [];
        var visited = {};
        var queue = [compName];
        var step = 0;
        visited[compName] = true;
        while (queue.length > 0 && step < 10) {
          var nextQueue = [];
          for (var qi = 0; qi < queue.length; qi++) {
            for (var si = 0; si < SUPPLY_CHAIN.length; si++) {
              if (SUPPLY_CHAIN[si].deps && SUPPLY_CHAIN[si].deps.indexOf(queue[qi]) !== -1 && !visited[SUPPLY_CHAIN[si].name]) {
                visited[SUPPLY_CHAIN[si].name] = true;
                nextQueue.push(SUPPLY_CHAIN[si].name);
              }
            }
          }
          if (nextQueue.length > 0) {
            steps.push({ step: step + 1, components: nextQueue });
          }
          queue = nextQueue;
          step++;
        }
        var totalAffected = Object.keys(visited).length - 1;
        var out = '<div class="pm-result-title">PROPAGATION ANALYSIS: ' + esc(compName) + '</div>';
        out += '<div class="pm-result-detail">Total components affected: ' + esc(String(totalAffected)) + '</div>';
        if (steps.length > 0) {
          for (var pi = 0; pi < steps.length; pi++) {
            out += '<div class="pm-prop-step">';
            out += '<span class="pm-prop-step-label">STEP ' + esc(String(steps[pi].step)) + ':</span> ';
            out += esc(steps[pi].components.join(', '));
            out += '</div>';
          }
        } else {
          out += '<div class="pm-result-detail">No downstream propagation detected.</div>';
        }
        resultEl.style.display = 'block';
        resultEl.innerHTML = out;
      });
    }
  }

  // =========================================================================
  // TAB 11: DEFENSE ORCHESTRATOR
  // =========================================================================

  var CONTAINMENT_ACTIONS = [
    { name: 'Network Isolation', status: 'standby', triggered: 12, lastTriggered: '2026-09-12 14:22:10', scope: 'Segment-level network isolation via SDN', icon: '[+]' },
    { name: 'Account Lockout', status: 'active', triggered: 34, lastTriggered: '2026-09-13 01:15:44', scope: 'Domain and local account disable', icon: '[U]' },
    { name: 'Process Kill', status: 'standby', triggered: 89, lastTriggered: '2026-09-13 02:01:33', scope: 'Targeted process termination on endpoints', icon: '&#9760;' },
    { name: 'DNS Sinkhole', status: 'active', triggered: 156, lastTriggered: '2026-09-13 02:14:00', scope: 'Redirect malicious domains to sinkhole', icon: '[N]' },
    { name: 'Firewall Block', status: 'active', triggered: 278, lastTriggered: '2026-09-13 02:10:55', scope: 'Dynamic firewall rule injection', icon: '[D]' },
    { name: 'Service Shutdown', status: 'standby', triggered: 3, lastTriggered: '2026-09-10 08:30:00', scope: 'Graceful service termination', icon: '&#9632;' }
  ];

  var AUTO_RESPONSES = [
    { ts: '2026-09-13 02:14:00', trigger: 'DNS query to known C2 domain', action: 'DNS Sinkhole activated', result: 'SUCCESS', duration: '0.3s' },
    { ts: '2026-09-13 02:10:55', trigger: 'Outbound connection to APT-BEAR C2', action: 'Firewall rule added: BLOCK 185.220.101.34', result: 'SUCCESS', duration: '0.8s' },
    { ts: '2026-09-13 02:01:33', trigger: 'Cobalt Strike beacon detected PID 4482', action: 'Process terminated on WS-0142', result: 'SUCCESS', duration: '1.2s' },
    { ts: '2026-09-13 01:55:12', trigger: 'Brute force against RDP endpoint', action: 'Firewall rule added: BLOCK 91.219.237.88', result: 'SUCCESS', duration: '0.5s' },
    { ts: '2026-09-13 01:48:33', trigger: 'Malware hash match on file download', action: 'File quarantined, hash blocked', result: 'SUCCESS', duration: '2.1s' },
    { ts: '2026-09-13 01:42:07', trigger: 'DNS zone transfer attempt', action: 'DNS Sinkhole + source IP blocked', result: 'SUCCESS', duration: '0.4s' },
    { ts: '2026-09-13 01:33:20', trigger: 'Suspicious PowerShell execution', action: 'Process terminated, script logged', result: 'SUCCESS', duration: '0.9s' },
    { ts: '2026-09-13 01:27:55', trigger: 'Phishing email detected', action: 'Email quarantined, sender blocked', result: 'SUCCESS', duration: '1.5s' },
    { ts: '2026-09-13 01:22:14', trigger: 'Honeypot ALPHA interaction', action: 'Session recorded, source flagged', result: 'SUCCESS', duration: '0.2s' },
    { ts: '2026-09-13 01:15:44', trigger: 'Credential stuffing detected', action: 'Account lockout for 15 accounts', result: 'SUCCESS', duration: '3.2s' },
    { ts: '2026-09-13 01:08:30', trigger: 'Lateral movement via PsExec', action: 'Network isolation of source host', result: 'SUCCESS', duration: '4.5s' },
    { ts: '2026-09-13 00:58:19', trigger: 'Internal port scan detected', action: 'Source host isolated', result: 'PARTIAL', duration: '2.8s' },
    { ts: '2026-09-13 00:52:44', trigger: 'Data exfil via DNS tunnel', action: 'DNS sinkhole + investigation ticket', result: 'SUCCESS', duration: '1.1s' },
    { ts: '2026-09-13 00:45:11', trigger: 'Suspicious scheduled task creation', action: 'Task removed, host flagged', result: 'SUCCESS', duration: '1.8s' },
    { ts: '2026-09-13 00:38:55', trigger: 'LSASS memory access by non-system', action: 'Process killed, credentials rotated', result: 'SUCCESS', duration: '5.2s' },
    { ts: '2026-09-12 23:55:22', trigger: 'Webshell upload detected', action: 'File removed, WAF rule added', result: 'SUCCESS', duration: '0.7s' },
    { ts: '2026-09-12 23:44:08', trigger: 'Directory traversal on API', action: 'Source IP blocked, WAF updated', result: 'SUCCESS', duration: '0.6s' },
    { ts: '2026-09-12 23:30:15', trigger: 'Kerberoasting attempt', action: 'Service account password rotated', result: 'SUCCESS', duration: '8.3s' },
    { ts: '2026-09-12 23:22:31', trigger: 'SMTP enumeration detected', action: 'Source blocked at MTA', result: 'SUCCESS', duration: '0.4s' },
    { ts: '2026-09-12 23:10:00', trigger: 'Registry run key modification', action: 'Change reverted, host flagged', result: 'SUCCESS', duration: '2.4s' },
    { ts: '2026-09-12 22:55:33', trigger: 'WMI event subscription created', action: 'Subscription removed', result: 'SUCCESS', duration: '1.3s' },
    { ts: '2026-09-12 22:40:12', trigger: 'Suspicious DLL side-loading', action: 'DLL quarantined, process killed', result: 'SUCCESS', duration: '1.9s' },
    { ts: '2026-09-12 22:25:44', trigger: 'Golden ticket usage detected', action: 'KRBTGT password rotated', result: 'SUCCESS', duration: '15.2s' },
    { ts: '2026-09-12 22:11:54', trigger: 'Modbus probe on SCADA', action: 'Source isolated, ICS alert raised', result: 'SUCCESS', duration: '0.8s' },
    { ts: '2026-09-12 21:55:00', trigger: 'Shadow copy deletion attempt', action: 'VSS protected, host isolated', result: 'SUCCESS', duration: '3.1s' },
    { ts: '2026-09-12 21:38:40', trigger: 'Social engineering call logged', action: 'Alert to security team', result: 'MANUAL', duration: 'N/A' },
    { ts: '2026-09-12 21:22:15', trigger: 'Ransomware file extension change', action: 'Host isolated, backup initiated', result: 'SUCCESS', duration: '6.7s' },
    { ts: '2026-09-12 21:05:33', trigger: 'Audit log clearing attempt', action: 'Action blocked, admin notified', result: 'SUCCESS', duration: '0.3s' },
    { ts: '2026-09-12 20:55:17', trigger: 'Credential stuffing via Tor', action: 'Tor exit nodes blocked', result: 'SUCCESS', duration: '2.0s' },
    { ts: '2026-09-12 20:40:00', trigger: 'RDP brute force from internal', action: 'Source account locked, host flagged', result: 'SUCCESS', duration: '1.4s' }
  ];

  var PLAYBOOKS = [
    { name: 'RANSOMWARE-RESPONSE', currentStep: 4, totalSteps: 8, team: 'Blue Team Alpha', status: 'running', steps: ['Detect', 'Isolate', 'Preserve Evidence', 'Identify Scope', 'Eradicate', 'Recover', 'Monitor', 'Report'] },
    { name: 'APT-CONTAINMENT', currentStep: 3, totalSteps: 6, team: 'CIRT', status: 'running', steps: ['Identify IOCs', 'Scope Impact', 'Contain Lateral', 'Eradicate Persistence', 'Credential Reset', 'Monitor'] },
    { name: 'DATA-BREACH-RESPONSE', currentStep: 6, totalSteps: 10, team: 'IR Team', status: 'paused', steps: ['Detection', 'Triage', 'Scope', 'Contain', 'Forensics', 'Notify Legal', 'Customer Notice', 'Remediate', 'Monitor', 'Lessons Learned'] },
    { name: 'INSIDER-THREAT', currentStep: 2, totalSteps: 7, team: 'CounterIntel', status: 'running', steps: ['Alert Review', 'Evidence Collection', 'Behavioral Analysis', 'Legal Coordination', 'Containment', 'Investigation', 'Closure'] },
    { name: 'DDoS-MITIGATION', currentStep: 5, totalSteps: 5, team: 'NOC', status: 'complete', steps: ['Detect', 'Classify', 'Mitigate', 'Communicate', 'Post-Incident'] }
  ];

  var RECOVERY_SYSTEMS = [
    { priority: 1, name: 'Active Directory Domain Controllers', depsMet: true, estRecovery: '15 min', status: 'recovered' },
    { priority: 2, name: 'DNS Infrastructure', depsMet: true, estRecovery: '10 min', status: 'recovered' },
    { priority: 3, name: 'Certificate Authority', depsMet: true, estRecovery: '20 min', status: 'recovered' },
    { priority: 4, name: 'DHCP Servers', depsMet: true, estRecovery: '5 min', status: 'recovered' },
    { priority: 5, name: 'Email Gateway', depsMet: true, estRecovery: '30 min', status: 'in-progress' },
    { priority: 6, name: 'VPN Concentrators', depsMet: true, estRecovery: '25 min', status: 'in-progress' },
    { priority: 7, name: 'Web Application Firewalls', depsMet: true, estRecovery: '15 min', status: 'in-progress' },
    { priority: 8, name: 'Database Clusters', depsMet: false, estRecovery: '45 min', status: 'pending' },
    { priority: 9, name: 'Application Servers', depsMet: false, estRecovery: '30 min', status: 'pending' },
    { priority: 10, name: 'Load Balancers', depsMet: false, estRecovery: '10 min', status: 'pending' },
    { priority: 11, name: 'Monitoring Systems', depsMet: false, estRecovery: '20 min', status: 'pending' },
    { priority: 12, name: 'Backup Systems', depsMet: false, estRecovery: '35 min', status: 'pending' },
    { priority: 13, name: 'Development Environment', depsMet: false, estRecovery: '40 min', status: 'pending' },
    { priority: 14, name: 'CI/CD Pipeline', depsMet: false, estRecovery: '25 min', status: 'pending' },
    { priority: 15, name: 'User Workstations', depsMet: false, estRecovery: '60 min', status: 'pending' }
  ];

  var CREDENTIAL_SETS = [
    { name: 'Domain Admin Accounts', type: 'Password', lastRotation: '2026-09-12', nextRotation: '2026-09-19', health: 'good' },
    { name: 'Service Accounts (Tier 0)', type: 'Password', lastRotation: '2026-09-10', nextRotation: '2026-09-17', health: 'good' },
    { name: 'Service Accounts (Tier 1)', type: 'Password', lastRotation: '2026-09-08', nextRotation: '2026-09-15', health: 'warning' },
    { name: 'API Gateway Keys', type: 'API Key', lastRotation: '2026-09-11', nextRotation: '2026-09-18', health: 'good' },
    { name: 'Database Credentials', type: 'Password', lastRotation: '2026-09-05', nextRotation: '2026-09-12', health: 'critical' },
    { name: 'SSL/TLS Certificates', type: 'Certificate', lastRotation: '2026-08-15', nextRotation: '2026-11-15', health: 'good' },
    { name: 'SSH Keys (Infrastructure)', type: 'SSH Key', lastRotation: '2026-09-01', nextRotation: '2026-10-01', health: 'good' },
    { name: 'Cloud IAM Keys (AWS)', type: 'Access Key', lastRotation: '2026-09-09', nextRotation: '2026-09-16', health: 'good' },
    { name: 'Cloud IAM Keys (Azure)', type: 'Access Key', lastRotation: '2026-09-07', nextRotation: '2026-09-14', health: 'warning' },
    { name: 'KRBTGT Account', type: 'Kerberos', lastRotation: '2026-09-12', nextRotation: '2026-09-26', health: 'good' }
  ];

  function renderDefense() {
    var h = '';
    h += '<div class="pm-section-header">DEFENSE ORCHESTRATION CENTER</div>';

    // Active Containment Status
    h += '<div class="pm-subsection-title">ACTIVE CONTAINMENT STATUS</div>';
    h += '<div class="pm-containment-grid">';
    for (var i = 0; i < CONTAINMENT_ACTIONS.length; i++) {
      var ca = CONTAINMENT_ACTIONS[i];
      var caStatusCls = ca.status === 'active' ? 'pm-contain-active' : 'pm-contain-standby';
      var dotCls = ca.status === 'active' ? 'pm-dot-green' : 'pm-dot-yellow';
      h += '<div class="pm-containment-card ' + caStatusCls + '">';
      h += '<div class="pm-contain-icon">' + ca.icon + '</div>';
      h += '<div class="pm-contain-name">' + esc(ca.name) + '</div>';
      h += '<div class="pm-contain-status"><span class="' + dotCls + '"></span> ' + esc(ca.status.toUpperCase()) + '</div>';
      h += '<div class="pm-contain-detail">Triggered: ' + esc(String(ca.triggered)) + ' times</div>';
      h += '<div class="pm-contain-detail">Last: ' + esc(ca.lastTriggered) + '</div>';
      h += '<div class="pm-contain-scope">' + esc(ca.scope) + '</div>';
      h += '<button class="pm-btn pm-btn-sm pm-contain-toggle" data-idx="' + i + '">' + (ca.status === 'active' ? 'DEACTIVATE' : 'ACTIVATE') + '</button>';
      h += '</div>';
    }
    h += '</div>';

    // Automated Response Log
    h += '<div class="pm-subsection-title">AUTOMATED RESPONSE LOG</div>';
    h += '<div class="pm-form-row">';
    h += '<label class="pm-label">FILTER: </label>';
    h += '<select id="pmResponseFilter" class="pm-select">';
    h += '<option value="all">ALL ACTIONS</option>';
    h += '<option value="SUCCESS">SUCCESS</option>';
    h += '<option value="PARTIAL">PARTIAL</option>';
    h += '<option value="MANUAL">MANUAL</option>';
    h += '</select>';
    h += '</div>';
    h += '<div class="pm-response-log" id="pmResponseLog">';
    h += '<div class="pm-table-wrap"><table class="pm-table">';
    h += '<thead><tr><th>TIMESTAMP</th><th>TRIGGER</th><th>ACTION</th><th>RESULT</th><th>DURATION</th></tr></thead>';
    h += '<tbody>';
    for (var r = 0; r < AUTO_RESPONSES.length; r++) {
      var ar = AUTO_RESPONSES[r];
      var resCls = ar.result === 'SUCCESS' ? 'pm-status-green' : ar.result === 'PARTIAL' ? 'pm-status-yellow' : 'pm-status-blue';
      h += '<tr class="pm-response-row" data-result="' + esc(ar.result) + '">';
      h += '<td class="pm-mono">' + esc(ar.ts) + '</td>';
      h += '<td>' + esc(ar.trigger) + '</td>';
      h += '<td>' + esc(ar.action) + '</td>';
      h += '<td><span class="' + resCls + '">' + esc(ar.result) + '</span></td>';
      h += '<td>' + esc(ar.duration) + '</td>';
      h += '</tr>';
    }
    h += '</tbody></table></div>';
    h += '</div>';

    // Playbook Execution Status
    h += '<div class="pm-subsection-title">PLAYBOOK EXECUTION STATUS</div>';
    h += '<div class="pm-playbook-list">';
    for (var p = 0; p < PLAYBOOKS.length; p++) {
      var pb = PLAYBOOKS[p];
      var pct = Math.round(pb.currentStep / pb.totalSteps * 100);
      var pbStatusCls = pb.status === 'running' ? 'pm-status-green' : pb.status === 'paused' ? 'pm-status-yellow' : 'pm-status-blue';
      h += '<div class="pm-playbook-card">';
      h += '<div class="pm-playbook-header">';
      h += '<span class="pm-playbook-name">' + esc(pb.name) + '</span>';
      h += '<span class="' + pbStatusCls + '">' + esc(pb.status.toUpperCase()) + '</span>';
      h += '</div>';
      h += '<div class="pm-playbook-team">Team: ' + esc(pb.team) + '</div>';
      h += '<div class="pm-playbook-progress">';
      h += '<div class="pm-progress-bar"><div class="pm-progress-fill" style="width:' + pct + '%"></div></div>';
      h += '<span class="pm-progress-text">' + esc(String(pb.currentStep)) + '/' + esc(String(pb.totalSteps)) + ' (' + esc(String(pct)) + '%)</span>';
      h += '</div>';
      h += '<div class="pm-playbook-steps">';
      for (var ps = 0; ps < pb.steps.length; ps++) {
        var stepCls = ps < pb.currentStep ? 'pm-step-done' : ps === pb.currentStep ? 'pm-step-active' : 'pm-step-pending';
        h += '<span class="pm-step ' + stepCls + '">' + esc(pb.steps[ps]) + '</span>';
      }
      h += '</div>';
      if (pb.status !== 'complete') {
        h += '<button class="pm-btn pm-btn-sm pm-playbook-toggle" data-idx="' + p + '">' + (pb.status === 'paused' ? 'RESUME' : 'PAUSE') + '</button>';
      }
      h += '</div>';
    }
    h += '</div>';

    // Recovery Dashboard
    h += '<div class="pm-subsection-title">RECOVERY DASHBOARD — DEPENDENCY-AWARE RESTART ORDERING</div>';
    h += '<div class="pm-table-wrap"><table class="pm-table">';
    h += '<thead><tr><th>PRIORITY</th><th>SYSTEM</th><th>DEPS MET</th><th>EST. RECOVERY</th><th>STATUS</th><th>ACTION</th></tr></thead>';
    h += '<tbody>';
    for (var rv = 0; rv < RECOVERY_SYSTEMS.length; rv++) {
      var rs = RECOVERY_SYSTEMS[rv];
      var rsStatusCls = rs.status === 'recovered' ? 'pm-status-green' : rs.status === 'in-progress' ? 'pm-status-yellow' : 'pm-status-red';
      var depsCls = rs.depsMet ? 'pm-status-green' : 'pm-status-red';
      h += '<tr>';
      h += '<td class="pm-center">' + esc(String(rs.priority)) + '</td>';
      h += '<td>' + esc(rs.name) + '</td>';
      h += '<td><span class="' + depsCls + '">' + (rs.depsMet ? 'YES' : 'NO') + '</span></td>';
      h += '<td>' + esc(rs.estRecovery) + '</td>';
      h += '<td><span class="' + rsStatusCls + '">' + esc(rs.status.toUpperCase()) + '</span></td>';
      h += '<td>';
      if (rs.status === 'pending' && rs.depsMet) {
        h += '<button class="pm-btn pm-btn-sm pm-recovery-btn" data-idx="' + rv + '">START RECOVERY</button>';
      } else if (rs.status === 'in-progress') {
        h += '<span class="pm-blink">RECOVERING...</span>';
      } else if (rs.status === 'recovered') {
        h += '<span class="pm-status-green">ONLINE</span>';
      } else {
        h += '<span class="pm-status-dim">WAITING ON DEPS</span>';
      }
      h += '</td>';
      h += '</tr>';
    }
    h += '</tbody></table></div>';

    // Credential Rotation Status
    h += '<div class="pm-subsection-title">CREDENTIAL ROTATION STATUS</div>';
    h += '<div class="pm-table-wrap"><table class="pm-table">';
    h += '<thead><tr><th>CREDENTIAL SET</th><th>TYPE</th><th>LAST ROTATION</th><th>NEXT ROTATION</th><th>HEALTH</th></tr></thead>';
    h += '<tbody>';
    for (var cr = 0; cr < CREDENTIAL_SETS.length; cr++) {
      var cs = CREDENTIAL_SETS[cr];
      var healthCls = cs.health === 'good' ? 'pm-status-green' : cs.health === 'warning' ? 'pm-status-yellow' : 'pm-status-red';
      h += '<tr>';
      h += '<td>' + esc(cs.name) + '</td>';
      h += '<td>' + esc(cs.type) + '</td>';
      h += '<td>' + esc(cs.lastRotation) + '</td>';
      h += '<td>' + esc(cs.nextRotation) + '</td>';
      h += '<td><span class="' + healthCls + '">' + esc(cs.health.toUpperCase()) + '</span></td>';
      h += '</tr>';
    }
    h += '</tbody></table></div>';

    // Kill Switch Controls
    h += '<div class="pm-subsection-title">EMERGENCY KILL SWITCHES</div>';
    h += '<div class="pm-killswitch-warning">&#9888; REQUIRES HUMAN AUTHORIZATION — IRREVERSIBLE ACTIONS</div>';
    h += '<div class="pm-killswitch-grid">';

    var killSwitches = [
      { id: 'netKill', name: 'NETWORK KILL SWITCH', desc: 'Immediately sever all external network connections. Internal-only mode.', status: 'armed' },
      { id: 'sysLock', name: 'SYSTEM LOCKDOWN', desc: 'Lock all user accounts, disable remote access, enforce maintenance mode.', status: 'armed' },
      { id: 'evidence', name: 'EVIDENCE PRESERVATION', desc: 'Snapshot all systems, freeze logs, initiate forensic collection.', status: 'armed' }
    ];

    for (var ks = 0; ks < killSwitches.length; ks++) {
      var sw = killSwitches[ks];
      h += '<div class="pm-killswitch-card">';
      h += '<div class="pm-ks-name">' + esc(sw.name) + '</div>';
      h += '<div class="pm-ks-desc">' + esc(sw.desc) + '</div>';
      h += '<div class="pm-ks-status">Status: <span class="pm-status-yellow">' + esc(sw.status.toUpperCase()) + '</span></div>';
      h += '<button class="pm-btn pm-btn-kill pm-ks-btn" data-ks="' + esc(sw.id) + '">ACTIVATE</button>';
      h += '<div class="pm-ks-confirm" id="pmKsConfirm' + esc(sw.id) + '" style="display:none">';
      h += '<div class="pm-ks-confirm-text">CONFIRM ACTIVATION? This action is irreversible.</div>';
      h += '<button class="pm-btn pm-btn-kill pm-ks-confirm-btn" data-ks="' + esc(sw.id) + '">CONFIRM — ACTIVATE NOW</button>';
      h += '<button class="pm-btn pm-btn-sm pm-ks-cancel-btn" data-ks="' + esc(sw.id) + '">CANCEL</button>';
      h += '</div>';
      h += '</div>';
    }
    h += '</div>';

    return h;
  }

  function bindDefense() {
    // Containment toggle
    var containBtns = main.querySelectorAll('.pm-contain-toggle');
    for (var i = 0; i < containBtns.length; i++) {
      containBtns[i].addEventListener('click', function() {
        var idx = parseInt(this.getAttribute('data-idx'));
        if (CONTAINMENT_ACTIONS[idx]) {
          CONTAINMENT_ACTIONS[idx].status = CONTAINMENT_ACTIONS[idx].status === 'active' ? 'standby' : 'active';
          render();
        }
      });
    }

    // Response log filter
    var respFilter = main.querySelector('#pmResponseFilter');
    if (respFilter) {
      respFilter.addEventListener('change', function() {
        var val = this.value;
        var rows = main.querySelectorAll('.pm-response-row');
        for (var j = 0; j < rows.length; j++) {
          if (val === 'all' || rows[j].getAttribute('data-result') === val) {
            rows[j].style.display = '';
          } else {
            rows[j].style.display = 'none';
          }
        }
      });
    }

    // Playbook pause/resume
    var pbBtns = main.querySelectorAll('.pm-playbook-toggle');
    for (var p = 0; p < pbBtns.length; p++) {
      pbBtns[p].addEventListener('click', function() {
        var idx = parseInt(this.getAttribute('data-idx'));
        if (PLAYBOOKS[idx]) {
          PLAYBOOKS[idx].status = PLAYBOOKS[idx].status === 'paused' ? 'running' : 'paused';
          render();
        }
      });
    }

    // Recovery restart buttons
    var recBtns = main.querySelectorAll('.pm-recovery-btn');
    for (var rb = 0; rb < recBtns.length; rb++) {
      recBtns[rb].addEventListener('click', function() {
        var idx = parseInt(this.getAttribute('data-idx'));
        if (RECOVERY_SYSTEMS[idx]) {
          RECOVERY_SYSTEMS[idx].status = 'in-progress';
          render();
        }
      });
    }

    // Kill switch buttons
    var ksBtns = main.querySelectorAll('.pm-ks-btn');
    for (var k = 0; k < ksBtns.length; k++) {
      ksBtns[k].addEventListener('click', function() {
        var ksId = this.getAttribute('data-ks');
        var confirmEl = main.querySelector('#pmKsConfirm' + ksId);
        if (confirmEl) {
          confirmEl.style.display = 'block';
          this.style.display = 'none';
        }
      });
    }

    var ksConfirmBtns = main.querySelectorAll('.pm-ks-confirm-btn');
    for (var kc = 0; kc < ksConfirmBtns.length; kc++) {
      ksConfirmBtns[kc].addEventListener('click', function() {
        var ksId = this.getAttribute('data-ks');
        var card = this.closest('.pm-killswitch-card');
        if (card) {
          card.innerHTML = '<div class="pm-ks-activated">' +
            '<div class="pm-ks-name">' + esc(ksId.toUpperCase()) + '</div>' +
            '<div class="pm-status-red pm-blink">ACTIVATED</div>' +
            '<div class="pm-ks-time">Activated: ' + esc(new Date().toISOString().replace('T', ' ').slice(0, 19)) + '</div>' +
            '</div>';
        }
      });
    }

    var ksCancelBtns = main.querySelectorAll('.pm-ks-cancel-btn');
    for (var kx = 0; kx < ksCancelBtns.length; kx++) {
      ksCancelBtns[kx].addEventListener('click', function() {
        var ksId = this.getAttribute('data-ks');
        var confirmEl = main.querySelector('#pmKsConfirm' + ksId);
        var activateBtn = this.closest('.pm-killswitch-card').querySelector('.pm-ks-btn');
        if (confirmEl) confirmEl.style.display = 'none';
        if (activateBtn) activateBtn.style.display = '';
      });
    }
  }

  // =========================================================================
  // TAB 12: BATTLE DAMAGE ASSESSMENT
  // =========================================================================

  var BDA_EVIDENCE = [
    { id: 'EV-2026-0001', type: 'SIGINT', source: 'COMSAT-7', classification: 'TOP SECRET//SCI', desc: 'Intercepted communications confirming target system offline', chain: 'VERIFIED', hash: 'a3f8c91b2d4e5f6a7b8c9d0e1f2a3b4c' },
    { id: 'EV-2026-0002', type: 'IMINT', source: 'SAT-KEYHOLE-12', classification: 'TOP SECRET', desc: 'Satellite imagery showing physical damage to server facility', chain: 'VERIFIED', hash: 'b4e9d02c3f5a6b7c8d9e0f1a2b3c4d5e' },
    { id: 'EV-2026-0003', type: 'Cyber', source: 'CNE Team Alpha', classification: 'SECRET//NOFORN', desc: 'Implant telemetry confirming target database corruption', chain: 'VERIFIED', hash: 'c5f0e13d4a6b7c8d9e0f1a2b3c4d5e6f' },
    { id: 'EV-2026-0004', type: 'HUMINT', source: 'SOURCE CARDINAL', classification: 'TOP SECRET//HCS', desc: 'Human source confirms target organization operational disruption', chain: 'VERIFIED', hash: 'd6a1f24e5b7c8d9e0f1a2b3c4d5e6f7a' },
    { id: 'EV-2026-0005', type: 'MASINT', source: 'ELINT Platform', classification: 'SECRET', desc: 'Electromagnetic emissions from target facility ceased', chain: 'VERIFIED', hash: 'e7b2a35f6c8d9e0f1a2b3c4d5e6f7a8b' },
    { id: 'EV-2026-0006', type: 'OSINT', source: 'Social Media', classification: 'UNCLASSIFIED', desc: 'Public reports of service outage consistent with operation timeline', chain: 'VERIFIED', hash: 'f8c3b46a7d9e0f1a2b3c4d5e6f7a8b9c' },
    { id: 'EV-2026-0007', type: 'Cyber', source: 'Passive DNS', classification: 'SECRET', desc: 'Target domains no longer resolving after engagement window', chain: 'VERIFIED', hash: 'a9d4c57b8e0f1a2b3c4d5e6f7a8b9c0d' },
    { id: 'EV-2026-0008', type: 'SIGINT', source: 'SIGINT Station', classification: 'TOP SECRET//SCI', desc: 'Intercepted emergency communications from target network ops center', chain: 'PENDING', hash: 'b0e5d68c9f1a2b3c4d5e6f7a8b9c0d1e' },
    { id: 'EV-2026-0009', type: 'IMINT', source: 'UAV-REAPER-3', classification: 'SECRET', desc: 'Aerial imagery of target facility emergency generator activation', chain: 'VERIFIED', hash: 'c1f6e79d0a2b3c4d5e6f7a8b9c0d1e2f' },
    { id: 'EV-2026-0010', type: 'Cyber', source: 'Honeypot Network', classification: 'SECRET', desc: 'Target adversary ceased scanning operations post-engagement', chain: 'VERIFIED', hash: 'd2a7f80e1b3c4d5e6f7a8b9c0d1e2f3a' },
    { id: 'EV-2026-0011', type: 'HUMINT', source: 'LIAISON PARTNER', classification: 'SECRET//REL FVEY', desc: 'Allied service confirms target impact assessment corroborates findings', chain: 'VERIFIED', hash: 'e3b8a91f2c4d5e6f7a8b9c0d1e2f3a4b' },
    { id: 'EV-2026-0012', type: 'MASINT', source: 'Spectrum Analyzer', classification: 'SECRET', desc: 'RF emissions profile change consistent with hardware damage', chain: 'PENDING', hash: 'f4c9b02a3d5e6f7a8b9c0d1e2f3a4b5c' }
  ];

  var RECOVERY_TIMELINE_BDA = [
    { step: 1, name: 'Initial Impact', time: 'T+0', desc: 'Target systems impacted. Primary capabilities degraded or denied.' },
    { step: 2, name: 'Damage Assessment', time: 'T+2h', desc: 'Target begins internal assessment of damage scope and nature.' },
    { step: 3, name: 'Emergency Response', time: 'T+6h', desc: 'Target activates incident response. Backup systems brought online.' },
    { step: 4, name: 'Partial Restoration', time: 'T+24h', desc: 'Limited capability restored via redundant systems and manual processes.' },
    { step: 5, name: 'Investigation Phase', time: 'T+48h', desc: 'Target conducts forensic investigation, identifies attack vectors.' },
    { step: 6, name: 'Rebuild Phase', time: 'T+7d', desc: 'Target begins rebuilding compromised systems from clean backups.' },
    { step: 7, name: 'Hardening', time: 'T+14d', desc: 'Target implements new defenses, patches vulnerabilities, updates procedures.' },
    { step: 8, name: 'Full Restoration', time: 'T+30d', desc: 'Target returns to full operational capability with improved defenses.' }
  ];

  var LESSONS_LEARNED = [
    { category: 'Planning', finding: 'Initial intelligence underestimated target redundancy capabilities', recommendation: 'Incorporate infrastructure resilience analysis in pre-engagement planning', status: 'implementing' },
    { category: 'Execution', finding: 'Timing window was optimal; minimal collateral impact achieved', recommendation: 'Document timing methodology for future reference', status: 'complete' },
    { category: 'Assessment', finding: 'BDA cycle time exceeded target of 4 hours due to SIGINT delays', recommendation: 'Pre-position SIGINT collection assets for faster BDA turnaround', status: 'planned' },
    { category: 'Coordination', finding: 'Allied partner provided critical corroborating intelligence within 6 hours', recommendation: 'Expand allied BDA sharing agreements to additional partners', status: 'in-progress' },
    { category: 'Technical', finding: 'Implant persistence survived target remediation for 72 additional hours', recommendation: 'Update implant resilience metrics in planning models', status: 'complete' }
  ];

  function renderBDA() {
    var h = '';
    h += '<div class="pm-section-header">BATTLE DAMAGE ASSESSMENT</div>';

    // Assessment Form
    h += '<div class="pm-subsection-title">NEW ASSESSMENT</div>';
    h += '<div class="pm-bda-form" id="pmBdaForm">';
    h += '<div class="pm-form-row">';
    h += '<div class="pm-form-group">';
    h += '<label class="pm-label">OPERATION NAME</label>';
    h += '<input id="pmBdaOpName" class="pm-input" type="text" placeholder="Operation codename...">';
    h += '</div>';
    h += '<div class="pm-form-group">';
    h += '<label class="pm-label">DATE</label>';
    h += '<input id="pmBdaDate" class="pm-input" type="text" value="2026-09-13">';
    h += '</div>';
    h += '</div>';
    h += '<div class="pm-form-row">';
    h += '<div class="pm-form-group">';
    h += '<label class="pm-label">TARGET NAME</label>';
    h += '<select id="pmBdaTarget" class="pm-select">';
    for (var n = 0; n < INFRA_NODES.length; n++) {
      h += '<option value="' + esc(INFRA_NODES[n].id) + '">' + esc(INFRA_NODES[n].name) + '</option>';
    }
    h += '</select>';
    h += '</div>';
    h += '<div class="pm-form-group">';
    h += '<label class="pm-label">TARGET COORDINATES</label>';
    h += '<input id="pmBdaCoords" class="pm-input" type="text" placeholder="LAT, LON">';
    h += '</div>';
    h += '</div>';
    h += '<div class="pm-form-row">';
    h += '<div class="pm-form-group">';
    h += '<label class="pm-label">BATTLE DAMAGE CATEGORY</label>';
    h += '<select id="pmBdaCat" class="pm-select">';
    h += '<option value="destroyed">DESTROYED</option>';
    h += '<option value="degraded">DEGRADED</option>';
    h += '<option value="disrupted">DISRUPTED</option>';
    h += '<option value="denied">DENIED</option>';
    h += '</select>';
    h += '</div>';
    h += '<div class="pm-form-group">';
    h += '<label class="pm-label">CONFIDENCE LEVEL: <span id="pmBdaConfVal">75</span>%</label>';
    h += '<input id="pmBdaConf" class="pm-slider" type="range" min="0" max="100" value="75">';
    h += '</div>';
    h += '</div>';
    h += '<div class="pm-form-row">';
    h += '<div class="pm-form-group">';
    h += '<label class="pm-label">EVIDENCE TYPE</label>';
    h += '<div class="pm-checkbox-row">';
    var evTypes = ['SIGINT', 'IMINT', 'MASINT', 'HUMINT', 'Cyber'];
    for (var ev = 0; ev < evTypes.length; ev++) {
      h += '<label class="pm-checkbox-label"><input type="checkbox" class="pm-checkbox pm-ev-check" value="' + esc(evTypes[ev]) + '"> ' + esc(evTypes[ev]) + '</label>';
    }
    h += '</div>';
    h += '</div>';
    h += '</div>';
    h += '<div class="pm-form-row">';
    h += '<div class="pm-form-group pm-full-width">';
    h += '<label class="pm-label">ANALYST NOTES</label>';
    h += '<textarea id="pmBdaNotes" class="pm-textarea" rows="4" placeholder="Enter detailed assessment notes..."></textarea>';
    h += '</div>';
    h += '</div>';
    h += '<div class="pm-form-row">';
    h += '<button id="pmBdaSubmit" class="pm-btn pm-btn-accent">SUBMIT ASSESSMENT</button>';
    h += '<button id="pmBdaReset" class="pm-btn pm-btn-sm">RESET FORM</button>';
    h += '</div>';
    h += '</div>';
    h += '<div id="pmBdaResult" class="pm-result-box" style="display:none"></div>';

    // Target Status Visualization
    h += '<div class="pm-subsection-title">TARGET STATUS VISUALIZATION</div>';
    var bdaCounts = { destroyed: 3, degraded: 8, disrupted: 12, denied: 5 };
    var bdaTotal = bdaCounts.destroyed + bdaCounts.degraded + bdaCounts.disrupted + bdaCounts.denied;
    h += '<div class="pm-bda-quadrant">';
    var bdaCats = [
      { key: 'destroyed', label: 'DESTROYED', color: '#ff0040', count: bdaCounts.destroyed },
      { key: 'degraded', label: 'DEGRADED', color: '#ff6600', count: bdaCounts.degraded },
      { key: 'disrupted', label: 'DISRUPTED', color: '#ffcc00', count: bdaCounts.disrupted },
      { key: 'denied', label: 'DENIED', color: '#0088ff', count: bdaCounts.denied }
    ];
    for (var bc = 0; bc < bdaCats.length; bc++) {
      var bdaCat = bdaCats[bc];
      var bdaPct = (bdaCat.count / bdaTotal * 100).toFixed(1);
      h += '<div class="pm-bda-quad-card">';
      h += '<div class="pm-bda-quad-label" style="color:' + bdaCat.color + '">' + esc(bdaCat.label) + '</div>';
      h += '<div class="pm-bda-quad-count" style="color:' + bdaCat.color + '">' + esc(String(bdaCat.count)) + '</div>';
      h += '<div class="pm-bda-quad-pct">' + esc(bdaPct) + '%</div>';
      h += '<div class="pm-bda-quad-ring">';
      h += '<svg width="80" height="80" viewBox="0 0 80 80">';
      var circumference = 2 * Math.PI * 30;
      var dashLen = circumference * (bdaCat.count / bdaTotal);
      h += '<circle cx="40" cy="40" r="30" fill="none" stroke="#1a1a2e" stroke-width="6"/>';
      h += '<circle cx="40" cy="40" r="30" fill="none" stroke="' + bdaCat.color + '" stroke-width="6" stroke-dasharray="' + dashLen + ' ' + (circumference - dashLen) + '" transform="rotate(-90 40 40)"/>';
      h += '</svg>';
      h += '</div>';
      h += '</div>';
    }
    h += '</div>';

    // Evidence Inventory
    h += '<div class="pm-subsection-title">EVIDENCE INVENTORY</div>';
    h += '<div class="pm-table-wrap"><table class="pm-table">';
    h += '<thead><tr><th>ID</th><th>TYPE</th><th>SOURCE</th><th>CLASSIFICATION</th><th>DESCRIPTION</th><th>CHAIN</th><th>INTEGRITY HASH</th></tr></thead>';
    h += '<tbody>';
    for (var ei = 0; ei < BDA_EVIDENCE.length; ei++) {
      var evi = BDA_EVIDENCE[ei];
      var chainCls = evi.chain === 'VERIFIED' ? 'pm-status-green' : 'pm-status-yellow';
      var classCls = evi.classification.indexOf('TOP SECRET') !== -1 ? 'pm-class-ts' : evi.classification.indexOf('SECRET') !== -1 ? 'pm-class-s' : 'pm-class-u';
      h += '<tr>';
      h += '<td class="pm-mono">' + esc(evi.id) + '</td>';
      h += '<td>' + esc(evi.type) + '</td>';
      h += '<td>' + esc(evi.source) + '</td>';
      h += '<td><span class="' + classCls + '">' + esc(evi.classification) + '</span></td>';
      h += '<td>' + esc(evi.desc) + '</td>';
      h += '<td><span class="' + chainCls + '">' + esc(evi.chain) + '</span></td>';
      h += '<td class="pm-mono pm-hash">' + esc(evi.hash) + '</td>';
      h += '</tr>';
    }
    h += '</tbody></table></div>';

    // Attribution Confidence Matrix
    h += '<div class="pm-subsection-title">ATTRIBUTION CONFIDENCE MATRIX</div>';
    h += '<div class="pm-table-wrap"><table class="pm-table" id="pmAttrTable">';
    h += '<thead><tr><th>APT GROUP</th><th>TECHNICAL</th><th>BEHAVIORAL</th><th>GEOPOLITICAL</th><th>OVERALL</th></tr></thead>';
    h += '<tbody>';
    var attrGroups = APT_GROUPS.slice(0, 5);
    for (var ag = 0; ag < attrGroups.length; ag++) {
      var apt = attrGroups[ag];
      var techConf = Math.floor(Math.random() * 40 + 60);
      var behConf = Math.floor(Math.random() * 50 + 40);
      var geoConf = Math.floor(Math.random() * 60 + 30);
      var overallConf = Math.round((techConf + behConf + geoConf) / 3);
      var overallCls = overallConf >= 70 ? 'pm-risk-crit' : overallConf >= 50 ? 'pm-risk-high' : 'pm-risk-med';
      h += '<tr class="pm-attr-row" data-idx="' + ag + '">';
      h += '<td>' + esc(apt.name) + ' (' + esc(apt.origin) + ')</td>';
      h += '<td>' + esc(String(techConf)) + '%</td>';
      h += '<td>' + esc(String(behConf)) + '%</td>';
      h += '<td>' + esc(String(geoConf)) + '%</td>';
      h += '<td><span class="' + overallCls + '">' + esc(String(overallConf)) + '%</span></td>';
      h += '</tr>';
      h += '<tr class="pm-attr-detail" id="pmAttrDetail' + ag + '" style="display:none">';
      h += '<td colspan="5">';
      h += '<div class="pm-attr-detail-content">';
      h += '<div>Known TTPs: ' + esc(apt.ttps ? apt.ttps.join(', ') : 'N/A') + '</div>';
      h += '<div>Target Sectors: ' + esc(apt.targets ? apt.targets.join(', ') : 'N/A') + '</div>';
      h += '<div>Threat Level: ' + esc(apt.threat || 'Unknown') + '</div>';
      h += '</div>';
      h += '</td>';
      h += '</tr>';
    }
    h += '</tbody></table></div>';

    // Recovery Timeline
    h += '<div class="pm-subsection-title">TARGET RECOVERY TIMELINE</div>';
    h += '<div class="pm-recovery-timeline">';
    for (var rt = 0; rt < RECOVERY_TIMELINE_BDA.length; rt++) {
      var rStep = RECOVERY_TIMELINE_BDA[rt];
      h += '<div class="pm-rt-step">';
      h += '<div class="pm-rt-marker">' + esc(String(rStep.step)) + '</div>';
      h += '<div class="pm-rt-content">';
      h += '<div class="pm-rt-name">' + esc(rStep.name) + '</div>';
      h += '<div class="pm-rt-time">' + esc(rStep.time) + '</div>';
      h += '<div class="pm-rt-desc">' + esc(rStep.desc) + '</div>';
      h += '</div>';
      h += '</div>';
    }
    h += '</div>';

    // Lessons Learned
    h += '<div class="pm-subsection-title">LESSONS LEARNED</div>';
    h += '<div class="pm-table-wrap"><table class="pm-table">';
    h += '<thead><tr><th>CATEGORY</th><th>FINDING</th><th>RECOMMENDATION</th><th>STATUS</th></tr></thead>';
    h += '<tbody>';
    for (var ll = 0; ll < LESSONS_LEARNED.length; ll++) {
      var lesson = LESSONS_LEARNED[ll];
      var llStatusCls = lesson.status === 'complete' ? 'pm-status-green' : lesson.status === 'in-progress' || lesson.status === 'implementing' ? 'pm-status-yellow' : 'pm-status-blue';
      h += '<tr>';
      h += '<td>' + esc(lesson.category) + '</td>';
      h += '<td>' + esc(lesson.finding) + '</td>';
      h += '<td>' + esc(lesson.recommendation) + '</td>';
      h += '<td><span class="' + llStatusCls + '">' + esc(lesson.status.toUpperCase()) + '</span></td>';
      h += '</tr>';
    }
    h += '</tbody></table></div>';

    return h;
  }

  function bindBDA() {
    // Confidence slider
    var confSlider = main.querySelector('#pmBdaConf');
    var confVal = main.querySelector('#pmBdaConfVal');
    if (confSlider && confVal) {
      confSlider.addEventListener('input', function() {
        confVal.textContent = this.value;
      });
    }

    // Submit assessment
    var submitBtn = main.querySelector('#pmBdaSubmit');
    if (submitBtn) {
      submitBtn.addEventListener('click', function() {
        var opName = main.querySelector('#pmBdaOpName');
        var date = main.querySelector('#pmBdaDate');
        var target = main.querySelector('#pmBdaTarget');
        var coords = main.querySelector('#pmBdaCoords');
        var cat = main.querySelector('#pmBdaCat');
        var conf = main.querySelector('#pmBdaConf');
        var notes = main.querySelector('#pmBdaNotes');
        var resultEl = main.querySelector('#pmBdaResult');

        if (!opName || !resultEl) return;
        if (!opName.value.trim()) {
          resultEl.style.display = 'block';
          resultEl.innerHTML = '<div class="pm-result-error">ERROR: Operation name is required.</div>';
          return;
        }

        var evChecks = main.querySelectorAll('.pm-ev-check:checked');
        var evList = [];
        for (var ec = 0; ec < evChecks.length; ec++) {
          evList.push(evChecks[ec].value);
        }

        var out = '<div class="pm-result-success">';
        out += '<div class="pm-result-title">ASSESSMENT SUBMITTED</div>';
        out += '<div class="pm-result-detail">Operation: ' + esc(opName.value) + '</div>';
        out += '<div class="pm-result-detail">Date: ' + esc(date ? date.value : 'N/A') + '</div>';
        out += '<div class="pm-result-detail">Target: ' + esc(target ? target.options[target.selectedIndex].text : 'N/A') + '</div>';
        out += '<div class="pm-result-detail">Coordinates: ' + esc(coords ? coords.value : 'N/A') + '</div>';
        out += '<div class="pm-result-detail">Category: ' + esc(cat ? cat.value.toUpperCase() : 'N/A') + '</div>';
        out += '<div class="pm-result-detail">Confidence: ' + esc(conf ? conf.value : '0') + '%</div>';
        out += '<div class="pm-result-detail">Evidence Types: ' + esc(evList.length > 0 ? evList.join(', ') : 'None selected') + '</div>';
        out += '<div class="pm-result-detail">Notes: ' + esc(notes ? notes.value : 'N/A') + '</div>';
        out += '<div class="pm-result-detail">Assessment ID: BDA-' + esc(String(Math.floor(Math.random() * 90000 + 10000))) + '</div>';
        out += '</div>';
        resultEl.style.display = 'block';
        resultEl.innerHTML = out;
      });
    }

    // Reset form
    var resetBtn = main.querySelector('#pmBdaReset');
    if (resetBtn) {
      resetBtn.addEventListener('click', function() {
        var opName = main.querySelector('#pmBdaOpName');
        var notes = main.querySelector('#pmBdaNotes');
        var coords = main.querySelector('#pmBdaCoords');
        var conf = main.querySelector('#pmBdaConf');
        var confDisplay = main.querySelector('#pmBdaConfVal');
        var resultEl = main.querySelector('#pmBdaResult');
        if (opName) opName.value = '';
        if (notes) notes.value = '';
        if (coords) coords.value = '';
        if (conf) conf.value = '75';
        if (confDisplay) confDisplay.textContent = '75';
        if (resultEl) resultEl.style.display = 'none';
        var evChecks = main.querySelectorAll('.pm-ev-check');
        for (var ec = 0; ec < evChecks.length; ec++) {
          evChecks[ec].checked = false;
        }
      });
    }

    // Attribution row expand
    var attrRows = main.querySelectorAll('.pm-attr-row');
    for (var ar = 0; ar < attrRows.length; ar++) {
      attrRows[ar].addEventListener('click', function() {
        var idx = this.getAttribute('data-idx');
        var detail = main.querySelector('#pmAttrDetail' + idx);
        if (detail) {
          detail.style.display = detail.style.display === 'none' ? '' : 'none';
        }
      });
    }
  }

  // =========================================================================
  // TAB 13: COMMAND AUTHORITY
  // =========================================================================

  var ALLIED_NATIONS = [
    { name: 'United Kingdom', code: 'GBR', coordination: 'Full', sharedIntel: true, jointOps: 12, lastCoord: '2026-09-13 01:00:00' },
    { name: 'Australia', code: 'AUS', coordination: 'Full', sharedIntel: true, jointOps: 8, lastCoord: '2026-09-12 22:00:00' },
    { name: 'Canada', code: 'CAN', coordination: 'Partial', sharedIntel: true, jointOps: 5, lastCoord: '2026-09-12 18:00:00' },
    { name: 'New Zealand', code: 'NZL', coordination: 'Limited', sharedIntel: false, jointOps: 2, lastCoord: '2026-09-10 12:00:00' },
    { name: 'Japan', code: 'JPN', coordination: 'Partial', sharedIntel: true, jointOps: 3, lastCoord: '2026-09-11 09:00:00' }
  ];

  var LEGAL_MATRIX = [
    { opType: 'Defensive Monitoring', unitCmd: true, theaterCmd: false, nationalAuth: false, alliedCoord: false, congressional: false },
    { opType: 'Active Defense', unitCmd: false, theaterCmd: true, nationalAuth: false, alliedCoord: false, congressional: false },
    { opType: 'Offensive Recon', unitCmd: false, theaterCmd: true, nationalAuth: true, alliedCoord: 'conditional', congressional: false },
    { opType: 'Offensive Engagement', unitCmd: false, theaterCmd: false, nationalAuth: true, alliedCoord: true, congressional: 'conditional' },
    { opType: 'Destructive Operations', unitCmd: false, theaterCmd: false, nationalAuth: true, alliedCoord: true, congressional: true }
  ];

  var DECISION_LOG = [
    { ts: '2026-09-13 01:30:00', decision: 'Authorize active defense against APT-BEAR C2 infrastructure', level: 'Theater Commander', rationale: 'Imminent threat to critical infrastructure systems', outcome: 'APPROVED' },
    { ts: '2026-09-12 22:15:00', decision: 'Escalate DEFCON level from 3 to 2', level: 'National Authority', rationale: 'Multiple coordinated attacks detected across sectors', outcome: 'APPROVED' },
    { ts: '2026-09-12 18:00:00', decision: 'Deploy additional deception operations in SCADA sector', level: 'Unit Commander', rationale: 'Increased probing activity targeting ICS systems', outcome: 'APPROVED' },
    { ts: '2026-09-12 14:30:00', decision: 'Initiate credential rotation for all Tier 0 accounts', level: 'Unit Commander', rationale: 'Kerberoasting attempts detected against service accounts', outcome: 'APPROVED' },
    { ts: '2026-09-12 10:00:00', decision: 'Request allied intelligence sharing on APT-PHOENIX', level: 'Theater Commander', rationale: 'Social engineering campaign targets overlap with allied interests', outcome: 'APPROVED' },
    { ts: '2026-09-11 20:00:00', decision: 'Deny request for offensive engagement against attribution target', level: 'National Authority', rationale: 'Insufficient attribution confidence (below 80% threshold)', outcome: 'DENIED' },
    { ts: '2026-09-11 16:00:00', decision: 'Authorize network isolation of compromised subnet', level: 'Unit Commander', rationale: 'Active lateral movement detected from compromised host', outcome: 'APPROVED' },
    { ts: '2026-09-11 12:00:00', decision: 'Extend wargame exercise IRON SHIELD by 24 hours', level: 'Theater Commander', rationale: 'Additional scenarios needed to test new defense capabilities', outcome: 'APPROVED' },
    { ts: '2026-09-10 08:00:00', decision: 'Approve supply chain audit of critical software vendors', level: 'Unit Commander', rationale: 'Anomalous behavior detected in third-party components', outcome: 'APPROVED' },
    { ts: '2026-09-09 14:00:00', decision: 'Share threat intelligence with FVEY partners', level: 'Theater Commander', rationale: 'Common adversary targeting allied infrastructure', outcome: 'APPROVED' }
  ];

  function renderAuthority() {
    var h = '';
    h += '<div class="pm-section-header">COMMAND AUTHORITY &amp; ESCALATION</div>';

    // Escalation Ladder
    h += '<div class="pm-subsection-title">ESCALATION LADDER</div>';
    h += '<div class="pm-escalation-ladder">';
    for (var i = 0; i < ESCALATION_LEVELS.length; i++) {
      var lvl = ESCALATION_LEVELS[i];
      var isCurrent = (i === (state.defconLevel || 2) - 1);
      var lvlClass = isCurrent ? 'pm-esc-level pm-esc-current' : 'pm-esc-level';
      h += '<div class="' + lvlClass + '" data-level="' + (i + 1) + '">';
      h += '<div class="pm-esc-number">LEVEL ' + esc(String(i + 1)) + '</div>';
      h += '<div class="pm-esc-name">' + esc(lvl.name) + '</div>';
      h += '<div class="pm-esc-desc">' + esc(lvl.description) + '</div>';
      h += '<div class="pm-esc-approval">Required Approval: ' + esc(lvl.approval) + '</div>';
      h += '<div class="pm-esc-examples">Examples: ' + esc(lvl.examples) + '</div>';
      if (isCurrent) {
        h += '<div class="pm-esc-badge">CURRENT LEVEL</div>';
      }
      h += '</div>';
      if (i < ESCALATION_LEVELS.length - 1) {
        h += '<div class="pm-esc-connector"></div>';
      }
    }
    h += '</div>';

    // Legal Authority Matrix
    h += '<div class="pm-subsection-title">LEGAL AUTHORITY MATRIX</div>';
    h += '<div class="pm-table-wrap"><table class="pm-table">';
    h += '<thead><tr>';
    h += '<th>OPERATION TYPE</th>';
    h += '<th>UNIT CMDR</th>';
    h += '<th>THEATER CMDR</th>';
    h += '<th>NATIONAL AUTH</th>';
    h += '<th>ALLIED COORD</th>';
    h += '<th>CONGRESSIONAL</th>';
    h += '</tr></thead><tbody>';
    for (var lm = 0; lm < LEGAL_MATRIX.length; lm++) {
      var law = LEGAL_MATRIX[lm];
      h += '<tr>';
      h += '<td>' + esc(law.opType) + '</td>';
      var fields = [law.unitCmd, law.theaterCmd, law.nationalAuth, law.alliedCoord, law.congressional];
      for (var f = 0; f < fields.length; f++) {
        if (fields[f] === true) {
          h += '<td class="pm-center"><span class="pm-auth-check">&#10003;</span></td>';
        } else if (fields[f] === false) {
          h += '<td class="pm-center"><span class="pm-auth-x">&#10007;</span></td>';
        } else {
          h += '<td class="pm-center"><span class="pm-auth-cond">COND</span></td>';
        }
      }
      h += '</tr>';
    }
    h += '</tbody></table></div>';

    // Allied Coordination Status
    h += '<div class="pm-subsection-title">ALLIED COORDINATION STATUS</div>';
    h += '<div class="pm-allied-grid">';
    for (var a = 0; a < ALLIED_NATIONS.length; a++) {
      var ally = ALLIED_NATIONS[a];
      var coordCls = ally.coordination === 'Full' ? 'pm-coord-full' : ally.coordination === 'Partial' ? 'pm-coord-partial' : 'pm-coord-limited';
      h += '<div class="pm-allied-card">';
      h += '<div class="pm-allied-name">' + esc(ally.name) + ' (' + esc(ally.code) + ')</div>';
      h += '<div class="pm-allied-detail">Coordination: <span class="' + coordCls + '">' + esc(ally.coordination) + '</span></div>';
      h += '<div class="pm-allied-detail">Shared Intel: ' + (ally.sharedIntel ? '<span class="pm-status-green">YES</span>' : '<span class="pm-status-red">NO</span>') + '</div>';
      h += '<div class="pm-allied-detail">Joint Ops: ' + esc(String(ally.jointOps)) + '</div>';
      h += '<div class="pm-allied-detail">Last Coord: ' + esc(ally.lastCoord) + '</div>';
      h += '<div class="pm-allied-expand-content" id="pmAllied' + a + '" style="display:none">';
      h += '<div class="pm-allied-expand-detail">Communication Channel: SECURE/ENCRYPTED</div>';
      h += '<div class="pm-allied-expand-detail">Classification Level: ' + (ally.coordination === 'Full' ? 'TOP SECRET//SCI//REL ' + esc(ally.code) : 'SECRET//REL ' + esc(ally.code)) + '</div>';
      h += '<div class="pm-allied-expand-detail">Primary POC: REDACTED</div>';
      h += '<div class="pm-allied-expand-detail">Treaty Framework: ' + (ally.code === 'JPN' ? 'Bilateral Defense Agreement' : 'FVEY / UKUSA Agreement') + '</div>';
      h += '</div>';
      h += '<button class="pm-btn pm-btn-sm pm-allied-expand-btn" data-idx="' + a + '">DETAILS</button>';
      h += '</div>';
    }
    h += '</div>';

    // SITREP/OPREP Generator
    h += '<div class="pm-subsection-title">SITREP / OPREP GENERATOR</div>';
    h += '<div class="pm-report-gen">';
    h += '<div class="pm-form-row">';
    h += '<div class="pm-form-group pm-full-width">';
    h += '<label class="pm-label">OPERATION NAME</label>';
    h += '<input id="pmReportOpName" class="pm-input" type="text" placeholder="Operation name...">';
    h += '</div>';
    h += '</div>';
    h += '<div class="pm-form-row">';
    h += '<div class="pm-form-group pm-full-width">';
    h += '<label class="pm-label">CURRENT SITUATION</label>';
    h += '<textarea id="pmReportSituation" class="pm-textarea" rows="3" placeholder="Describe current situation..."></textarea>';
    h += '</div>';
    h += '</div>';
    h += '<div class="pm-form-row">';
    h += '<div class="pm-form-group pm-full-width">';
    h += '<label class="pm-label">ENEMY ACTIVITY</label>';
    h += '<textarea id="pmReportEnemy" class="pm-textarea" rows="3" placeholder="Describe enemy activity..."></textarea>';
    h += '</div>';
    h += '</div>';
    h += '<div class="pm-form-row">';
    h += '<div class="pm-form-group pm-full-width">';
    h += '<label class="pm-label">FRIENDLY ACTIVITY</label>';
    h += '<textarea id="pmReportFriendly" class="pm-textarea" rows="3" placeholder="Describe friendly activity..."></textarea>';
    h += '</div>';
    h += '</div>';
    h += '<div class="pm-form-row">';
    h += '<button id="pmGenSitrep" class="pm-btn pm-btn-accent">GENERATE SITREP</button>';
    h += '<button id="pmGenOprep" class="pm-btn pm-btn-warn">GENERATE OPREP</button>';
    h += '</div>';
    h += '</div>';
    h += '<div id="pmReportOutput" class="pm-result-box" style="display:none"></div>';

    // Risk/Benefit Analysis
    h += '<div class="pm-subsection-title">RISK / BENEFIT ANALYSIS</div>';
    h += '<div class="pm-risk-benefit">';
    h += '<div class="pm-form-row">';
    h += '<div class="pm-form-group pm-full-width">';
    h += '<label class="pm-label">PROPOSED OPERATION</label>';
    h += '<input id="pmRbOp" class="pm-input" type="text" placeholder="Describe proposed operation...">';
    h += '</div>';
    h += '</div>';
    h += '<div class="pm-form-row">';
    h += '<div class="pm-form-group">';
    h += '<label class="pm-label">RISK LEVEL: <span id="pmRiskVal">5</span>/10</label>';
    h += '<input id="pmRiskSlider" class="pm-slider" type="range" min="1" max="10" value="5">';
    h += '</div>';
    h += '<div class="pm-form-group">';
    h += '<label class="pm-label">EXPECTED BENEFIT: <span id="pmBenefitVal">5</span>/10</label>';
    h += '<input id="pmBenefitSlider" class="pm-slider" type="range" min="1" max="10" value="5">';
    h += '</div>';
    h += '<div class="pm-form-group">';
    h += '<label class="pm-label">COLLATERAL RISK: <span id="pmCollateralVal">3</span>/10</label>';
    h += '<input id="pmCollateralSlider" class="pm-slider" type="range" min="1" max="10" value="3">';
    h += '</div>';
    h += '</div>';
    h += '<div class="pm-rb-result" id="pmRbResult">';
    var initRatio = (5 / (5 + 3)).toFixed(2);
    h += '<div class="pm-rb-ratio">Risk/Benefit Ratio: ' + esc(initRatio) + '</div>';
    h += '<div class="pm-rb-recommendation pm-status-yellow">RECOMMENDATION: CAUTION</div>';
    h += '</div>';
    h += '</div>';

    // Decision Log
    h += '<div class="pm-subsection-title">DECISION LOG</div>';
    h += '<div class="pm-form-row">';
    h += '<label class="pm-label">FILTER: </label>';
    h += '<select id="pmDecisionFilter" class="pm-select">';
    h += '<option value="all">ALL DECISIONS</option>';
    h += '<option value="APPROVED">APPROVED</option>';
    h += '<option value="DENIED">DENIED</option>';
    h += '</select>';
    h += '</div>';
    h += '<div class="pm-table-wrap"><table class="pm-table">';
    h += '<thead><tr><th>TIMESTAMP</th><th>DECISION</th><th>AUTHORITY LEVEL</th><th>RATIONALE</th><th>OUTCOME</th></tr></thead>';
    h += '<tbody id="pmDecisionLog">';
    for (var dl = 0; dl < DECISION_LOG.length; dl++) {
      var dec = DECISION_LOG[dl];
      var decCls = dec.outcome === 'APPROVED' ? 'pm-status-green' : 'pm-status-red';
      h += '<tr class="pm-decision-row" data-outcome="' + esc(dec.outcome) + '">';
      h += '<td class="pm-mono">' + esc(dec.ts) + '</td>';
      h += '<td>' + esc(dec.decision) + '</td>';
      h += '<td>' + esc(dec.level) + '</td>';
      h += '<td>' + esc(dec.rationale) + '</td>';
      h += '<td><span class="' + decCls + '">' + esc(dec.outcome) + '</span></td>';
      h += '</tr>';
    }
    h += '</tbody></table></div>';

    return h;
  }

  function bindAuthority() {
    // Escalation level click
    var escLevels = main.querySelectorAll('.pm-esc-level');
    for (var i = 0; i < escLevels.length; i++) {
      escLevels[i].addEventListener('click', function() {
        var lvl = parseInt(this.getAttribute('data-level'));
        var levels = main.querySelectorAll('.pm-esc-level');
        for (var j = 0; j < levels.length; j++) {
          levels[j].classList.remove('pm-esc-current');
          var badge = levels[j].querySelector('.pm-esc-badge');
          if (badge) badge.remove();
        }
        this.classList.add('pm-esc-current');
        var badgeEl = document.createElement('div');
        badgeEl.className = 'pm-esc-badge';
        badgeEl.textContent = 'CURRENT LEVEL';
        this.appendChild(badgeEl);
        state.defconLevel = lvl;
        saveState();
      });
    }

    // Allied expand buttons
    var alliedBtns = main.querySelectorAll('.pm-allied-expand-btn');
    for (var ab = 0; ab < alliedBtns.length; ab++) {
      alliedBtns[ab].addEventListener('click', function() {
        var idx = this.getAttribute('data-idx');
        var content = main.querySelector('#pmAllied' + idx);
        if (content) {
          if (content.style.display === 'none') {
            content.style.display = 'block';
            this.textContent = 'COLLAPSE';
          } else {
            content.style.display = 'none';
            this.textContent = 'DETAILS';
          }
        }
      });
    }

    // SITREP generator
    var sitrepBtn = main.querySelector('#pmGenSitrep');
    if (sitrepBtn) {
      sitrepBtn.addEventListener('click', function() {
        var opName = main.querySelector('#pmReportOpName');
        var situation = main.querySelector('#pmReportSituation');
        var enemy = main.querySelector('#pmReportEnemy');
        var friendly = main.querySelector('#pmReportFriendly');
        var output = main.querySelector('#pmReportOutput');
        if (!output) return;

        var now = new Date().toISOString().replace('T', ' ').slice(0, 19);
        var out = '<div class="pm-report-output">';
        out += '<div class="pm-report-classification">TOP SECRET//SCI//NOFORN</div>';
        out += '<div class="pm-report-type">SITUATION REPORT (SITREP)</div>';
        out += '<div class="pm-report-line">DTG: ' + esc(now) + 'Z</div>';
        out += '<div class="pm-report-line">OPERATION: ' + esc(opName ? opName.value || 'UNNAMED' : 'UNNAMED') + '</div>';
        out += '<div class="pm-report-line">FROM: PROMETHEUS COMMAND CENTER</div>';
        out += '<div class="pm-report-line">TO: HIGHER HEADQUARTERS</div>';
        out += '<div class="pm-report-divider"></div>';
        out += '<div class="pm-report-section">1. SITUATION</div>';
        out += '<div class="pm-report-body">' + esc(situation ? situation.value || 'No situation reported.' : 'No situation reported.') + '</div>';
        out += '<div class="pm-report-section">2. ENEMY ACTIVITY</div>';
        out += '<div class="pm-report-body">' + esc(enemy ? enemy.value || 'No enemy activity reported.' : 'No enemy activity reported.') + '</div>';
        out += '<div class="pm-report-section">3. FRIENDLY ACTIVITY</div>';
        out += '<div class="pm-report-body">' + esc(friendly ? friendly.value || 'No friendly activity reported.' : 'No friendly activity reported.') + '</div>';
        out += '<div class="pm-report-section">4. ADMINISTRATIVE/LOGISTICS</div>';
        out += '<div class="pm-report-body">All systems operational. No logistics issues to report.</div>';
        out += '<div class="pm-report-section">5. COMMAND AND SIGNAL</div>';
        out += '<div class="pm-report-body">Command: PROMETHEUS ACTUAL. Signal: Primary and alternate comms operational.</div>';
        out += '<div class="pm-report-divider"></div>';
        out += '<div class="pm-report-footer">CLASSIFICATION: TOP SECRET//SCI//NOFORN</div>';
        out += '</div>';

        output.style.display = 'block';
        output.innerHTML = out;
      });
    }

    // OPREP generator
    var oprepBtn = main.querySelector('#pmGenOprep');
    if (oprepBtn) {
      oprepBtn.addEventListener('click', function() {
        var opName = main.querySelector('#pmReportOpName');
        var situation = main.querySelector('#pmReportSituation');
        var enemy = main.querySelector('#pmReportEnemy');
        var friendly = main.querySelector('#pmReportFriendly');
        var output = main.querySelector('#pmReportOutput');
        if (!output) return;

        var now = new Date().toISOString().replace('T', ' ').slice(0, 19);
        var out = '<div class="pm-report-output">';
        out += '<div class="pm-report-classification">TOP SECRET//SCI//NOFORN</div>';
        out += '<div class="pm-report-type">OPERATIONAL REPORT (OPREP-3)</div>';
        out += '<div class="pm-report-line">DTG: ' + esc(now) + 'Z</div>';
        out += '<div class="pm-report-line">OPERATION: ' + esc(opName ? opName.value || 'UNNAMED' : 'UNNAMED') + '</div>';
        out += '<div class="pm-report-line">ORIGINATOR: PROMETHEUS COMMAND CENTER</div>';
        out += '<div class="pm-report-line">PRECEDENCE: FLASH</div>';
        out += '<div class="pm-report-divider"></div>';
        out += '<div class="pm-report-section">A. EVENT CATEGORY: CYBER INCIDENT</div>';
        out += '<div class="pm-report-section">B. CIRCUMSTANCES</div>';
        out += '<div class="pm-report-body">' + esc(situation ? situation.value || 'Pending detailed report.' : 'Pending detailed report.') + '</div>';
        out += '<div class="pm-report-section">C. ASSESSMENT OF HOSTILE THREAT</div>';
        out += '<div class="pm-report-body">' + esc(enemy ? enemy.value || 'Assessment pending.' : 'Assessment pending.') + '</div>';
        out += '<div class="pm-report-section">D. ACTIONS TAKEN</div>';
        out += '<div class="pm-report-body">' + esc(friendly ? friendly.value || 'Actions pending report.' : 'Actions pending report.') + '</div>';
        out += '<div class="pm-report-section">E. RESOURCES NEEDED</div>';
        out += '<div class="pm-report-body">Additional intelligence collection assets requested.</div>';
        out += '<div class="pm-report-section">F. EXPECTED NEXT REPORT</div>';
        out += '<div class="pm-report-body">Next OPREP within 6 hours or upon significant change.</div>';
        out += '<div class="pm-report-divider"></div>';
        out += '<div class="pm-report-footer">CLASSIFICATION: TOP SECRET//SCI//NOFORN</div>';
        out += '</div>';

        output.style.display = 'block';
        output.innerHTML = out;
      });
    }

    // Risk/Benefit sliders
    var riskSlider = main.querySelector('#pmRiskSlider');
    var benefitSlider = main.querySelector('#pmBenefitSlider');
    var collateralSlider = main.querySelector('#pmCollateralSlider');
    var riskVal = main.querySelector('#pmRiskVal');
    var benefitVal = main.querySelector('#pmBenefitVal');
    var collateralVal = main.querySelector('#pmCollateralVal');
    var rbResult = main.querySelector('#pmRbResult');

    function updateRB() {
      if (!riskSlider || !benefitSlider || !collateralSlider || !rbResult) return;
      var risk = parseInt(riskSlider.value);
      var benefit = parseInt(benefitSlider.value);
      var collateral = parseInt(collateralSlider.value);
      if (riskVal) riskVal.textContent = String(risk);
      if (benefitVal) benefitVal.textContent = String(benefit);
      if (collateralVal) collateralVal.textContent = String(collateral);

      var ratio = (benefit / (risk + collateral)).toFixed(2);
      var recommendation, recClass;
      if (parseFloat(ratio) >= 1.5) {
        recommendation = 'PROCEED';
        recClass = 'pm-status-green';
      } else if (parseFloat(ratio) >= 0.75) {
        recommendation = 'CAUTION';
        recClass = 'pm-status-yellow';
      } else {
        recommendation = 'ABORT';
        recClass = 'pm-status-red';
      }

      rbResult.innerHTML = '<div class="pm-rb-ratio">Risk/Benefit Ratio: ' + esc(ratio) + '</div>' +
        '<div class="pm-rb-recommendation ' + recClass + '">RECOMMENDATION: ' + esc(recommendation) + '</div>';
    }

    if (riskSlider) riskSlider.addEventListener('input', updateRB);
    if (benefitSlider) benefitSlider.addEventListener('input', updateRB);
    if (collateralSlider) collateralSlider.addEventListener('input', updateRB);

    // Decision log filter
    var decFilter = main.querySelector('#pmDecisionFilter');
    if (decFilter) {
      decFilter.addEventListener('change', function() {
        var val = this.value;
        var rows = main.querySelectorAll('.pm-decision-row');
        for (var j = 0; j < rows.length; j++) {
          if (val === 'all' || rows[j].getAttribute('data-outcome') === val) {
            rows[j].style.display = '';
          } else {
            rows[j].style.display = 'none';
          }
        }
      });
    }
  }

  // ==========================================================================
  // OMNI ANALYSIS SUITE — added tabs: pivot / attribution / exposure / report
  // All computation is client-side over the existing in-memory datasets.
  // ==========================================================================
  function pmDownload(filename, mime, content) {
    try {
      var blob = new Blob([content], { type: mime });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      // object URL intentionally not revoked via timer to respect no-timer rule
    } catch (e) {}
  }
  function pmCSV(headers, rows) {
    var q = function(v) { v = String(v == null ? '' : v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
    var out = headers.map(q).join(',') + '\n';
    for (var i = 0; i < rows.length; i++) out += rows[i].map(q).join(',') + '\n';
    return out;
  }
  function pmSevColor(score) {
    return score >= 75 ? '#ff0040' : score >= 50 ? '#ffaa00' : score >= 25 ? '#00e5ff' : '#00ff88';
  }
  function pmHay(parts) { return parts.filter(Boolean).join(' ').toLowerCase(); }
  function pmHi(text, q) {
    var s = esc(String(text == null ? '' : text));
    if (!q) return s;
    try {
      var re = new RegExp('(' + q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'ig');
      return s.replace(re, '<span class="pm-hl">$1</span>');
    } catch (e) { return s; }
  }
  function pmActorIOCs(group) {
    var out = [], name = group.name, al = group.aliases || [], db = IOC_DATABASE || [];
    for (var i = 0; i < db.length; i++) {
      var t = db[i].threat;
      if (t && (t === name || name.indexOf(t) !== -1 || al.indexOf(t) !== -1)) out.push(db[i]);
    }
    return out;
  }
  function pmActorCampaigns(group) {
    var out = [];
    for (var i = 0; i < APT_CAMPAIGNS.length; i++) if (APT_CAMPAIGNS[i].apt === group.id) out.push(APT_CAMPAIGNS[i]);
    return out;
  }
  function pmActorTTPs(group) {
    var set = {};
    (group.ttps || []).forEach(function(t) { set[t.split('.')[0]] = true; });
    pmActorCampaigns(group).forEach(function(c) { (c.ttps || []).forEach(function(t) { set[t.split('.')[0]] = true; }); });
    return Object.keys(set);
  }
  function pmMitreName(code) {
    for (var i = 0; i < MITRE_TECHNIQUES.length; i++) if (MITRE_TECHNIQUES[i].id === code) return MITRE_TECHNIQUES[i].name;
    return '';
  }
  function pmNodeExposure(node) {
    var vulns = [], kev = 0, expl = 0, maxCvss = 0, i;
    for (i = 0; i < VULN_DATABASE.length; i++) {
      var v = VULN_DATABASE[i];
      if (v.affectedNodes && v.affectedNodes.indexOf(node.id) !== -1) {
        vulns.push(v);
        if (v.kev) kev++;
        if (v.exploitAvailable) expl++;
        if (v.cvss > maxCvss) maxCvss = v.cvss;
      }
    }
    var preds = [], maxConf = 0;
    for (i = 0; i < THREAT_PREDICTIONS.length; i++) {
      var p = THREAT_PREDICTIONS[i];
      if (p.targets && p.targets.indexOf(node.id) !== -1) { preds.push(p); if (p.confidence > maxConf) maxConf = p.confidence; }
    }
    var dependents = 0;
    for (i = 0; i < INFRA_NODES.length; i++) if (INFRA_NODES[i].deps && INFRA_NODES[i].deps.indexOf(node.id) !== -1) dependents++;
    var score = Math.min(100, Math.round(node.criticality * 4 + kev * 12 + expl * 6 + preds.length * 10 + dependents * 2));
    return { vulns: vulns, kev: kev, expl: expl, maxCvss: maxCvss, preds: preds, maxConf: maxConf, dependents: dependents, score: score };
  }
  function pmBar(score) {
    var c = pmSevColor(score);
    return '<div style="display:flex;align-items:center;gap:8px">' +
      '<div class="pm-bar-track" style="max-width:120px"><div class="pm-bar-fill" style="width:' + score + '%;background:' + c + '"></div></div>' +
      '<span style="color:' + c + ';font-weight:bold;font-family:monospace;min-width:26px">' + score + '</span></div>';
  }

  // -------- TAB: OMNI-PIVOT --------------------------------------------------
  function pmRenderPivotResults(q) {
    var IOCDB = IOC_DATABASE || [];
    q = (q || '').trim().toLowerCase();
    if (!q) {
      var ov = [
        ['IOC DATABASE', IOCDB.length], ['THREAT ACTORS', APT_GROUPS.length],
        ['CAMPAIGNS', APT_CAMPAIGNS.length], ['INTEL FEEDS', INTEL_FEEDS.length],
        ['PREDICTIONS', THREAT_PREDICTIONS.length], ['VULNERABILITIES', VULN_DATABASE.length],
        ['ATT&CK TECHNIQUES', MITRE_TECHNIQUES.length], ['INFRA NODES', INFRA_NODES.length],
        ['SUPPLY CHAIN', SUPPLY_CHAIN.length]
      ];
      var oh = '<div class="pm-stat-row">';
      for (var i = 0; i < ov.length; i++) oh += '<div class="pm-stat-box"><div class="pm-stat-value" style="color:#00e5ff">' + ov[i][1] + '</div><div class="pm-stat-label">' + ov[i][0] + '</div></div>';
      oh += '</div><div class="pm-mono" style="padding:16px 0;text-align:center;color:#667788">Enter a query above to correlate an entity across every dataset.</div>';
      return oh;
    }
    var has = function(x, parts) { return pmHay(parts).indexOf(q) !== -1; };
    var ioc = IOCDB.filter(function(x) { return has(x, [x.value, x.threat, x.type, x.source, (x.tags || []).join(' ')]); });
    var act = APT_GROUPS.filter(function(x) { return has(x, [x.id, x.name, x.nation, (x.aliases || []).join(' '), (x.targets || []).join(' '), (x.ttps || []).join(' ')]); });
    var camp = APT_CAMPAIGNS.filter(function(x) { return has(x, [x.id, x.name, x.apt, (x.tools || []).join(' '), (x.ttps || []).join(' '), (x.sectors || []).join(' '), (x.infrastructure || []).join(' '), x.description]); });
    var intel = INTEL_FEEDS.filter(function(x) { return has(x, [x.id, x.source, x.type, x.summary, x.classification]); });
    var pred = THREAT_PREDICTIONS.filter(function(x) { return has(x, [x.id, x.threat, (x.targets || []).join(' '), (x.indicators || []).join(' '), (x.geopoliticalTriggers || []).join(' ')]); });
    var vuln = VULN_DATABASE.filter(function(x) { return has(x, [x.cve, x.product, x.vendor, x.type, (x.affectedNodes || []).join(' ')]); });
    var mitre = MITRE_TECHNIQUES.filter(function(x) { return has(x, [x.id, x.name, x.tactic, (x.usedBy || []).join(' ')]); });
    var nodes = INFRA_NODES.filter(function(x) { return has(x, [x.id, x.name, x.sector, x.type, x.ip]); });
    var sc = SUPPLY_CHAIN.filter(function(x) { return has(x, [x.id, x.name, x.vendor, x.category, (x.vulns || []).join(' ')]); });
    var all = [ioc, act, camp, intel, pred, vuln, mitre, nodes, sc];
    var total = 0, ds = 0;
    for (var k = 0; k < all.length; k++) { total += all[k].length; if (all[k].length) ds++; }
    function grp(label, items, color, lineFn) {
      if (!items.length) return '';
      var cap = items.slice(0, 30);
      var b = '<div class="pm-hitcard"><div class="pm-hitcard-hdr"><span class="pm-card-title" style="margin:0">' + label + '</span><span class="pm-badge" style="background:' + color + ';color:#04121a;border:none">' + items.length + '</span></div>';
      for (var i = 0; i < cap.length; i++) b += '<div class="pm-hitline">' + lineFn(cap[i]) + '</div>';
      if (items.length > cap.length) b += '<div class="pm-mono" style="padding-top:6px">+' + (items.length - cap.length) + ' more records</div>';
      return b + '</div>';
    }
    var out = '<div class="pm-mono" style="margin:6px 0 12px">MATCH SUMMARY: <strong style="color:#00ff88">' + total + '</strong> records across <strong style="color:#00e5ff">' + ds + '</strong> of 9 datasets for "<strong>' + esc(q) + '</strong>"</div>';
    if (!total) return out + '<div class="pm-mono" style="padding:20px 0;text-align:center;color:#667788">No correlations found. Try an actor name, IP, domain, CVE, ATT&amp;CK ID, or node ID.</div>';
    out += '<div class="pm-pivot-grid">';
    out += grp('IOC DATABASE', ioc, '#ff6600', function(x) { return '<span class="pm-badge pm-badge-medium">' + esc(x.type) + '</span> ' + pmHi(x.value, q) + '<div class="pm-mono">actor: ' + pmHi(x.threat, q) + ' &middot; ' + esc(x.confidence) + ' conf &middot; ' + esc((x.tags || []).join(', ')) + '</div>'; });
    out += grp('THREAT ACTORS', act, '#ff0040', function(x) { return '<strong>' + pmHi(x.id + ' / ' + x.name, q) + '</strong> (' + pmHi(x.nation, q) + ') &middot; threat ' + esc(x.threatLevel) + '<div class="pm-mono">aka ' + pmHi((x.aliases || []).join(', '), q) + '</div>'; });
    out += grp('CAMPAIGNS', camp, '#ffaa00', function(x) { return '<strong>' + pmHi(x.id + ' ' + x.name, q) + '</strong> &middot; ' + esc(x.apt) + ' &middot; ' + esc(x.victims) + ' victims<div class="pm-mono">' + pmHi((x.tools || []).join(', '), q) + '</div>'; });
    out += grp('INTEL FEEDS', intel, '#00bfff', function(x) { return '<strong>' + esc(x.id) + '</strong> <span class="pm-badge pm-badge-low">' + esc(x.type) + '</span> ' + pmHi(x.source, q) + '<div class="pm-mono">' + pmHi(x.summary, q) + '</div>'; });
    out += grp('PREDICTIONS', pred, '#cc44ff', function(x) { return '<strong>' + esc(x.id) + '</strong> &middot; ' + esc(x.confidence) + '% &middot; ' + esc(x.horizon) + '<div class="pm-mono">' + pmHi(x.threat, q) + '</div><div class="pm-mono">targets: ' + pmHi((x.targets || []).join(', '), q) + '</div>'; });
    out += grp('VULNERABILITIES', vuln, '#ff3355', function(x) { return '<strong>' + pmHi(x.cve, q) + '</strong> &middot; CVSS ' + esc(x.cvss) + (x.kev ? ' <span class="pm-badge pm-badge-critical">KEV</span>' : '') + '<div class="pm-mono">' + pmHi(x.product + ' (' + x.vendor + ')', q) + ' &middot; nodes: ' + esc((x.affectedNodes || []).join(', ') || 'none') + '</div>'; });
    out += grp('ATT&CK TECHNIQUES', mitre, '#00e5ff', function(x) { return '<strong>' + pmHi(x.id, q) + '</strong> ' + pmHi(x.name, q) + '<div class="pm-mono">' + esc(x.tactic) + ' &middot; used by ' + esc((x.usedBy || []).length) + ' actors</div>'; });
    out += grp('INFRA NODES', nodes, '#00ff88', function(x) { return '<strong>' + pmHi(x.id + ' ' + x.name, q) + '</strong><div class="pm-mono">' + pmHi(x.sector, q) + ' &middot; ' + esc(x.type) + ' &middot; ' + pmHi(x.ip, q) + ' &middot; crit ' + esc(x.criticality) + '</div>'; });
    out += grp('SUPPLY CHAIN', sc, '#88ccff', function(x) { return '<strong>' + pmHi(x.id + ' ' + x.name, q) + '</strong> &middot; ' + pmHi(x.vendor, q) + '<div class="pm-mono">risk ' + esc(x.riskScore) + ' &middot; vulns: ' + esc((x.vulns || []).join(', ') || 'none') + '</div>'; });
    return out + '</div>';
  }
  function renderPivot() {
    var q = state.pivotQ || '';
    var html = '<div class="pm-section-header">OMNI-PIVOT :: CROSS-DATASET INDICATOR CORRELATION</div>';
    html += '<div class="pm-mono" style="margin-bottom:10px">Search any indicator, entity, actor, CVE, ATT&amp;CK ID, node, or keyword across all 9 intelligence datasets simultaneously.</div>';
    html += '<div class="pm-filter-bar">';
    html += '<input type="text" class="pm-input" id="pm-pivot-input" placeholder="e.g. APT28, Sandworm, 185.220.101.42, CVE-2024-3400, T1190, PG16, LockBit" value="' + esc(q) + '" style="max-width:560px">';
    html += '<button class="pm-btn" id="pm-pivot-clear">CLEAR</button>';
    html += '</div>';
    html += '<div class="pm-filter-bar"><span class="pm-filter-label">QUICK PIVOTS:</span>';
    var seeds = ['APT28', 'Sandworm', 'Volt Typhoon', 'LockBit', 'Lazarus', 'CVE-2024-3400', 'T1190', 'SCADA', '185.220.101.42', 'PG16'];
    for (var s = 0; s < seeds.length; s++) html += '<button class="pm-filter-btn" data-pivot-seed="' + esc(seeds[s]) + '">' + esc(seeds[s]) + '</button>';
    html += '</div>';
    html += '<div id="pm-pivot-results">' + pmRenderPivotResults(q) + '</div>';
    return html;
  }
  function bindPivot() {
    var input = main.querySelector('#pm-pivot-input');
    var results = main.querySelector('#pm-pivot-results');
    var run = function(v) { state.pivotQ = v; if (results) results.innerHTML = pmRenderPivotResults(v); };
    if (input) {
      input.addEventListener('input', function() { run(this.value); });
      input.focus();
      try { var vlen = input.value.length; input.setSelectionRange(vlen, vlen); } catch (e) {}
    }
    var clr = main.querySelector('#pm-pivot-clear');
    if (clr) clr.addEventListener('click', function() { if (input) input.value = ''; run(''); if (input) input.focus(); });
    var seeds = main.querySelectorAll('[data-pivot-seed]');
    for (var i = 0; i < seeds.length; i++) seeds[i].addEventListener('click', function() {
      var v = this.getAttribute('data-pivot-seed');
      if (input) { input.value = v; input.focus(); }
      run(v);
    });
  }

  // -------- TAB: ATTRIBUTION -------------------------------------------------
  function pmAttrRows() {
    return APT_GROUPS.map(function(g) {
      var camps = pmActorCampaigns(g), iocs = pmActorIOCs(g), ttps = pmActorTTPs(g);
      var victims = camps.reduce(function(a, c) { return a + (c.victims || 0); }, 0);
      var score = Math.min(100, Math.round(g.threatLevel * 7 + camps.length * 8 + iocs.length * 2 + Math.min(30, victims / 3) + (g.active ? 10 : 0)));
      return { g: g, camps: camps, iocs: iocs, ttps: ttps, victims: victims, score: score };
    }).sort(function(a, b) { return b.score - a.score; });
  }
  function renderAttribution() {
    var rows = pmAttrRows();
    var sel = state.attrActor;
    if (!sel || !rows.some(function(r) { return r.g.id === sel; })) sel = rows[0].g.id;
    var nations = {};
    rows.forEach(function(r) { nations[r.g.nation] = 1; });
    var nationList = Object.keys(nations).sort();
    var html = '<div class="pm-section-header">ATTRIBUTION :: ACTOR LINKAGE &amp; TTP-OVERLAP ENGINE</div>';
    html += '<div class="pm-mono" style="margin-bottom:10px">Activity score derived from threat level, linked campaigns, attributed IOCs, victim totals, and operational status. Select an actor for linkage detail.</div>';
    html += '<div class="pm-filter-bar"><span class="pm-filter-label">NATION:</span>';
    html += '<button class="pm-filter-btn active" data-attr-nation="ALL">ALL</button>';
    for (var n = 0; n < nationList.length; n++) html += '<button class="pm-filter-btn" data-attr-nation="' + esc(nationList[n]) + '">' + esc(nationList[n]) + '</button>';
    html += '</div>';
    html += '<div class="pm-table-wrap"><table class="pm-table"><thead><tr><th>#</th><th>ACTOR</th><th>NATION</th><th>THREAT</th><th>CAMPAIGNS</th><th>IOCs</th><th>TTPs</th><th>VICTIMS</th><th>STATUS</th><th>ACTIVITY</th></tr></thead><tbody>';
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      html += '<tr class="pm-clickrow' + (r.g.id === sel ? ' pm-rowsel' : '') + '" data-attr-actor="' + esc(r.g.id) + '" data-nation="' + esc(r.g.nation) + '">';
      html += '<td>' + (i + 1) + '</td>';
      html += '<td><strong>' + esc(r.g.name) + '</strong><div class="pm-mono">' + esc(r.g.id) + '</div></td>';
      html += '<td>' + esc(r.g.nation) + '</td>';
      html += '<td><span class="pm-badge ' + (r.g.threatLevel >= 9 ? 'pm-badge-critical' : r.g.threatLevel >= 7 ? 'pm-badge-high' : 'pm-badge-medium') + '">' + esc(r.g.threatLevel) + '</span></td>';
      html += '<td>' + r.camps.length + '</td><td>' + r.iocs.length + '</td><td>' + r.ttps.length + '</td><td>' + r.victims + '</td>';
      html += '<td>' + (r.g.active ? '<span class="pm-status-green">ACTIVE</span>' : '<span class="pm-status-dim">DORMANT</span>') + '</td>';
      html += '<td>' + pmBar(r.score) + '</td></tr>';
    }
    html += '</tbody></table></div>';
    // Detail panel
    var srow = null;
    for (var j = 0; j < rows.length; j++) if (rows[j].g.id === sel) { srow = rows[j]; break; }
    if (srow) {
      var g = srow.g;
      // closest actors by TTP Jaccard
      var jac = function(a, b) { var sb = {}; b.forEach(function(x) { sb[x] = 1; }); var inter = 0; a.forEach(function(x) { if (sb[x]) inter++; }); var uni = a.length + b.length - inter; return uni ? inter / uni : 0; };
      var near = rows.filter(function(x) { return x.g.id !== g.id; }).map(function(x) {
        var shared = x.ttps.filter(function(t) { return srow.ttps.indexOf(t) !== -1; });
        return { g: x.g, shared: shared, sim: jac(srow.ttps, x.ttps) };
      }).filter(function(x) { return x.shared.length > 0; }).sort(function(a, b) { return b.sim - a.sim; }).slice(0, 6);
      var iocByType = {};
      srow.iocs.forEach(function(x) { iocByType[x.type] = (iocByType[x.type] || 0) + 1; });
      html += '<div class="pm-section-sub">ATTRIBUTION DETAIL :: ' + esc(g.name) + ' (' + esc(g.id) + ')</div>';
      html += '<div class="pm-grid-3">';
      // Campaigns
      html += '<div class="pm-card"><div class="pm-card-title">LINKED CAMPAIGNS (' + srow.camps.length + ')</div>';
      if (srow.camps.length) { for (var c = 0; c < srow.camps.length; c++) { var cp = srow.camps[c]; html += '<div class="pm-hitline"><strong>' + esc(cp.name) + '</strong> <span class="pm-mono">' + esc(cp.status) + '</span><div class="pm-mono">' + esc((cp.sectors || []).join(', ')) + ' &middot; ' + esc(cp.victims) + ' victims</div></div>'; } }
      else html += '<div class="pm-mono">No campaigns linked.</div>';
      html += '</div>';
      // IOCs
      html += '<div class="pm-card"><div class="pm-card-title">ATTRIBUTED IOCs (' + srow.iocs.length + ')</div>';
      var itk = Object.keys(iocByType);
      if (itk.length) { for (var t2 = 0; t2 < itk.length; t2++) html += '<div class="pm-kv"><span class="pm-kv-k">' + esc(itk[t2]) + '</span><span>' + iocByType[itk[t2]] + '</span></div>'; }
      else html += '<div class="pm-mono">No IOCs attributed.</div>';
      html += '</div>';
      // Closest actors
      html += '<div class="pm-card"><div class="pm-card-title">CLOSEST ACTORS (TTP OVERLAP)</div>';
      if (near.length) { for (var m = 0; m < near.length; m++) { var nn = near[m]; html += '<div class="pm-hitline"><strong>' + esc(nn.g.name) + '</strong> <span class="pm-mono">' + esc(nn.g.nation) + '</span><div class="pm-mono">' + nn.shared.length + ' shared TTPs &middot; ' + Math.round(nn.sim * 100) + '% similarity</div></div>'; } }
      else html += '<div class="pm-mono">No overlapping TTPs.</div>';
      html += '</div>';
      html += '</div>';
      // TTP list
      html += '<div class="pm-section-sub">TECHNIQUE PROFILE (' + srow.ttps.length + ' UNIQUE ATT&amp;CK TECHNIQUES)</div>';
      html += '<div style="display:flex;flex-wrap:wrap;gap:4px">';
      for (var tt = 0; tt < srow.ttps.length; tt++) { var nm = pmMitreName(srow.ttps[tt]); html += '<span class="pm-tag" title="' + esc(nm) + '">' + esc(srow.ttps[tt]) + (nm ? ' ' + esc(nm) : '') + '</span>'; }
      html += '</div>';
    }
    return html;
  }
  function bindAttribution() {
    var rows = main.querySelectorAll('[data-attr-actor]');
    for (var i = 0; i < rows.length; i++) rows[i].addEventListener('click', function() {
      state.attrActor = this.getAttribute('data-attr-actor');
      render();
    });
    var nb = main.querySelectorAll('[data-attr-nation]');
    for (var j = 0; j < nb.length; j++) nb[j].addEventListener('click', function() {
      var val = this.getAttribute('data-attr-nation');
      var all = main.querySelectorAll('[data-attr-nation]');
      for (var k = 0; k < all.length; k++) all[k].classList.remove('active');
      this.classList.add('active');
      var trs = main.querySelectorAll('tr[data-nation]');
      for (var t = 0; t < trs.length; t++) trs[t].style.display = (val === 'ALL' || trs[t].getAttribute('data-nation') === val) ? '' : 'none';
    });
  }

  // -------- TAB: EXPOSURE ----------------------------------------------------
  function renderExposure() {
    var data = INFRA_NODES.map(function(n) { return { n: n, e: pmNodeExposure(n) }; });
    var exposedVuln = 0, kevNodes = 0, predNodes = 0, sum = 0;
    data.forEach(function(d) { if (d.e.vulns.length) exposedVuln++; if (d.e.kev > 0) kevNodes++; if (d.e.preds.length) predNodes++; sum += d.e.score; });
    var avg = data.length ? Math.round(sum / data.length) : 0;
    var sectors = {};
    data.forEach(function(d) { sectors[d.n.sector] = 1; });
    var sectorList = Object.keys(sectors).sort();
    data.sort(function(a, b) { return b.e.score - a.e.score; });
    var shown = data.filter(function(d) { return d.e.vulns.length || d.e.preds.length || d.n.criticality >= 8; });
    var cap = shown.slice(0, 80);
    var html = '<div class="pm-section-header">EXPOSURE :: INFRASTRUCTURE ATTACK-SURFACE EXPLORER</div>';
    html += '<div class="pm-mono" style="margin-bottom:10px">Exposure score = criticality&times;4 + KEV&times;12 + exploitable&times;6 + predicted-target&times;10 + dependents&times;2 (capped at 100), computed live over the vulnerability, prediction, and dependency graphs.</div>';
    html += '<div class="pm-stat-row">';
    html += '<div class="pm-stat-box"><div class="pm-stat-value" style="color:#ff6600">' + exposedVuln + '</div><div class="pm-stat-label">NODES WITH VULNS</div></div>';
    html += '<div class="pm-stat-box"><div class="pm-stat-value" style="color:#ff0040">' + kevNodes + '</div><div class="pm-stat-label">KEV-AFFECTED</div></div>';
    html += '<div class="pm-stat-box"><div class="pm-stat-value" style="color:#cc44ff">' + predNodes + '</div><div class="pm-stat-label">PREDICTED TARGETS</div></div>';
    html += '<div class="pm-stat-box"><div class="pm-stat-value" style="color:' + pmSevColor(avg) + '">' + avg + '</div><div class="pm-stat-label">AVG EXPOSURE</div></div>';
    html += '<div class="pm-stat-box"><div class="pm-stat-value" style="color:#00e5ff">' + shown.length + '</div><div class="pm-stat-label">FLAGGED NODES</div></div>';
    html += '</div>';
    html += '<div class="pm-filter-bar">';
    html += '<span class="pm-filter-label">SECTOR:</span><select class="pm-select" id="pm-exp-sector"><option value="ALL">ALL SECTORS</option>';
    for (var s = 0; s < sectorList.length; s++) html += '<option value="' + esc(sectorList[s]) + '">' + esc(sectorList[s]) + '</option>';
    html += '</select>';
    html += '<button class="pm-filter-btn active" data-exp-flag="ALL">ALL</button>';
    html += '<button class="pm-filter-btn" data-exp-flag="KEV">KEV ONLY</button>';
    html += '<button class="pm-filter-btn" data-exp-flag="PRED">PREDICTED ONLY</button>';
    html += '<input type="text" class="pm-input" id="pm-exp-search" placeholder="filter by node id / name" style="max-width:240px">';
    html += '</div>';
    html += '<div class="pm-table-wrap"><table class="pm-table"><thead><tr><th>NODE</th><th>NAME</th><th>SECTOR</th><th>CRIT</th><th>VULNS</th><th>KEV</th><th>EXPL</th><th>MAX CVSS</th><th>PREDICTED</th><th>DEPENDENTS</th><th>EXPOSURE</th></tr></thead><tbody>';
    for (var i = 0; i < cap.length; i++) {
      var d = cap[i], e = d.e;
      html += '<tr class="pm-exp-row" data-sector="' + esc(d.n.sector) + '" data-kev="' + (e.kev > 0 ? '1' : '0') + '" data-pred="' + (e.preds.length ? '1' : '0') + '" data-search="' + esc((d.n.id + ' ' + d.n.name).toLowerCase()) + '">';
      html += '<td><strong>' + esc(d.n.id) + '</strong></td><td>' + esc(d.n.name) + '</td><td>' + esc(d.n.sector) + '</td>';
      html += '<td>' + esc(d.n.criticality) + '</td><td>' + e.vulns.length + '</td>';
      html += '<td>' + (e.kev ? '<span class="pm-status-red">' + e.kev + '</span>' : '0') + '</td>';
      html += '<td>' + e.expl + '</td><td>' + (e.maxCvss || '-') + '</td>';
      html += '<td>' + (e.preds.length ? '<span class="pm-status-yellow">' + e.preds.length + '</span> (' + e.maxConf + '%)' : '-') + '</td>';
      html += '<td>' + e.dependents + '</td><td>' + pmBar(e.score) + '</td></tr>';
    }
    html += '</tbody></table></div>';
    if (shown.length > cap.length) html += '<div class="pm-mono" style="padding-top:8px">Showing top ' + cap.length + ' of ' + shown.length + ' flagged nodes by exposure score.</div>';
    return html;
  }
  function bindExposure() {
    var applyFilters = function() {
      var secEl = main.querySelector('#pm-exp-sector');
      var sec = secEl ? secEl.value : 'ALL';
      var flagBtn = main.querySelector('[data-exp-flag].active');
      var flag = flagBtn ? flagBtn.getAttribute('data-exp-flag') : 'ALL';
      var searchEl = main.querySelector('#pm-exp-search');
      var term = searchEl ? searchEl.value.trim().toLowerCase() : '';
      var rows = main.querySelectorAll('.pm-exp-row');
      for (var i = 0; i < rows.length; i++) {
        var r = rows[i], show = true;
        if (sec !== 'ALL' && r.getAttribute('data-sector') !== sec) show = false;
        if (flag === 'KEV' && r.getAttribute('data-kev') !== '1') show = false;
        if (flag === 'PRED' && r.getAttribute('data-pred') !== '1') show = false;
        if (term && r.getAttribute('data-search').indexOf(term) === -1) show = false;
        r.style.display = show ? '' : 'none';
      }
    };
    var sec = main.querySelector('#pm-exp-sector');
    if (sec) sec.addEventListener('change', applyFilters);
    var srch = main.querySelector('#pm-exp-search');
    if (srch) srch.addEventListener('input', applyFilters);
    var flags = main.querySelectorAll('[data-exp-flag]');
    for (var i = 0; i < flags.length; i++) flags[i].addEventListener('click', function() {
      var all = main.querySelectorAll('[data-exp-flag]');
      for (var k = 0; k < all.length; k++) all[k].classList.remove('active');
      this.classList.add('active');
      applyFilters();
    });
  }

  // -------- TAB: REPORT BUILDER ---------------------------------------------
  function pmBuildReport(opts) {
    var sections = [];
    if (opts.actors) {
      var acts = APT_GROUPS.filter(function(g) { return g.active; }).sort(function(a, b) { return b.threatLevel - a.threatLevel; });
      sections.push({ key: 'actors', title: 'ACTIVE THREAT ACTORS', count: acts.length, rows: acts.map(function(g) { return { id: g.id, label: g.name, detail: g.nation + ' / threat ' + g.threatLevel, severity: g.threatLevel >= 9 ? 'critical' : g.threatLevel >= 7 ? 'high' : 'medium' }; }) });
    }
    if (opts.campaigns) {
      var cs = APT_CAMPAIGNS.filter(function(c) { return c.status === 'active'; }).sort(function(a, b) { return (b.victims || 0) - (a.victims || 0); });
      sections.push({ key: 'campaigns', title: 'ACTIVE CAMPAIGNS', count: cs.length, rows: cs.map(function(c) { return { id: c.id, label: c.name, detail: c.apt + ' / ' + c.victims + ' victims / ' + (c.sectors || []).join(', '), severity: c.victims >= 40 ? 'critical' : c.victims >= 15 ? 'high' : 'medium' }; }) });
    }
    if (opts.predictions) {
      var ps = THREAT_PREDICTIONS.filter(function(p) { return p.status === 'active'; }).sort(function(a, b) { return b.confidence - a.confidence; });
      sections.push({ key: 'predictions', title: 'ACTIVE PREDICTIONS', count: ps.length, rows: ps.map(function(p) { return { id: p.id, label: p.threat, detail: p.confidence + '% / ' + p.horizon + ' / targets ' + (p.targets || []).join(', '), severity: p.confidence >= 80 ? 'critical' : p.confidence >= 60 ? 'high' : 'medium' }; }) });
    }
    if (opts.iocs) {
      var hi = (IOC_DATABASE || []).filter(function(x) { return x.confidence === 'high'; });
      sections.push({ key: 'iocs', title: 'HIGH-CONFIDENCE IOCs', count: hi.length, rows: hi.map(function(x) { return { id: x.type, label: x.value, detail: x.threat + ' / ' + (x.tags || []).join(', '), severity: 'high' }; }) });
    }
    if (opts.vulns) {
      var kv = VULN_DATABASE.filter(function(v) { return v.kev; }).sort(function(a, b) { return b.cvss - a.cvss; });
      sections.push({ key: 'vulns', title: 'KEV VULNERABILITIES', count: kv.length, rows: kv.map(function(v) { return { id: v.cve, label: v.product + ' (' + v.vendor + ')', detail: 'CVSS ' + v.cvss + ' / ' + v.type + ' / nodes ' + ((v.affectedNodes || []).join(', ') || 'none'), severity: v.cvss >= 9 ? 'critical' : 'high' }; }) });
    }
    if (opts.exposure) {
      var ex = INFRA_NODES.map(function(n) { return { n: n, e: pmNodeExposure(n) }; }).sort(function(a, b) { return b.e.score - a.e.score; }).slice(0, 15);
      sections.push({ key: 'exposure', title: 'TOP EXPOSED NODES', count: ex.length, rows: ex.map(function(d) { return { id: d.n.id, label: d.n.name, detail: d.n.sector + ' / exposure ' + d.e.score + ' / ' + d.e.vulns.length + ' vulns', severity: d.e.score >= 75 ? 'critical' : d.e.score >= 50 ? 'high' : 'medium' }; }) });
    }
    return { meta: { title: opts.title, classification: opts.classification, generated: new Date().toISOString() }, sections: sections };
  }
  function pmReportPreview(rep) {
    var L = [];
    L.push(rep.meta.classification);
    L.push('=========================================================');
    L.push('INTELLIGENCE PRODUCT :: ' + rep.meta.title);
    L.push('GENERATED: ' + rep.meta.generated);
    L.push('SYSTEM: PROMETHEUS (TRAINING ENVIRONMENT)');
    L.push('=========================================================');
    L.push('');
    if (!rep.sections.length) { L.push('No sections selected. Choose at least one section to include.'); }
    for (var i = 0; i < rep.sections.length; i++) {
      var s = rep.sections[i];
      L.push('[' + (i + 1) + '] ' + s.title + ' (' + s.count + ')');
      L.push('---------------------------------------------------------');
      var cap = s.rows.slice(0, 20);
      for (var j = 0; j < cap.length; j++) L.push('  ' + s.rows[j].id + '  ' + s.rows[j].label + '  ::  ' + s.rows[j].detail);
      if (s.rows.length > cap.length) L.push('  ... +' + (s.rows.length - cap.length) + ' more');
      L.push('');
    }
    L.push('=========================================================');
    L.push(rep.meta.classification + ' // TRAINING ENVIRONMENT');
    return L.join('\n');
  }
  function pmReadReportOpts() {
    var titleEl = main.querySelector('#pm-rep-title');
    var classEl = main.querySelector('#pm-rep-class');
    var opts = { title: titleEl && titleEl.value ? titleEl.value : 'THREAT INTELLIGENCE SUMMARY', classification: classEl ? classEl.value : 'UNCLASSIFIED' };
    var boxes = main.querySelectorAll('[data-rep-sec]');
    for (var i = 0; i < boxes.length; i++) opts[boxes[i].getAttribute('data-rep-sec')] = boxes[i].checked;
    return opts;
  }
  function renderReport() {
    var secs = [['actors', 'Active Threat Actors'], ['campaigns', 'Active Campaigns'], ['predictions', 'Active Predictions'], ['iocs', 'High-Confidence IOCs'], ['vulns', 'KEV Vulnerabilities'], ['exposure', 'Top Exposed Nodes']];
    var html = '<div class="pm-section-header">REPORT BUILDER :: INTELLIGENCE PRODUCT &amp; EXPORT</div>';
    html += '<div class="pm-mono" style="margin-bottom:10px">Assemble a formatted intelligence product from live dataset aggregates and export it as JSON or CSV (client-side, no network).</div>';
    html += '<div class="pm-grid-2">';
    html += '<div class="pm-card"><div class="pm-card-title">REPORT PARAMETERS</div>';
    html += '<div class="pm-form-group"><div class="pm-label">TITLE</div><input type="text" class="pm-input" id="pm-rep-title" value="THREAT INTELLIGENCE SUMMARY"></div>';
    html += '<div class="pm-form-group"><div class="pm-label">CLASSIFICATION</div><select class="pm-select" id="pm-rep-class"><option>UNCLASSIFIED</option><option>CONFIDENTIAL</option><option>SECRET</option><option selected>TOP SECRET // SCI</option></select></div>';
    html += '<div class="pm-label">SECTIONS</div><div class="pm-checkbox-group">';
    for (var i = 0; i < secs.length; i++) html += '<label class="pm-checkbox-label"><input type="checkbox" data-rep-sec="' + secs[i][0] + '" checked> ' + esc(secs[i][1]) + '</label>';
    html += '</div>';
    html += '<div class="pm-filter-bar" style="margin-top:12px"><button class="pm-btn" id="pm-rep-gen">GENERATE PREVIEW</button><button class="pm-btn pm-btn-blue" id="pm-rep-json">DOWNLOAD JSON</button><button class="pm-btn pm-btn-warn" id="pm-rep-csv">DOWNLOAD CSV</button></div>';
    html += '<div class="pm-mono" id="pm-rep-status" style="margin-top:6px"></div>';
    html += '</div>';
    html += '<div class="pm-card"><div class="pm-card-title">PRODUCT PREVIEW</div>';
    var initial = pmReportPreview(pmBuildReport({ title: 'THREAT INTELLIGENCE SUMMARY', classification: 'TOP SECRET // SCI', actors: true, campaigns: true, predictions: true, iocs: true, vulns: true, exposure: true }));
    html += '<pre id="pm-rep-preview" style="white-space:pre-wrap;word-break:break-word;font-family:monospace;font-size:11px;line-height:1.5;max-height:520px;overflow:auto;margin:0">' + esc(initial) + '</pre>';
    html += '</div>';
    html += '</div>';
    return html;
  }
  function bindReport() {
    var refresh = function() {
      var rep = pmBuildReport(pmReadReportOpts());
      var pv = main.querySelector('#pm-rep-preview');
      if (pv) pv.textContent = pmReportPreview(rep);
      return rep;
    };
    var gen = main.querySelector('#pm-rep-gen');
    if (gen) gen.addEventListener('click', function() {
      var rep = refresh();
      var st = main.querySelector('#pm-rep-status');
      var total = rep.sections.reduce(function(a, s) { return a + s.count; }, 0);
      if (st) st.textContent = 'Preview generated: ' + rep.sections.length + ' sections, ' + total + ' records.';
    });
    var boxes = main.querySelectorAll('[data-rep-sec]');
    for (var i = 0; i < boxes.length; i++) boxes[i].addEventListener('change', refresh);
    var titleEl = main.querySelector('#pm-rep-title');
    if (titleEl) titleEl.addEventListener('input', refresh);
    var classEl = main.querySelector('#pm-rep-class');
    if (classEl) classEl.addEventListener('change', refresh);
    var jbtn = main.querySelector('#pm-rep-json');
    if (jbtn) jbtn.addEventListener('click', function() {
      var rep = pmBuildReport(pmReadReportOpts());
      pmDownload('prometheus-intel-report.json', 'application/json', JSON.stringify(rep, null, 2));
      var st = main.querySelector('#pm-rep-status'); if (st) st.textContent = 'JSON export downloaded.';
    });
    var cbtn = main.querySelector('#pm-rep-csv');
    if (cbtn) cbtn.addEventListener('click', function() {
      var rep = pmBuildReport(pmReadReportOpts());
      var rows = [];
      rep.sections.forEach(function(s) { s.rows.forEach(function(r) { rows.push([s.title, r.id, r.label, r.detail, r.severity]); }); });
      pmDownload('prometheus-intel-report.csv', 'text/csv', pmCSV(['section', 'id', 'label', 'detail', 'severity'], rows));
      var st = main.querySelector('#pm-rep-status'); if (st) st.textContent = 'CSV export downloaded (' + rows.length + ' records).';
    });
  }

  function render() {
    state.intervals.forEach(function(id) { clearInterval(id); });
    state.intervals = [];
    _pmIntervals = state.intervals;

    var tabsHtml = '';
    for (var i = 0; i < PM_TABS.length; i++) {
      var t = PM_TABS[i];
      tabsHtml += '<button class="pm-tab' + (state.activeTab === t.id ? ' active' : '') + '" data-tab="' + t.id + '">' + t.label + '</button>';
    }

    var contentHtml = '';
    switch (state.activeTab) {
      case 'command': contentHtml = renderCommandCenter(); break;
      case 'twin': contentHtml = renderDigitalTwin(); break;
      case 'terrain': contentHtml = renderCyberTerrain(); break;
      case 'sigint': contentHtml = renderSigint(); break;
      case 'predict': contentHtml = renderPredict(); break;
      case 'engage': contentHtml = renderEngage(); break;
      case 'wargame': contentHtml = renderWargame(); break;
      case 'cascade': contentHtml = renderCascade(); break;
      case 'counterintel': contentHtml = renderCounterIntel(); break;
      case 'supplychain': contentHtml = renderSupplyChain(); break;
      case 'defense': contentHtml = renderDefense(); break;
      case 'bda': contentHtml = renderBDA(); break;
      case 'authority': contentHtml = renderAuthority(); break;
      case 'pivot': contentHtml = renderPivot(); break;
      case 'attribution': contentHtml = renderAttribution(); break;
      case 'exposure': contentHtml = renderExposure(); break;
      case 'report': contentHtml = renderReport(); break;
    }

    main.innerHTML = PM_CSS +
      '<div class="pm-wrap">' +
      '<div class="pm-classification-banner">TOP SECRET // SCI // NOFORN // PROMETHEUS</div>' +
      '<div class="pm-header">' +
      '<div class="pm-scanline"></div>' +
      '<div class="pm-header-content">' +
      '<h1 class="pm-title">PROMETHEUS</h1>' +
      '<div class="pm-subtitle">PREDICTIVE REAL-TIME OMNISCIENT MONITORING, EMULATION, THREAT HUNTING &amp; ENGAGEMENT UNIFIED SYSTEM (TRAINING ENVIRONMENT)</div>' +
      '<div class="pm-header-meta">' +
      '<span class="pm-version">v4.7.2</span>' +
      '<span class="pm-operator">OPERATOR: ' + esc(state.operator || 'CLASSIFIED') + '</span>' +
      '<span class="pm-session">SESSION: ' + esc(state.sessionId || 'ACTIVE') + '</span>' +
      '</div>' +
      '</div>' +
      '</div>' +
      '<div class="pm-tabs">' + tabsHtml + '</div>' +
      '<div class="pm-content">' + contentHtml + '</div>' +
      '<div class="pm-footer">' +
      '<span>CLASSIFICATION: TOP SECRET // SCI</span>' +
      '<span>TRAINING ENVIRONMENT</span>' +
      '<span>UPTIME: ' + esc(getUptime()) + '</span>' +
      '</div>' +
      '</div>';

    // Bind tab click events
    var tabBtns = main.querySelectorAll('.pm-tab');
    for (var i = 0; i < tabBtns.length; i++) {
      tabBtns[i].addEventListener('click', function() {
        state.activeTab = this.getAttribute('data-tab');
        saveState();
        render();
      });
    }

    // Bind active tab events
    switch (state.activeTab) {
      case 'command': bindCommandCenter(); break;
      case 'twin': bindDigitalTwin(); break;
      case 'terrain': bindCyberTerrain(); break;
      case 'sigint': bindSigint(); break;
      case 'predict': bindPredict(); break;
      case 'engage': bindEngage(); break;
      case 'wargame': bindWargame(); break;
      case 'cascade': bindCascade(); break;
      case 'counterintel': bindCounterIntel(); break;
      case 'supplychain': bindSupplyChain(); break;
      case 'defense': bindDefense(); break;
      case 'bda': bindBDA(); break;
      case 'authority': bindAuthority(); break;
      case 'pivot': bindPivot(); break;
      case 'attribution': bindAttribution(); break;
      case 'exposure': bindExposure(); break;
      case 'report': bindReport(); break;
    }
  }

  // ===========================================================================
  // INITIALIZE
  // ===========================================================================

  loadState();
  if (!state.sessionId) {
    state.sessionId = generateId();
  }
  state.startTime = Date.now();
  // render() moved to after PM_CSS_EXT is defined to avoid undefined

// PROMETHEUS Extended Module — Additional data, analysis engines, and expanded tab features
// This section adds depth to every tab with additional intelligence, analysis, and visualization

// NOTE: This extended section appends to the main renderPrometheus function above.
// It is concatenated at build time. The functions below are standalone utilities
// called from the tab renderers above but defined here for code organization.

// ============================================================================
// EXTENDED APT CAMPAIGN DATA
// ============================================================================
var APT_CAMPAIGNS = [
  {id:'CAMP01',apt:'APT01',name:'Operation Fancy Storm',startDate:'2026-07-15',endDate:null,targets:['government','military'],ttps:['T1566.001','T1059.001','T1071.001','T1027','T1070.004'],tools:['X-Agent','X-Tunnel','Seduploader','Zebrocy'],infrastructure:['185.220.101.0/24','91.219.237.0/24'],status:'active',victims:12,sectors:['GOVERNMENT','TELECOM'],description:'Sustained intelligence collection operation targeting NATO government networks via spearphishing with weaponized documents'},
  {id:'CAMP02',apt:'APT02',name:'Midnight Cascade',startDate:'2026-06-01',endDate:null,targets:['technology','government'],ttps:['T1195.002','T1078.004','T1098.001','T1550.001','T1087.004'],tools:['EnvyScout','FoggyWeb','MagicWeb','NativeZone'],infrastructure:['Compromised Azure tenants','Legitimate cloud services'],status:'active',victims:8,sectors:['GOVERNMENT','HEALTHCARE'],description:'Supply chain compromise leveraging trusted cloud provider relationships to gain access to government cloud environments'},
  {id:'CAMP03',apt:'APT03',name:'BlackEnergy Resurgence',startDate:'2026-08-01',endDate:null,targets:['energy','government'],ttps:['T1190','T1059.003','T1485','T1561.002','T1529'],tools:['Industroyer2','CaddyWiper','ArguePatch','AcidRain'],infrastructure:['TOR infrastructure','Compromised SOHO routers'],status:'active',victims:5,sectors:['POWER_GRID','ENERGY'],description:'Destructive cyber operation targeting European energy infrastructure SCADA systems with wiper malware variants'},
  {id:'CAMP04',apt:'APT06',name:'Dragon Bridge',startDate:'2026-05-15',endDate:null,targets:['technology','healthcare','telecom'],ttps:['T1195.001','T1190','T1059.001','T1055.012','T1078.001'],tools:['ShadowPad','Winnti','PlugX','ChaCha20 Backdoor'],infrastructure:['Rented VPS in Southeast Asia','Compromised university networks'],status:'active',victims:23,sectors:['HEALTHCARE','TELECOM'],description:'Multi-sector espionage campaign exploiting software supply chain and N-day vulnerabilities for data theft'},
  {id:'CAMP05',apt:'APT11',name:'Typhoon Season',startDate:'2026-01-01',endDate:null,targets:['critical_infrastructure','telecom','government'],ttps:['T1190','T1078.001','T1059.001','T1003.003','T1562.001'],tools:['Living-off-the-land binaries','Custom webshells','SOHO router implants'],infrastructure:['Botnet of 2000+ compromised routers','Legitimate cloud services'],status:'active',victims:50,sectors:['TELECOM','GOVERNMENT','ENERGY','WATER'],description:'Strategic pre-positioning campaign maintaining persistent access across US critical infrastructure for potential destructive use during conflict'},
  {id:'CAMP06',apt:'APT12',name:'Silent Intercept',startDate:'2026-03-01',endDate:null,targets:['telecom','isp'],ttps:['T1190','T1059.001','T1078.001','T1056.001','T1005'],tools:['GhostEmperor rootkit','Custom UEFI implants','Demodex'],infrastructure:['Compromised telecom switches','Cloud infrastructure in neutral countries'],status:'active',victims:15,sectors:['TELECOM'],description:'Deep access campaign targeting telecom provider infrastructure to intercept communications including lawful intercept systems'},
  {id:'CAMP07',apt:'APT13',name:'Crypto Harvest 2026',startDate:'2026-02-01',endDate:null,targets:['financial','cryptocurrency'],ttps:['T1566.002','T1059.007','T1195.002','T1486','T1565.001'],tools:['TraderTraitor','AppleJeus','COPPERHEDGE','Custom DeFi exploits'],infrastructure:['Domains mimicking crypto services','Tor-hosted mixing services'],status:'active',victims:35,sectors:['FINANCIAL'],description:'Sustained cryptocurrency theft operation targeting exchanges, DeFi protocols, and individual high-value wallet holders, funding weapons programs'},
  {id:'CAMP08',apt:'APT17',name:'Persian Gateway',startDate:'2026-04-01',endDate:null,targets:['government','military','media'],ttps:['T1566.001','T1078.004','T1059.001','T1056.001','T1071.001'],tools:['CharmPower','HYPERSCRAPE','PHOSPHORUS backdoor','MediaPl'],infrastructure:['Iranian hosting providers','Compromised WordPress sites'],status:'active',victims:18,sectors:['GOVERNMENT'],description:'Intelligence collection targeting government officials and military personnel through social engineering and credential harvesting'},
  {id:'CAMP09',apt:'APT19',name:'Oil Slick',startDate:'2026-06-15',endDate:null,targets:['energy','financial','telecom'],ttps:['T1190','T1566.001','T1059.005','T1071.001','T1003.003'],tools:['POWBAT','BONDUPDATER','Glimpse','SideTwist'],infrastructure:['DNS tunneling infrastructure','Compromised websites in Middle East'],status:'active',victims:11,sectors:['ENERGY','FINANCIAL'],description:'Espionage campaign targeting energy and financial sectors in Gulf states for strategic intelligence and potential pre-positioning'},
  {id:'CAMP10',apt:'APT20',name:'Aqua Blade',startDate:'2026-08-10',endDate:null,targets:['water','critical_infrastructure'],ttps:['T1190','T1059.001','T1485','T1529'],tools:['IRGC custom PLC malware','Modified CyberAv3ngers tools'],infrastructure:['Iranian IP space','Compromised IoT devices'],status:'active',victims:3,sectors:['WATER'],description:'Destructive campaign targeting water treatment facilities using Unitronics PLC exploitation'},
  {id:'CAMP11',apt:'APT24',name:'Carbon Spider Web',startDate:'2026-01-15',endDate:null,targets:['financial','retail','hospitality'],ttps:['T1566.001','T1059.007','T1055.001','T1071.001','T1560.001'],tools:['LOADOUT','GRIFFON','BOOSTWRITE','BadUSB implants'],infrastructure:['Bulletproof hosting','Fast-flux DNS'],status:'active',victims:42,sectors:['FINANCIAL'],description:'Financially motivated campaign targeting point-of-sale systems and financial institutions through sophisticated social engineering'},
  {id:'CAMP12',apt:'APT26',name:'Octopus Arms',startDate:'2026-07-01',endDate:null,targets:['telecom','technology','financial'],ttps:['T1566.002','T1078.004','T1621','T1059.001','T1136.003'],tools:['Social engineering toolkit','SIM swapping infrastructure','Custom phishing frameworks'],infrastructure:['Disposable VoIP numbers','Rotating residential proxies'],status:'active',victims:28,sectors:['TELECOM','FINANCIAL'],description:'Young threat actors using advanced social engineering against telecom help desks for SIM swapping and credential theft'},
  {id:'CAMP13',apt:'APT27',name:'Lock and Key 4.0',startDate:'2026-03-01',endDate:null,targets:['healthcare','manufacturing','government'],ttps:['T1190','T1059.001','T1486','T1490','T1071.001'],tools:['LockBit 4.0 ransomware','StealBit','Custom exploitation tools'],infrastructure:['Tor-hosted leak sites','Cryptocurrency wallets'],status:'active',victims:156,sectors:['HEALTHCARE','GOVERNMENT'],description:'Ransomware-as-a-Service operation with affiliate model targeting critical infrastructure and healthcare for maximum impact and payment likelihood'},
  {id:'CAMP14',apt:'APT03',name:'AcidRain 2.0',startDate:'2026-09-01',endDate:null,targets:['satellite','telecom','military'],ttps:['T1190','T1059.001','T1561.002','T1529'],tools:['AcidRain 2.0','AcidPour','Custom satellite firmware exploits'],infrastructure:['Compromised IoT botnets','Bulletproof hosting'],status:'active',victims:2,sectors:['TELECOM','GOVERNMENT'],description:'Destructive operation targeting satellite communication terminals and ground stations to disrupt military and civilian communications'},
  {id:'CAMP15',apt:'APT05',name:'Primitive Harvest',startDate:'2026-08-15',endDate:null,targets:['government','military','law_enforcement'],ttps:['T1566.001','T1059.005','T1547.001','T1071.001','T1082'],tools:['Pteranodon','GammaLoad','GammaSteel','EvilGnome'],infrastructure:['Dynamic DNS services','Free hosting providers'],status:'active',victims:45,sectors:['GOVERNMENT'],description:'High-volume but lower sophistication phishing campaign maintaining persistent access to Ukrainian government and military networks'}
];

// ============================================================================
// EXTENDED INCIDENT RESPONSE PLAYBOOKS
// ============================================================================
var IR_PLAYBOOKS = [
  {id:'PB01',name:'RANSOMWARE RESPONSE',category:'destructive',severity:'critical',steps:[
    {order:1,action:'Isolate affected systems from network',duration:'5 min',automated:true,tool:'EDR/Firewall'},
    {order:2,action:'Identify ransomware variant and encryption method',duration:'15 min',automated:false,tool:'Malware Analysis'},
    {order:3,action:'Check for backup integrity and availability',duration:'30 min',automated:false,tool:'Backup System'},
    {order:4,action:'Collect forensic evidence from infected systems',duration:'1 hour',automated:true,tool:'DFIR Toolkit'},
    {order:5,action:'Assess scope of encryption and data impact',duration:'2 hours',automated:false,tool:'EDR/SIEM'},
    {order:6,action:'Engage legal counsel and consider notification requirements',duration:'1 hour',automated:false,tool:'Legal'},
    {order:7,action:'Restore systems from clean backups',duration:'4-24 hours',automated:false,tool:'Recovery'},
    {order:8,action:'Conduct root cause analysis and remediate initial access',duration:'2-4 hours',automated:false,tool:'Threat Hunt'}
  ]},
  {id:'PB02',name:'CREDENTIAL COMPROMISE',category:'access',severity:'high',steps:[
    {order:1,action:'Disable compromised accounts immediately',duration:'2 min',automated:true,tool:'IAM/AD'},
    {order:2,action:'Revoke all active sessions and tokens',duration:'5 min',automated:true,tool:'IAM'},
    {order:3,action:'Review authentication logs for unauthorized access',duration:'30 min',automated:true,tool:'SIEM'},
    {order:4,action:'Check for persistence mechanisms (scheduled tasks, services)',duration:'1 hour',automated:true,tool:'EDR'},
    {order:5,action:'Force password reset for affected and related accounts',duration:'30 min',automated:true,tool:'IAM'},
    {order:6,action:'Review lateral movement from compromised credentials',duration:'2 hours',automated:false,tool:'SIEM/EDR'}
  ]},
  {id:'PB03',name:'LATERAL MOVEMENT CONTAINMENT',category:'spread',severity:'critical',steps:[
    {order:1,action:'Identify all systems accessed by adversary',duration:'30 min',automated:true,tool:'EDR/SIEM'},
    {order:2,action:'Isolate affected network segments',duration:'10 min',automated:true,tool:'Firewall/SDN'},
    {order:3,action:'Block identified adversary indicators at perimeter',duration:'5 min',automated:true,tool:'Firewall/IPS'},
    {order:4,action:'Deploy additional monitoring on adjacent segments',duration:'15 min',automated:true,tool:'EDR'},
    {order:5,action:'Hunt for additional compromised systems',duration:'2-4 hours',automated:false,tool:'Threat Hunt'},
    {order:6,action:'Validate containment effectiveness',duration:'1 hour',automated:false,tool:'SIEM'}
  ]},
  {id:'PB04',name:'DATA EXFILTRATION RESPONSE',category:'theft',severity:'critical',steps:[
    {order:1,action:'Identify and block exfiltration channels',duration:'10 min',automated:true,tool:'DLP/Firewall'},
    {order:2,action:'Capture network traffic for forensic analysis',duration:'5 min',automated:true,tool:'PCAP'},
    {order:3,action:'Assess volume and sensitivity of exfiltrated data',duration:'2 hours',automated:false,tool:'DLP/SIEM'},
    {order:4,action:'Identify destination of stolen data',duration:'1 hour',automated:false,tool:'Network Forensics'},
    {order:5,action:'Engage legal for breach notification assessment',duration:'1 hour',automated:false,tool:'Legal'},
    {order:6,action:'Initiate credential rotation for exposed secrets',duration:'2 hours',automated:true,tool:'IAM'},
    {order:7,action:'Deploy enhanced DLP monitoring',duration:'30 min',automated:true,tool:'DLP'}
  ]},
  {id:'PB05',name:'SCADA INCIDENT RESPONSE',category:'ics',severity:'critical',steps:[
    {order:1,action:'Verify physical safety of controlled processes',duration:'5 min',automated:false,tool:'OT Operators'},
    {order:2,action:'Switch to manual control if safety is compromised',duration:'10 min',automated:false,tool:'Physical'},
    {order:3,action:'Isolate IT/OT boundary connections',duration:'5 min',automated:true,tool:'Firewall'},
    {order:4,action:'Identify compromised PLCs/RTUs/HMIs',duration:'1 hour',automated:false,tool:'ICS Security'},
    {order:5,action:'Capture forensic images of affected ICS devices',duration:'2 hours',automated:false,tool:'ICS Forensics'},
    {order:6,action:'Restore ICS firmware from known-good images',duration:'4-8 hours',automated:false,tool:'ICS Recovery'},
    {order:7,action:'Validate safe operation before returning to automated control',duration:'2 hours',automated:false,tool:'OT Operators'},
    {order:8,action:'Deploy enhanced OT monitoring',duration:'1 hour',automated:true,tool:'ICS Security'},
    {order:9,action:'Notify CISA ICS-CERT and sector ISAC',duration:'30 min',automated:false,tool:'Comms'}
  ]},
  {id:'PB06',name:'INSIDER THREAT INVESTIGATION',category:'insider',severity:'high',steps:[
    {order:1,action:'Preserve evidence without alerting subject',duration:'immediate',automated:false,tool:'Legal/HR'},
    {order:2,action:'Enable enhanced monitoring on subject accounts',duration:'15 min',automated:true,tool:'UEBA/DLP'},
    {order:3,action:'Review access logs and data access patterns',duration:'2 hours',automated:true,tool:'SIEM'},
    {order:4,action:'Check for data staging and exfiltration indicators',duration:'1 hour',automated:true,tool:'DLP'},
    {order:5,action:'Coordinate with legal, HR, and counterintelligence',duration:'ongoing',automated:false,tool:'CI'}
  ]},
  {id:'PB07',name:'SUPPLY CHAIN COMPROMISE',category:'supply',severity:'critical',steps:[
    {order:1,action:'Identify affected software version and deployment scope',duration:'30 min',automated:true,tool:'Asset Inventory'},
    {order:2,action:'Isolate systems running compromised software',duration:'15 min',automated:true,tool:'EDR/Firewall'},
    {order:3,action:'Analyze malicious payload and IOCs',duration:'2 hours',automated:false,tool:'Malware Analysis'},
    {order:4,action:'Hunt for post-compromise activity',duration:'4 hours',automated:false,tool:'Threat Hunt'},
    {order:5,action:'Deploy emergency patch or rollback to safe version',duration:'2-8 hours',automated:true,tool:'Patch Management'},
    {order:6,action:'Notify vendor and coordinate disclosure',duration:'1 hour',automated:false,tool:'Comms'},
    {order:7,action:'Review build pipeline integrity',duration:'4 hours',automated:false,tool:'DevSecOps'}
  ]},
  {id:'PB08',name:'DDOS MITIGATION',category:'availability',severity:'high',steps:[
    {order:1,action:'Activate DDoS mitigation service',duration:'2 min',automated:true,tool:'DDoS Protection'},
    {order:2,action:'Identify attack vector and traffic patterns',duration:'10 min',automated:true,tool:'Network Monitoring'},
    {order:3,action:'Deploy traffic filtering and rate limiting',duration:'5 min',automated:true,tool:'Firewall/WAF'},
    {order:4,action:'Scale infrastructure to absorb remaining traffic',duration:'15 min',automated:true,tool:'Cloud/CDN'},
    {order:5,action:'Monitor for secondary attack vector',duration:'ongoing',automated:true,tool:'SIEM'},
    {order:6,action:'Conduct post-attack analysis and improve defenses',duration:'2 hours',automated:false,tool:'SOC'}
  ]}
];

// ============================================================================
// EXTENDED VULNERABILITY DATABASE
// ============================================================================
var VULN_DATABASE = [
  {cve:'CVE-2024-3400',product:'PAN-OS',vendor:'Palo Alto',cvss:10.0,type:'Command Injection',exploitAvailable:true,kev:true,affectedVersions:'10.2, 11.0, 11.1',patchAvailable:true,datePublished:'2024-04-12',affectedNodes:['TC08','TC09']},
  {cve:'CVE-2024-21762',product:'FortiOS',vendor:'Fortinet',cvss:9.8,type:'Out-of-bounds Write',exploitAvailable:true,kev:true,affectedVersions:'6.x, 7.0-7.4',patchAvailable:true,datePublished:'2024-02-08',affectedNodes:['TC08','TC09']},
  {cve:'CVE-2024-6387',product:'OpenSSH',vendor:'OpenBSD',cvss:8.1,type:'Race Condition RCE',exploitAvailable:true,kev:true,affectedVersions:'8.5p1-9.7p1',patchAvailable:true,datePublished:'2024-07-01',affectedNodes:['GV03','GV19']},
  {cve:'CVE-2024-38063',product:'Windows TCP/IP',vendor:'Microsoft',cvss:9.8,type:'Remote Code Execution',exploitAvailable:true,kev:true,affectedVersions:'Windows 10/11, Server 2016-2025',patchAvailable:true,datePublished:'2024-08-13',affectedNodes:['FN07','FN08','GV03']},
  {cve:'CVE-2024-47575',product:'FortiManager',vendor:'Fortinet',cvss:9.8,type:'Missing Authentication',exploitAvailable:true,kev:true,affectedVersions:'6.2-7.6',patchAvailable:true,datePublished:'2024-10-23',affectedNodes:[]},
  {cve:'CVE-2024-24919',product:'Quantum Gateway',vendor:'Check Point',cvss:8.6,type:'Information Disclosure',exploitAvailable:true,kev:true,affectedVersions:'R80.20-R81.20',patchAvailable:true,datePublished:'2024-05-28',affectedNodes:[]},
  {cve:'CVE-2024-21887',product:'Connect Secure',vendor:'Ivanti',cvss:9.1,type:'Command Injection',exploitAvailable:true,kev:true,affectedVersions:'9.x, 22.x',patchAvailable:true,datePublished:'2024-01-10',affectedNodes:['GV03']},
  {cve:'CVE-2024-23113',product:'FortiOS',vendor:'Fortinet',cvss:9.8,type:'Format String Bug',exploitAvailable:true,kev:true,affectedVersions:'7.0-7.4',patchAvailable:true,datePublished:'2024-02-08',affectedNodes:[]},
  {cve:'CVE-2024-1086',product:'Linux Kernel',vendor:'Linux',cvss:7.8,type:'Use After Free',exploitAvailable:true,kev:true,affectedVersions:'5.14-6.6',patchAvailable:true,datePublished:'2024-01-31',affectedNodes:['GV19','TC14']},
  {cve:'CVE-2024-37085',product:'ESXi',vendor:'VMware',cvss:6.8,type:'Auth Bypass',exploitAvailable:true,kev:true,affectedVersions:'7.0, 8.0',patchAvailable:true,datePublished:'2024-06-25',affectedNodes:[]},
  {cve:'CVE-2023-20198',product:'IOS XE',vendor:'Cisco',cvss:10.0,type:'Privilege Escalation',exploitAvailable:true,kev:true,affectedVersions:'16.x, 17.x',patchAvailable:true,datePublished:'2023-10-16',affectedNodes:['TC08']},
  {cve:'CVE-2023-4966',product:'NetScaler ADC',vendor:'Citrix',cvss:9.4,type:'Buffer Overflow',exploitAvailable:true,kev:true,affectedVersions:'13.1, 14.1',patchAvailable:true,datePublished:'2023-10-10',affectedNodes:[]},
  {cve:'CVE-2024-8933',product:'Modicon M340',vendor:'Schneider Electric',cvss:9.1,type:'Auth Bypass',exploitAvailable:false,kev:false,affectedVersions:'3.x',patchAvailable:true,datePublished:'2024-11-12',affectedNodes:['WT11','EN19']},
  {cve:'CVE-2024-35303',product:'S7-1500',vendor:'Siemens',cvss:8.8,type:'Buffer Overflow',exploitAvailable:false,kev:false,affectedVersions:'4.x',patchAvailable:true,datePublished:'2024-06-11',affectedNodes:['PG16','PG17']},
  {cve:'CVE-2024-43044',product:'Jenkins',vendor:'Jenkins',cvss:9.8,type:'Arbitrary File Read',exploitAvailable:true,kev:true,affectedVersions:'2.x',patchAvailable:true,datePublished:'2024-08-07',affectedNodes:[]},
  {cve:'CVE-2024-34351',product:'Next.js',vendor:'Vercel',cvss:7.5,type:'SSRF',exploitAvailable:true,kev:false,affectedVersions:'13.x, 14.x',patchAvailable:true,datePublished:'2024-05-09',affectedNodes:[]},
  {cve:'CVE-2024-6385',product:'GitLab',vendor:'GitLab',cvss:9.6,type:'Pipeline Execution',exploitAvailable:true,kev:false,affectedVersions:'15.x-17.x',patchAvailable:true,datePublished:'2024-07-10',affectedNodes:[]},
  {cve:'CVE-2024-38809',product:'Spring Framework',vendor:'VMware',cvss:7.5,type:'DoS via Multipart',exploitAvailable:false,kev:false,affectedVersions:'5.3, 6.0, 6.1',patchAvailable:true,datePublished:'2024-08-20',affectedNodes:[]},
  {cve:'CVE-2024-21060',product:'MySQL',vendor:'Oracle',cvss:6.5,type:'DoS',exploitAvailable:false,kev:false,affectedVersions:'8.0, 8.3',patchAvailable:true,datePublished:'2024-04-16',affectedNodes:[]},
  {cve:'CVE-2024-37334',product:'SQL Server',vendor:'Microsoft',cvss:8.8,type:'Remote Code Execution',exploitAvailable:false,kev:false,affectedVersions:'2019, 2022',patchAvailable:true,datePublished:'2024-07-09',affectedNodes:['FN07']},
  {cve:'CVE-2024-25062',product:'libxml2',vendor:'GNOME',cvss:7.5,type:'Use After Free',exploitAvailable:true,kev:false,affectedVersions:'2.x',patchAvailable:true,datePublished:'2024-02-04',affectedNodes:[]},
  {cve:'CVE-2023-40289',product:'BMC IPMI',vendor:'Supermicro',cvss:8.8,type:'Command Injection',exploitAvailable:true,kev:false,affectedVersions:'Various',patchAvailable:true,datePublished:'2023-10-06',affectedNodes:[]},
  {cve:'CVE-2023-23583',product:'Xeon Processors',vendor:'Intel',cvss:8.8,type:'Privilege Escalation',exploitAvailable:false,kev:false,affectedVersions:'Various Xeon',patchAvailable:true,datePublished:'2023-11-14',affectedNodes:[]},
  {cve:'CVE-2024-21793',product:'BIG-IP',vendor:'F5',cvss:7.5,type:'OData Injection',exploitAvailable:true,kev:false,affectedVersions:'17.x',patchAvailable:true,datePublished:'2024-05-08',affectedNodes:[]},
  {cve:'CVE-2024-20368',product:'ISE',vendor:'Cisco',cvss:6.1,type:'XSS',exploitAvailable:false,kev:false,affectedVersions:'3.x',patchAvailable:true,datePublished:'2024-04-03',affectedNodes:[]}
];

// ============================================================================
// NATION-STATE CYBER CAPABILITY PROFILES
// ============================================================================
var NATION_PROFILES = [
  {nation:'Russia',tier:1,units:['GRU Unit 74455 (Sandworm)','GRU Unit 26165 (APT28)','SVR (APT29)','FSB (Turla, Gamaredon)'],capability:'Destructive attacks, intelligence collection, election interference, information operations',notableOps:['NotPetya (2017)','SolarWinds (2020)','Viasat (2022)','Industroyer2 (2022)'],primaryTargets:['NATO','Ukraine','Energy','Elections'],estimatedOperators:'5,000-10,000',budget:'$500M-1B estimated annual',assessment:'Top-tier offensive capability with willingness to deploy destructive attacks against civilian infrastructure'},
  {nation:'China',tier:1,units:['PLA SSF Unit 61398','MSS','PLA SSF Unit 61486','Various contract hackers'],capability:'Large-scale espionage, IP theft, pre-positioning, supply chain compromise',notableOps:['OPM (2015)','Equifax (2017)','SolarWinds adjacent','Volt Typhoon (2023-2026)'],primaryTargets:['US CI','Technology','Defense','Telecom'],estimatedOperators:'50,000-100,000',budget:'$2-5B estimated annual',assessment:'Largest state cyber force, focused on strategic intelligence and pre-positioning for Taiwan contingency'},
  {nation:'North Korea',tier:2,units:['RGB Bureau 121','Lazarus Group','Kimsuky','Andariel','ScarCruft'],capability:'Financial theft, cryptocurrency heists, espionage, destructive attacks',notableOps:['Sony Pictures (2014)','WannaCry (2017)','Bangladesh Bank (2016)','Axie Infinity (2022)'],primaryTargets:['Financial','Cryptocurrency','South Korea','Defense'],estimatedOperators:'7,000-10,000',budget:'$200-500M (partially self-funded via theft)',assessment:'Highly motivated by revenue generation for sanctions evasion, with growing sophistication in crypto theft'},
  {nation:'Iran',tier:2,units:['IRGC-CEC','APT35 (Charming Kitten)','MuddyWater','OilRig','CyberAv3ngers'],capability:'Destructive attacks, espionage, influence operations, ICS targeting',notableOps:['Saudi Aramco (2012)','Bowman Avenue Dam (2013)','Albania (2022)','Unitronics PLCs (2023)'],primaryTargets:['Gulf States','Israel','US CI','Energy'],estimatedOperators:'5,000-8,000',budget:'$200-400M estimated annual',assessment:'Rapidly developing ICS/SCADA targeting capability with demonstrated willingness to attack water infrastructure'},
  {nation:'United States',tier:1,units:['NSA TAO','US CYBERCOM','CIA Center for Cyber Intelligence'],capability:'Full spectrum cyber operations, intelligence collection, offensive counter-cyber',notableOps:['Stuxnet (2010)','Equation Group tools','Olympic Games','Classified'],primaryTargets:['Classified'],estimatedOperators:'30,000+',budget:'$10B+ annual (public)',assessment:'Most capable state cyber force with global reach, primarily focused on intelligence and military operations'},
  {nation:'Israel',tier:1,units:['Unit 8200','Mossad','Shin Bet'],capability:'Offensive cyber, zero-day development, surveillance technology',notableOps:['Stuxnet (joint)','Duqu','Flame','Pegasus ecosystem'],primaryTargets:['Iran','Regional threats','Counter-terrorism'],estimatedOperators:'5,000-8,000',budget:'$1-2B estimated annual',assessment:'World-class zero-day development and offensive capability, commercial surveillance ecosystem'},
  {nation:'United Kingdom',tier:1,units:['GCHQ','NCSC','National Cyber Force'],capability:'Intelligence collection, offensive cyber, defensive operations',notableOps:['Classified SIGINT operations','Counter-ISIS operations'],primaryTargets:['Russia','China','Counter-terrorism'],estimatedOperators:'6,000+',budget:'$2B+ annual',assessment:'Strong Five Eyes partner with growing offensive capability through National Cyber Force'},
  {nation:'Vietnam',tier:3,units:['APT32/OceanLotus'],capability:'Espionage, surveillance of dissidents',notableOps:['OceanLotus campaigns against ASEAN'],primaryTargets:['Government','Dissidents','ASEAN'],estimatedOperators:'500-1,000',budget:'$50-100M estimated',assessment:'Developing capability focused on regional intelligence and domestic surveillance'}
];

// ============================================================================
// DETECTION RULES & SIGMA SIGNATURES
// ============================================================================
var DETECTION_RULES = [
  {id:'DR01',name:'SCADA Protocol Anomaly',category:'ICS',description:'Detects unusual Modbus TCP commands targeting PLC registers outside normal operating parameters',severity:'critical',dataSource:'OT Network Monitor',mitre:'T1059',falsePositiveRate:'low'},
  {id:'DR02',name:'Lateral Movement via PsExec',category:'Endpoint',description:'Detects PsExec service installation and remote execution patterns',severity:'high',dataSource:'Sysmon EventCode 13',mitre:'T1570',falsePositiveRate:'medium'},
  {id:'DR03',name:'Kerberoasting Activity',category:'Identity',description:'Detects TGS requests for service accounts with RC4 encryption',severity:'high',dataSource:'Windows Security 4769',mitre:'T1558.003',falsePositiveRate:'low'},
  {id:'DR04',name:'DCSync Attack',category:'Identity',description:'Detects directory replication requests from non-DC systems',severity:'critical',dataSource:'Windows Security 4662',mitre:'T1003.006',falsePositiveRate:'very low'},
  {id:'DR05',name:'DNS Tunneling',category:'Network',description:'Detects abnormally long DNS queries indicative of data exfiltration',severity:'high',dataSource:'DNS Logs',mitre:'T1071.004',falsePositiveRate:'medium'},
  {id:'DR06',name:'Process Injection',category:'Endpoint',description:'Detects CreateRemoteThread calls into processes like lsass.exe',severity:'critical',dataSource:'Sysmon EventCode 8',mitre:'T1055',falsePositiveRate:'low'},
  {id:'DR07',name:'Suspicious PowerShell',category:'Endpoint',description:'Detects encoded PowerShell commands and AMSI bypass attempts',severity:'high',dataSource:'PowerShell Logging',mitre:'T1059.001',falsePositiveRate:'medium'},
  {id:'DR08',name:'Living Off The Land',category:'Endpoint',description:'Detects abuse of certutil, mshta, regsvr32, and other LOLBins',severity:'medium',dataSource:'Sysmon EventCode 1',mitre:'T1218',falsePositiveRate:'high'},
  {id:'DR09',name:'Credential Dumping',category:'Endpoint',description:'Detects access to LSASS memory and SAM registry hive extraction',severity:'critical',dataSource:'Sysmon EventCode 10',mitre:'T1003',falsePositiveRate:'low'},
  {id:'DR10',name:'C2 Beacon Detection',category:'Network',description:'Detects periodic outbound connections with consistent jitter to unknown domains',severity:'high',dataSource:'Proxy/Firewall Logs',mitre:'T1071.001',falsePositiveRate:'medium'},
  {id:'DR11',name:'Data Staging',category:'Endpoint',description:'Detects creation of compressed archives in temp directories with sensitive file types',severity:'medium',dataSource:'Sysmon EventCode 11',mitre:'T1074',falsePositiveRate:'medium'},
  {id:'DR12',name:'Shadow Copy Deletion',category:'Endpoint',description:'Detects vssadmin or wmic commands deleting shadow copies (ransomware precursor)',severity:'critical',dataSource:'Sysmon EventCode 1',mitre:'T1490',falsePositiveRate:'very low'},
  {id:'DR13',name:'Registry Persistence',category:'Endpoint',description:'Detects modifications to Run/RunOnce registry keys',severity:'medium',dataSource:'Sysmon EventCode 13',mitre:'T1547.001',falsePositiveRate:'high'},
  {id:'DR14',name:'WMI Persistence',category:'Endpoint',description:'Detects WMI event subscription creation for persistence',severity:'high',dataSource:'Sysmon EventCode 19-21',mitre:'T1546.003',falsePositiveRate:'low'},
  {id:'DR15',name:'Anomalous Network Traffic',category:'Network',description:'Detects traffic to known threat actor infrastructure using threat intelligence feeds',severity:'critical',dataSource:'Firewall/Proxy',mitre:'T1071',falsePositiveRate:'very low'},
  {id:'DR16',name:'BGP Hijack Attempt',category:'Network',description:'Detects unexpected BGP route announcements for monitored prefixes',severity:'critical',dataSource:'BGP Monitoring',mitre:'T1557',falsePositiveRate:'low'},
  {id:'DR17',name:'Certificate Anomaly',category:'Network',description:'Detects SSL/TLS certificates with unusual attributes or self-signed certificates on critical services',severity:'medium',dataSource:'Certificate Monitor',mitre:'T1587.003',falsePositiveRate:'medium'},
  {id:'DR18',name:'Firmware Modification',category:'ICS',description:'Detects unauthorized changes to PLC or RTU firmware',severity:'critical',dataSource:'ICS Monitor',mitre:'T0839',falsePositiveRate:'very low'},
  {id:'DR19',name:'Privilege Escalation',category:'Endpoint',description:'Detects use of known privilege escalation exploits and techniques',severity:'high',dataSource:'Sysmon/EDR',mitre:'T1068',falsePositiveRate:'low'},
  {id:'DR20',name:'Exfiltration via Cloud Storage',category:'Network',description:'Detects large uploads to cloud storage services (S3, Azure Blob, GCS)',severity:'high',dataSource:'Proxy/CASB',mitre:'T1567',falsePositiveRate:'medium'}
];

// ============================================================================
// MITRE ATT&CK TECHNIQUE MAPPING
// ============================================================================
var MITRE_TECHNIQUES = [
  {id:'T1190',name:'Exploit Public-Facing Application',tactic:'Initial Access',usedBy:['APT03','APT06','APT07','APT11','APT19','APT27']},
  {id:'T1566',name:'Phishing',tactic:'Initial Access',usedBy:['APT01','APT02','APT05','APT10','APT14','APT17','APT25','APT26']},
  {id:'T1195',name:'Supply Chain Compromise',tactic:'Initial Access',usedBy:['APT02','APT06','APT09','APT22']},
  {id:'T1078',name:'Valid Accounts',tactic:'Initial Access',usedBy:['APT02','APT11','APT17','APT26','APT27']},
  {id:'T1059',name:'Command and Scripting Interpreter',tactic:'Execution',usedBy:['APT01','APT02','APT03','APT05','APT06','APT07','APT08','APT11','APT13','APT14','APT17','APT18','APT19']},
  {id:'T1059.001',name:'PowerShell',tactic:'Execution',usedBy:['APT01','APT02','APT06','APT11','APT17']},
  {id:'T1059.003',name:'Windows Command Shell',tactic:'Execution',usedBy:['APT03','APT05']},
  {id:'T1059.005',name:'Visual Basic',tactic:'Execution',usedBy:['APT05','APT19']},
  {id:'T1059.007',name:'JavaScript',tactic:'Execution',usedBy:['APT13','APT24']},
  {id:'T1203',name:'Exploitation for Client Execution',tactic:'Execution',usedBy:['APT16','APT31x','APT34x']},
  {id:'T1547',name:'Boot or Logon Autostart Execution',tactic:'Persistence',usedBy:['APT05','APT10','APT14']},
  {id:'T1543',name:'Create or Modify System Process',tactic:'Persistence',usedBy:[]},
  {id:'T1098',name:'Account Manipulation',tactic:'Persistence',usedBy:['APT02']},
  {id:'T1136',name:'Create Account',tactic:'Persistence',usedBy:['APT26']},
  {id:'T1055',name:'Process Injection',tactic:'Defense Evasion',usedBy:['APT06','APT24','APT32']},
  {id:'T1027',name:'Obfuscated Files or Information',tactic:'Defense Evasion',usedBy:['APT01','APT04','APT05','APT18','APT27','APT30','APT32']},
  {id:'T1070',name:'Indicator Removal',tactic:'Defense Evasion',usedBy:['APT21']},
  {id:'T1562',name:'Impair Defenses',tactic:'Defense Evasion',usedBy:['APT11']},
  {id:'T1003',name:'OS Credential Dumping',tactic:'Credential Access',usedBy:['APT11','APT19']},
  {id:'T1056',name:'Input Capture',tactic:'Credential Access',usedBy:['APT12','APT14','APT17','APT34x']},
  {id:'T1071',name:'Application Layer Protocol',tactic:'Command and Control',usedBy:['APT01','APT04','APT05','APT08','APT10','APT17','APT18','APT19','APT24','APT25','APT27','APT29x','APT32']},
  {id:'T1573',name:'Encrypted Channel',tactic:'Command and Control',usedBy:['APT04']},
  {id:'T1090',name:'Proxy',tactic:'Command and Control',usedBy:['APT04','APT09']},
  {id:'T1041',name:'Exfiltration Over C2 Channel',tactic:'Exfiltration',usedBy:[]},
  {id:'T1560',name:'Archive Collected Data',tactic:'Collection',usedBy:['APT07','APT08','APT16','APT24','APT25']},
  {id:'T1005',name:'Data from Local System',tactic:'Collection',usedBy:['APT08','APT12']},
  {id:'T1486',name:'Data Encrypted for Impact',tactic:'Impact',usedBy:['APT13','APT25','APT27','APT28x','APT29x']},
  {id:'T1485',name:'Data Destruction',tactic:'Impact',usedBy:['APT03','APT20','APT21','APT30']},
  {id:'T1561',name:'Disk Wipe',tactic:'Impact',usedBy:['APT03']},
  {id:'T1529',name:'System Shutdown/Reboot',tactic:'Impact',usedBy:['APT03','APT20']}
];

// ============================================================================
// EXTENDED HELPER FUNCTIONS
// ============================================================================
function getAPTById(id) {
  for (var i = 0; i < APT_GROUPS.length; i++) {
    if (APT_GROUPS[i].id === id) return APT_GROUPS[i];
  }
  return null;
}

function getAPTByName(name) {
  for (var i = 0; i < APT_GROUPS.length; i++) {
    if (APT_GROUPS[i].name === name) return APT_GROUPS[i];
  }
  return null;
}

function getCampaignsForAPT(aptId) {
  var result = [];
  for (var i = 0; i < APT_CAMPAIGNS.length; i++) {
    if (APT_CAMPAIGNS[i].apt === aptId) result.push(APT_CAMPAIGNS[i]);
  }
  return result;
}

function getTechniquesForAPT(aptId) {
  var result = [];
  for (var i = 0; i < MITRE_TECHNIQUES.length; i++) {
    if (MITRE_TECHNIQUES[i].usedBy.indexOf(aptId) !== -1) result.push(MITRE_TECHNIQUES[i]);
  }
  return result;
}

function getVulnsForNode(nodeId) {
  var result = [];
  for (var i = 0; i < VULN_DATABASE.length; i++) {
    if (VULN_DATABASE[i].affectedNodes.indexOf(nodeId) !== -1) result.push(VULN_DATABASE[i]);
  }
  return result;
}

function getRiskColor(score) {
  if (score >= 35) return '#ff0040';
  if (score >= 25) return '#ff6600';
  if (score >= 15) return '#ffaa00';
  return '#00ff88';
}

function getPlaybookById(id) {
  for (var i = 0; i < IR_PLAYBOOKS.length; i++) {
    if (IR_PLAYBOOKS[i].id === id) return IR_PLAYBOOKS[i];
  }
  return null;
}

function countBySector(nodeList) {
  var counts = {};
  for (var i = 0; i < nodeList.length; i++) {
    var node = getNodeById(nodeList[i]);
    if (node) {
      counts[node.sector] = (counts[node.sector] || 0) + 1;
    }
  }
  return counts;
}

function getTotalPopulation(nodeIds) {
  var total = 0;
  for (var i = 0; i < nodeIds.length; i++) {
    var node = getNodeById(nodeIds[i]);
    if (node) total += node.population;
  }
  return total;
}

function getTriggersForRegion(region) {
  var result = [];
  for (var i = 0; i < GEO_TRIGGERS.length; i++) {
    if (GEO_TRIGGERS[i].region === region) result.push(GEO_TRIGGERS[i]);
  }
  return result;
}

function getComponentsByCategory(category) {
  var result = [];
  for (var i = 0; i < SUPPLY_CHAIN.length; i++) {
    if (SUPPLY_CHAIN[i].category === category) result.push(SUPPLY_CHAIN[i]);
  }
  return result;
}

function getHighRiskComponents() {
  var result = [];
  for (var i = 0; i < SUPPLY_CHAIN.length; i++) {
    if (SUPPLY_CHAIN[i].riskScore >= 30) result.push(SUPPLY_CHAIN[i]);
  }
  return result.sort(function(a, b) { return b.riskScore - a.riskScore; });
}

function getActiveThreats() {
  var result = [];
  for (var i = 0; i < THREAT_PREDICTIONS.length; i++) {
    if (THREAT_PREDICTIONS[i].status === 'active') result.push(THREAT_PREDICTIONS[i]);
  }
  return result.sort(function(a, b) { return b.confidence - a.confidence; });
}

function getRecentIntel(hours) {
  var cutoff = new Date(Date.now() - hours * 3600000).toISOString();
  var result = [];
  for (var i = 0; i < INTEL_FEEDS.length; i++) {
    if (INTEL_FEEDS[i].timestamp >= cutoff) result.push(INTEL_FEEDS[i]);
  }
  return result;
}

function calculateThreatScore() {
  var score = 0;
  var activeThreats = getActiveThreats();
  for (var i = 0; i < activeThreats.length; i++) {
    score += activeThreats[i].confidence * (activeThreats[i].horizon === '24h' ? 3 : (activeThreats[i].horizon === '48h' ? 2 : 1));
  }
  var criticalTriggers = 0;
  for (var g = 0; g < GEO_TRIGGERS.length; g++) {
    if (GEO_TRIGGERS[g].escalationRisk === 'critical') criticalTriggers++;
  }
  score += criticalTriggers * 50;
  return Math.min(1000, score);
}

function generateThreatBrief() {
  var activeThreats = getActiveThreats();
  var recentIntel = getRecentIntel(24);
  var brief = 'THREAT BRIEF - ' + new Date().toISOString() + '\n\n';
  brief += 'ACTIVE THREATS: ' + activeThreats.length + '\n';
  brief += 'RECENT INTEL (24h): ' + recentIntel.length + ' reports\n';
  brief += 'THREAT SCORE: ' + calculateThreatScore() + '/1000\n\n';
  brief += 'TOP THREATS:\n';
  for (var i = 0; i < Math.min(5, activeThreats.length); i++) {
    brief += '  ' + (i + 1) + '. [' + activeThreats[i].horizon + '] ' + activeThreats[i].threat + ' (Confidence: ' + activeThreats[i].confidence + '%)\n';
  }
  return brief;
}

function getNodeDependencyDepth(nodeId, visited) {
  if (!visited) visited = [];
  if (visited.indexOf(nodeId) !== -1) return 0;
  visited.push(nodeId);
  var node = getNodeById(nodeId);
  if (!node || node.deps.length === 0) return 0;
  var maxDepth = 0;
  for (var i = 0; i < node.deps.length; i++) {
    var depth = getNodeDependencyDepth(node.deps[i], visited.slice());
    if (depth > maxDepth) maxDepth = depth;
  }
  return maxDepth + 1;
}

function calculateSectorRisk(sectorId) {
  var nodes = getSectorNodes(sectorId);
  var totalRisk = 0;
  for (var i = 0; i < nodes.length; i++) {
    var nodeRisk = nodes[i].criticality * 10;
    var vulns = getVulnsForNode(nodes[i].id);
    nodeRisk += vulns.length * 15;
    var crossSectorDeps = 0;
    for (var d = 0; d < nodes[i].deps.length; d++) {
      var depNode = getNodeById(nodes[i].deps[d]);
      if (depNode && depNode.sector !== sectorId) crossSectorDeps++;
    }
    nodeRisk += crossSectorDeps * 5;
    totalRisk += nodeRisk;
  }
  return nodes.length > 0 ? Math.round(totalRisk / nodes.length) : 0;
}

function generateNetworkMap() {
  var map = {};
  for (var i = 0; i < INFRA_NODES.length; i++) {
    var node = INFRA_NODES[i];
    if (!map[node.sector]) map[node.sector] = [];
    map[node.sector].push({
      id: node.id,
      name: node.name,
      deps: node.deps,
      dependents: getDependents(node.id).length,
      criticality: node.criticality,
      population: node.population,
      risk: calculateNodeRisk(node)
    });
  }
  return map;
}

function calculateNodeRisk(node) {
  var risk = node.criticality * 8;
  var vulns = getVulnsForNode(node.id);
  risk += vulns.length * 20;
  var dependents = getDependents(node.id);
  risk += Math.min(dependents.length * 5, 30);
  if (node.status !== 'online') risk += 15;
  return Math.min(100, risk);
}

function formatDuration(minutes) {
  if (minutes < 60) return minutes + ' min';
  var hours = Math.floor(minutes / 60);
  var mins = minutes % 60;
  if (hours < 24) return hours + 'h ' + mins + 'm';
  var days = Math.floor(hours / 24);
  hours = hours % 24;
  return days + 'd ' + hours + 'h';
}

function generateSituationReport() {
  var sectors = {};
  for (var i = 0; i < SECTORS.length; i++) {
    var sec = SECTORS[i];
    sectors[sec.id] = {
      name: sec.name,
      health: getSectorHealth(sec.id),
      nodes: getSectorNodes(sec.id).length,
      risk: calculateSectorRisk(sec.id)
    };
  }
  var activeAPTs = [];
  for (var a = 0; a < APT_GROUPS.length; a++) {
    if (APT_GROUPS[a].active) activeAPTs.push(APT_GROUPS[a].name);
  }
  return {
    timestamp: new Date().toISOString(),
    defcon: state.defcon,
    threatScore: calculateThreatScore(),
    sectors: sectors,
    activeAPTs: activeAPTs,
    activeThreats: getActiveThreats().length,
    recentIntel: getRecentIntel(24).length,
    highRiskComponents: getHighRiskComponents().length
  };
}

// ============================================================================
// EXTENDED THREAT ACTOR PROFILES FOR DETAILED VIEW
// ============================================================================
var ACTOR_PROFILES = [
  {aptId:'APT01',overview:'APT28, also known as Fancy Bear, is a Russian military intelligence (GRU) cyber espionage group attributed to the GRU 85th Main Special Service Center (GTsSS), military unit 26165. Active since at least 2004, it has been involved in numerous high-profile attacks against government, military, and media targets.',motivation:'Intelligence collection and information operations aligned with Russian state interests',infrastructure:{c2Servers:45,domains:230,ipRanges:12,tlsCerts:89},tools:['X-Agent (Sofacy)','X-Tunnel','Seduploader','Zebrocy','Cannon','LoJack modified UEFI implant','Skinny Boy'],victimography:{countries:['US','UK','Germany','France','Ukraine','Georgia','Poland','Norway','Netherlands'],sectors:['Government','Military','Media','Defense','Energy','Think Tanks']},timeline:[
    {year:2008,event:'Georgia cyber attacks during Russia-Georgia war'},
    {year:2014,event:'Ukrainian election disruption attempt'},
    {year:2015,event:'German Bundestag compromise'},
    {year:2016,event:'DNC hack and US election interference'},
    {year:2017,event:'French presidential election interference'},
    {year:2018,event:'Olympic Destroyer during Pyeongchang Olympics'},
    {year:2020,event:'Norwegian Parliament email compromise'},
    {year:2022,event:'Targeting of Ukrainian government during invasion'},
    {year:2024,event:'EU parliamentary targets before elections'},
    {year:2026,event:'Operation Fancy Storm targeting NATO'}
  ]},
  {aptId:'APT02',overview:'APT29, also known as Cozy Bear, is attributed to the Russian Foreign Intelligence Service (SVR). Distinguished by its high sophistication and focus on stealthy, long-term intelligence collection. Known for the SolarWinds supply chain compromise and Microsoft cloud targeting.',motivation:'Strategic intelligence collection for Russian foreign policy decision-making',infrastructure:{c2Servers:32,domains:180,ipRanges:8,tlsCerts:67},tools:['EnvyScout','FoggyWeb','MagicWeb','NativeZone','TrailBlazer','SUNBURST','TEARDROP','Raindrop','GoldMax','Sibot','GoldFinder'],victimography:{countries:['US','UK','EU','Canada','Australia'],sectors:['Government','Technology','Think Tanks','Healthcare','Research']},timeline:[
    {year:2008,event:'First observed operations against US government'},
    {year:2014,event:'White House and State Department compromise'},
    {year:2015,event:'DNC network access (separate from APT28)'},
    {year:2020,event:'SolarWinds Orion supply chain compromise'},
    {year:2021,event:'USAID phishing campaign via Constant Contact'},
    {year:2023,event:'Microsoft cloud environment targeting'},
    {year:2024,event:'HPE corporate email compromise'},
    {year:2026,event:'Midnight Cascade cloud supply chain operation'}
  ]},
  {aptId:'APT03',overview:'Sandworm is attributed to GRU Unit 74455, the Main Center for Special Technologies. It is considered the most dangerous Russian cyber threat actor due to its willingness to deploy destructive and disruptive attacks against civilian infrastructure, including power grids.',motivation:'Destructive operations, intelligence collection, and strategic deterrence',infrastructure:{c2Servers:55,domains:340,ipRanges:15,tlsCerts:112},tools:['BlackEnergy','Industroyer/CrashOverride','NotPetya','Olympic Destroyer','Exaramel','Cyclops Blink','AcidRain','Industroyer2','CaddyWiper','ArguePatch','SwiftSlicer'],victimography:{countries:['Ukraine','US','UK','France','Georgia','Korea','Germany','Poland'],sectors:['Energy','Government','Media','Olympics','Financial','Transport']},timeline:[
    {year:2014,event:'BlackEnergy attacks on Ukrainian energy sector'},
    {year:2015,event:'Ukraine power grid attack (first cyber-caused blackout)'},
    {year:2016,event:'Second Ukraine power grid attack using Industroyer'},
    {year:2017,event:'NotPetya destructive global cyberattack ($10B+ damage)'},
    {year:2018,event:'Olympic Destroyer during Pyeongchang'},
    {year:2022,event:'AcidRain satellite attack, Industroyer2 against Ukraine grid'},
    {year:2024,event:'Multiple wiper deployments against Ukraine'},
    {year:2026,event:'BlackEnergy Resurgence targeting European energy'}
  ]},
  {aptId:'APT11',overview:'Volt Typhoon is a Chinese state-sponsored threat actor focused on pre-positioning for destructive cyber operations against US critical infrastructure. Uses living-off-the-land techniques to maintain persistent access while evading detection.',motivation:'Strategic pre-positioning for potential future destructive operations during geopolitical crisis',infrastructure:{c2Servers:2000,domains:50,ipRanges:0,tlsCerts:0},tools:['Living-off-the-land binaries only','Custom webshells','SOHO router firmware implants','No custom malware (intentionally)'],victimography:{countries:['US','Guam','Australia'],sectors:['Telecom','Water','Energy','Transport','Government','Maritime']},timeline:[
    {year:2021,event:'Initial access to US telecom infrastructure'},
    {year:2023,event:'Publicly exposed by Microsoft and Five Eyes'},
    {year:2024,event:'Confirmed access to water, energy, telecom, transport'},
    {year:2025,event:'Infrastructure expanded to 2000+ compromised routers'},
    {year:2026,event:'Typhoon Season - continued expansion and deepening of access'}
  ]},
  {aptId:'APT13',overview:'Lazarus Group is attributed to North Korean RGB Bureau 121. Unique among APT groups for being financially motivated, conducting cryptocurrency heists and bank robberies to fund the DPRK weapons program. Also conducts espionage and destructive operations.',motivation:'Revenue generation for DPRK weapons programs and intelligence collection',infrastructure:{c2Servers:28,domains:450,ipRanges:5,tlsCerts:34},tools:['TraderTraitor','AppleJeus','COPPERHEDGE','FASTCash','BLINDINGCAN','DTrack','MagicRAT','QuiteRAT','CollectionRAT'],victimography:{countries:['US','South Korea','Japan','Bangladesh','Global'],sectors:['Financial','Cryptocurrency','Defense','Entertainment','Aerospace']},timeline:[
    {year:2009,event:'DDoS attacks on US and South Korean websites'},
    {year:2014,event:'Sony Pictures destructive attack'},
    {year:2016,event:'Bangladesh Bank SWIFT heist ($81M)'},
    {year:2017,event:'WannaCry ransomware global outbreak'},
    {year:2022,event:'Axie Infinity Ronin bridge theft ($625M)'},
    {year:2023,event:'Multiple crypto heists totaling $1B+'},
    {year:2025,event:'Bybit exchange theft ($1.5B)'},
    {year:2026,event:'Crypto Harvest 2026 - $1.2B stolen'}
  ]}
];

// ============================================================================
// NETWORK FLOW DATA FOR VISUALIZATION
// ============================================================================
var NETWORK_FLOWS = [
  {source:'PG14',dest:'TC03',protocol:'Modbus/TCP',port:502,bandwidth:'1.2 Mbps',encrypted:false,anomaly:false},
  {source:'PG16',dest:'PG07',protocol:'DNP3',port:20000,bandwidth:'0.5 Mbps',encrypted:false,anomaly:false},
  {source:'PG17',dest:'PG08',protocol:'DNP3',port:20000,bandwidth:'0.4 Mbps',encrypted:false,anomaly:false},
  {source:'WT11',dest:'TC03',protocol:'OPC-UA',port:4840,bandwidth:'0.8 Mbps',encrypted:true,anomaly:false},
  {source:'WT01',dest:'WT11',protocol:'Modbus/TCP',port:502,bandwidth:'0.3 Mbps',encrypted:false,anomaly:true},
  {source:'TC03',dest:'TC14',protocol:'BGP',port:179,bandwidth:'10 Gbps',encrypted:false,anomaly:false},
  {source:'TC08',dest:'TC14',protocol:'BGP',port:179,bandwidth:'8 Gbps',encrypted:false,anomaly:false},
  {source:'FN01',dest:'FN05',protocol:'FIX',port:9878,bandwidth:'5 Gbps',encrypted:true,anomaly:false},
  {source:'FN03',dest:'TC14',protocol:'SWIFT',port:443,bandwidth:'100 Mbps',encrypted:true,anomaly:false},
  {source:'HC04',dest:'TC03',protocol:'HL7/FHIR',port:443,bandwidth:'2 Gbps',encrypted:true,anomaly:false},
  {source:'GV01',dest:'TC06',protocol:'Classified',port:0,bandwidth:'1 Gbps',encrypted:true,anomaly:false},
  {source:'GV10',dest:'GV01',protocol:'Classified',port:0,bandwidth:'500 Mbps',encrypted:true,anomaly:false},
  {source:'EN19',dest:'EN01',protocol:'SCADA',port:502,bandwidth:'0.2 Mbps',encrypted:false,anomaly:true},
  {source:'EN19',dest:'EN03',protocol:'SCADA',port:502,bandwidth:'0.3 Mbps',encrypted:false,anomaly:false},
  {source:'TR01',dest:'TC03',protocol:'ASTERIX',port:8600,bandwidth:'50 Mbps',encrypted:true,anomaly:false},
  {source:'TR05',dest:'TR03',protocol:'ERTMS',port:50000,bandwidth:'10 Mbps',encrypted:true,anomaly:false},
  {source:'HC13',dest:'TC17',protocol:'SIP',port:5060,bandwidth:'5 Mbps',encrypted:false,anomaly:false},
  {source:'GV06',dest:'TC17',protocol:'SIP/PSAP',port:5060,bandwidth:'10 Mbps',encrypted:false,anomaly:false},
  {source:'FN07',dest:'FN09',protocol:'ISO 8583',port:8583,bandwidth:'1 Gbps',encrypted:true,anomaly:false},
  {source:'FN10',dest:'TC14',protocol:'HTTPS',port:443,bandwidth:'3 Gbps',encrypted:true,anomaly:false},
  {source:'EN18',dest:'FN01',protocol:'FIX',port:9878,bandwidth:'2 Gbps',encrypted:true,anomaly:false},
  {source:'GV18',dest:'TC06',protocol:'GPS L-Band',port:0,bandwidth:'50 kbps',encrypted:true,anomaly:false},
  {source:'GV17',dest:'TC08',protocol:'HTTPS',port:443,bandwidth:'500 Mbps',encrypted:true,anomaly:false},
  {source:'HC09',dest:'HC01',protocol:'HL7',port:2575,bandwidth:'100 Mbps',encrypted:true,anomaly:false},
  {source:'WT12',dest:'WT11',protocol:'MQTT',port:1883,bandwidth:'0.1 Mbps',encrypted:false,anomaly:true},
  {source:'EN12',dest:'PG16',protocol:'DLMS/COSEM',port:4059,bandwidth:'0.5 Mbps',encrypted:false,anomaly:false},
  {source:'TR20',dest:'TC12',protocol:'V2X',port:2000,bandwidth:'100 Mbps',encrypted:true,anomaly:false},
  {source:'TR13',dest:'TR08',protocol:'NTCIP',port:161,bandwidth:'1 Mbps',encrypted:false,anomaly:false},
  {source:'FN13',dest:'GV07',protocol:'FedLine',port:443,bandwidth:'1 Gbps',encrypted:true,anomaly:false},
  {source:'GV04',dest:'TC03',protocol:'HTTPS',port:443,bandwidth:'500 Mbps',encrypted:true,anomaly:false}
];

// ============================================================================
// COMPLIANCE FRAMEWORKS
// ============================================================================
var COMPLIANCE_STATUS = [
  {framework:'NIST CSF 2.0',coverage:87,lastAssessment:'2026-08-15',gaps:['Supply Chain Risk Mgmt','Incident Recovery Testing'],status:'partial'},
  {framework:'NIST SP 800-82 (ICS)',coverage:72,lastAssessment:'2026-07-20',gaps:['Network Segmentation','PLC Firmware Signing','OT Monitoring'],status:'partial'},
  {framework:'NERC CIP',coverage:91,lastAssessment:'2026-09-01',gaps:['BES Cyber Asset Identification'],status:'compliant'},
  {framework:'IEC 62443',coverage:68,lastAssessment:'2026-06-15',gaps:['Zone Conduit Model','Security Level Assessment','Patch Management'],status:'partial'},
  {framework:'ISO 27001:2022',coverage:83,lastAssessment:'2026-08-01',gaps:['Threat Intelligence Integration','Cloud Security'],status:'partial'},
  {framework:'CMMC Level 3',coverage:78,lastAssessment:'2026-07-01',gaps:['Incident Response Testing','Audit Log Review','Access Mgmt'],status:'partial'},
  {framework:'FedRAMP High',coverage:92,lastAssessment:'2026-09-05',gaps:['Continuous Monitoring Automation'],status:'compliant'},
  {framework:'HIPAA Security',coverage:85,lastAssessment:'2026-08-10',gaps:['Business Associate Agreements','Encryption at Rest'],status:'partial'},
  {framework:'PCI DSS 4.0',coverage:89,lastAssessment:'2026-08-20',gaps:['Network Segmentation Testing'],status:'compliant'},
  {framework:'CISA CPGs',coverage:76,lastAssessment:'2026-09-01',gaps:['MFA Deployment','Asset Inventory','OT/IT Segmentation'],status:'partial'}
];

// ============================================================================
// EXERCISE INJECT TEMPLATES
// ============================================================================
var INJECT_TEMPLATES = [
  {category:'Red Team',templates:[
    {name:'Phishing Delivery',description:'Red team delivers spearphishing email with weaponized document to target user',difficulty:'easy',expectedBlue:'Detection within 15 minutes, user reporting'},
    {name:'Web Exploitation',description:'Red team exploits vulnerable web application to gain initial foothold',difficulty:'medium',expectedBlue:'IDS/WAF alert, log analysis'},
    {name:'Lateral Movement',description:'Red team moves laterally using compromised credentials',difficulty:'medium',expectedBlue:'Behavioral analytics, network monitoring'},
    {name:'Privilege Escalation',description:'Red team escalates from user to domain admin',difficulty:'hard',expectedBlue:'PAM alerting, AD monitoring'},
    {name:'Data Exfiltration',description:'Red team stages and exfiltrates sensitive data via DNS tunneling',difficulty:'hard',expectedBlue:'DLP detection, DNS analysis'},
    {name:'SCADA Access',description:'Red team accesses SCADA system and modifies PLC ladder logic',difficulty:'extreme',expectedBlue:'OT monitoring, process anomaly detection'},
    {name:'Ransomware Engagement',description:'Red team deploys ransomware payload across multiple endpoints',difficulty:'extreme',expectedBlue:'Immediate containment, backup restoration'},
    {name:'Supply Chain',description:'Red team introduces malicious update through software repository',difficulty:'extreme',expectedBlue:'Code signing verification, SBOM analysis'}
  ]},
  {category:'White Cell',templates:[
    {name:'Media Inquiry',description:'Media call requesting comment on cyber incident',difficulty:'easy',expectedBlue:'PAO response within 30 minutes'},
    {name:'Regulatory Notification',description:'Regulator requests immediate status update and incident details',difficulty:'medium',expectedBlue:'Legal/compliance response'},
    {name:'VIP Account Compromise',description:'CEO or board member reports compromised personal email',difficulty:'medium',expectedBlue:'Executive protection protocol'},
    {name:'Second Attack Vector',description:'While responding to primary incident, a second attack vector is discovered',difficulty:'hard',expectedBlue:'Resource allocation, triage'},
    {name:'Backup Failure',description:'Backup restoration fails during recovery, requiring alternate approach',difficulty:'hard',expectedBlue:'DR plan activation'},
    {name:'Physical Security Event',description:'Concurrent physical security alarm at data center',difficulty:'medium',expectedBlue:'Coordination with physical security'},
    {name:'Allied Warning',description:'Partner nation warns of related cyber activity targeting your sector',difficulty:'easy',expectedBlue:'Intelligence integration, posture adjustment'},
    {name:'Insider Discovery',description:'Evidence suggests incident may involve insider cooperation',difficulty:'extreme',expectedBlue:'CI engagement, evidence preservation'}
  ]}
];

// ============================================================================
// SCORING ENGINE
// ============================================================================
var SCORING_CRITERIA = [
  {category:'Detection',weight:25,subcriteria:[
    {name:'Time to Detect',maxPoints:10,description:'How quickly the blue team identifies the initial compromise'},
    {name:'Detection Method',maxPoints:8,description:'Whether detection was automated, manual, or reported'},
    {name:'Scope Identification',maxPoints:7,description:'Accuracy of identifying all affected systems'}
  ]},
  {category:'Containment',weight:25,subcriteria:[
    {name:'Time to Contain',maxPoints:10,description:'Speed of effective containment actions'},
    {name:'Containment Effectiveness',maxPoints:10,description:'Whether containment prevented further spread'},
    {name:'Minimal Disruption',maxPoints:5,description:'Containing threat without unnecessary business impact'}
  ]},
  {category:'Eradication & Recovery',weight:30,subcriteria:[
    {name:'Root Cause Identified',maxPoints:10,description:'Correctly identifying the root cause of the incident'},
    {name:'Complete Remediation',maxPoints:10,description:'All malicious artifacts removed, vulnerabilities patched'},
    {name:'Service Restoration',maxPoints:10,description:'Speed and completeness of service recovery'}
  ]},
  {category:'Communication & Reporting',weight:20,subcriteria:[
    {name:'Internal Reporting',maxPoints:8,description:'Timely and accurate internal communications'},
    {name:'External Reporting',maxPoints:7,description:'Appropriate notification of external parties'},
    {name:'Documentation',maxPoints:5,description:'Quality of incident documentation and timeline'}
  ]}
];

// ============================================================================
// ADDITIONAL CSS FOR EXTENDED FEATURES (appended to PM_CSS)
// ============================================================================
var PM_CSS_EXT = '<style>' +
  '.pm-actor-card { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 16px; margin-bottom: 12px; }' +
  '.pm-actor-card:hover { border-color: #2a3a4a; }' +
  '.pm-actor-name { font-size: 14px; color: #00ff88; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 6px; }' +
  '.pm-actor-nation { font-size: 11px; color: #ffaa00; }' +
  '.pm-campaign-card { background: #080c14; border: 1px solid #1a2332; border-radius: 4px; padding: 12px; margin-bottom: 8px; border-left: 3px solid #ff0040; }' +
  '.pm-campaign-title { font-size: 12px; color: #ff6600; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px; }' +
  '.pm-vuln-card { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 10px; margin-bottom: 6px; }' +
  '.pm-vuln-cvss { font-size: 16px; font-weight: bold; }' +
  '.pm-vuln-cvss-critical { color: #ff0040; }' +
  '.pm-vuln-cvss-high { color: #ff6600; }' +
  '.pm-vuln-cvss-medium { color: #ffaa00; }' +
  '.pm-vuln-cvss-low { color: #00aaff; }' +
  '.pm-flow-line { padding: 6px 10px; border-bottom: 1px solid #111820; font-size: 11px; display: flex; align-items: center; gap: 8px; }' +
  '.pm-flow-anomaly { border-left: 3px solid #ff0040; background: #1a0d0d; }' +
  '.pm-compliance-card { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 12px; }' +
  '.pm-compliance-bar { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }' +
  '.pm-inject-card { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 10px; margin-bottom: 6px; cursor: pointer; }' +
  '.pm-inject-card:hover { border-color: #00aa55; }' +
  '.pm-nation-card { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 14px; }' +
  '.pm-nation-card:hover { border-color: #2a3a4a; }' +
  '.pm-nation-flag { font-size: 24px; margin-right: 8px; }' +
  '.pm-nation-tier { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 9px; font-weight: bold; text-transform: uppercase; }' +
  '.pm-tier-1 { background: #330010; color: #ff0040; border: 1px solid #660020; }' +
  '.pm-tier-2 { background: #332a00; color: #ffaa00; border: 1px solid #665500; }' +
  '.pm-tier-3 { background: #002233; color: #00aaff; border: 1px solid #004466; }' +
  '.pm-playbook-step { padding: 10px 14px; border: 1px solid #1a2332; border-bottom: none; display: flex; gap: 12px; align-items: flex-start; }' +
  '.pm-playbook-step:last-child { border-bottom: 1px solid #1a2332; }' +
  '.pm-playbook-step .step-num { background: #0d2137; color: #00ff88; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: bold; flex-shrink: 0; }' +
  '.pm-playbook-auto { color: #00ff88; font-size: 9px; padding: 1px 4px; border: 1px solid #00aa55; border-radius: 2px; }' +
  '.pm-playbook-manual { color: #ffaa00; font-size: 9px; padding: 1px 4px; border: 1px solid #aa6600; border-radius: 2px; }' +
  '.pm-mitre-cell { padding: 4px 8px; border: 1px solid #1a2332; font-size: 9px; text-align: center; min-width: 60px; }' +
  '.pm-mitre-used { background: #1a0d0d; color: #ff6600; border-color: #4d2600; }' +
  '.pm-mitre-unused { background: #0d1117; color: #334455; }' +
  '.pm-draggable { cursor: move; user-select: none; }' +
  '.pm-slide-in { animation: pm-slideIn 0.3s ease-out; }' +
  '.pm-fade-in { animation: pm-fadeIn 0.3s ease-out; }' +
  '.pm-risk-gauge { width: 100px; height: 6px; background: #1a2332; border-radius: 3px; overflow: hidden; display: inline-block; vertical-align: middle; margin-left: 8px; }' +
  '.pm-risk-gauge-fill { height: 100%; border-radius: 3px; }' +
  '.pm-collapsible { cursor: pointer; }' +
  '.pm-collapsible::before { content: "\\25B6 "; font-size: 10px; }' +
  '.pm-collapsible.open::before { content: "\\25BC "; }' +
  '.pm-collapsed { display: none; }' +
  '.pm-highlight { background: rgba(0,255,136,0.1); border-color: #00ff88 !important; }' +
  '.pm-striped tr:nth-child(even) td { background: #080c14; }' +
  '.pm-compact td, .pm-compact th { padding: 4px 8px; font-size: 11px; }' +

  '.pm-panel-hdr { background:#111820; padding:8px 14px; font-size:11px; color:#00ff88; text-transform:uppercase; letter-spacing:2px; border-bottom:1px solid #1a2332; font-family:monospace; }' +
  '.pm-panel-title { font-size:12px; color:#00ff88; text-transform:uppercase; letter-spacing:2px; padding:10px 14px; font-family:monospace; border-bottom:1px solid #1a2332; background:#111820; }' +
  '.pm-card-header { font-size:11px; color:#00ff88; text-transform:uppercase; letter-spacing:1px; padding:0 0 8px; border-left:3px solid #00ff88; padding-left:10px; font-family:monospace; }' +
  '.pm-card-body { padding:0; }' +
  '.pm-content { padding:16px; }' +
  '.pm-footer { padding:8px 14px; font-size:10px; color:#667788; text-align:center; border-top:1px solid #1a2332; background:#080c14; }' +
  '.pm-center { text-align:center; }' +
  '.pm-mono { font-family:monospace; font-size:12px; color:#8899aa; }' +
  '.pm-canvas { width:100%; background:#080c14; border:1px solid #1a2332; border-radius:4px; display:block; }' +
  '.pm-dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:4px; vertical-align:middle; }' +
  '.pm-val-accent { color:#00ff88; font-weight:bold; }' +
  '.pm-version { font-size:10px; color:#667788; margin-left:8px; }' +
  '.pm-session { font-size:10px; color:#667788; margin-left:12px; }' +
  '.pm-operator { font-size:10px; color:#8899aa; }' +

  '.pm-header-content { display:flex; flex-wrap:wrap; align-items:center; gap:4px 16px; padding:10px 16px; background:#0a0e17; border-bottom:1px solid #1a2332; }' +
  '.pm-header-content .pm-title { flex-shrink:0; }' +
  '.pm-header-content .pm-subtitle { flex-basis:100%; order:3; margin-top:4px; }' +
  '.pm-header-meta { display:flex; align-items:center; gap:12px; font-size:10px; color:#667788; margin-left:auto; }' +
  '.pm-classification-banner { background:#cc0000; color:#fff; text-align:center; padding:4px 0; font-size:10px; font-weight:bold; letter-spacing:3px; font-family:monospace; }' +

  '.pm-filter-bar { display:flex; align-items:center; gap:8px; padding:8px 0; margin-bottom:8px; flex-wrap:wrap; }' +
  '.pm-filter-btn { background:transparent; border:1px solid #1a2332; color:#c8d6e5; padding:4px 10px; font-size:10px; text-transform:uppercase; letter-spacing:1px; cursor:pointer; font-family:monospace; border-radius:3px; }' +
  '.pm-filter-btn:hover { background:#111820; }' +
  '.pm-filter-btn.active { background:#0d2137; border-color:#00bfff; color:#00e5ff; }' +
  '.pm-filter-label { font-size:10px; color:#667788; text-transform:uppercase; letter-spacing:1px; font-family:monospace; }' +

  '.pm-section-header { font-size:13px; color:#00ff88; text-transform:uppercase; letter-spacing:2px; padding:12px 0 8px; font-family:monospace; border-bottom:1px solid #1a2332; margin-bottom:12px; }' +
  '.pm-section-sub { font-size:11px; color:#00e5ff; text-transform:uppercase; letter-spacing:1px; padding:10px 0 6px; font-family:monospace; }' +
  '.pm-subsection-title { font-size:11px; color:#00e5ff; text-transform:uppercase; letter-spacing:1px; padding:10px 0 8px; font-family:monospace; border-bottom:1px solid #111820; margin-bottom:8px; }' +
  '.pm-label-sm { font-size:10px; color:#667788; text-transform:uppercase; letter-spacing:1px; }' +

  '.pm-alert-sev { display:inline-block; padding:2px 6px; border-radius:2px; font-size:9px; font-weight:bold; text-transform:uppercase; color:#fff; min-width:50px; text-align:center; font-family:monospace; }' +
  '.pm-alert-id { font-size:11px; color:#8899aa; font-family:monospace; margin-right:8px; }' +
  '.pm-alert-msg { font-size:11px; color:#c8d6e5; flex:1; }' +
  '.pm-alert-count { font-size:10px; color:#00e5ff; margin-left:8px; }' +
  '.pm-alert-line { display:flex; align-items:center; gap:8px; padding:6px 0; border-bottom:1px solid #111820; font-size:11px; }' +
  '.pm-alert-box-title { font-size:11px; color:#ff6600; text-transform:uppercase; letter-spacing:1px; padding:8px 12px; background:#1a1000; border:1px solid #4d3300; border-radius:4px; margin-bottom:8px; font-family:monospace; }' +

  '.pm-stat-row { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:12px; }' +
  '.pm-stat-box { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:12px; flex:1; min-width:120px; text-align:center; }' +
  '.pm-stat-value { font-size:24px; font-weight:bold; font-family:monospace; }' +
  '.pm-stat-label { font-size:10px; color:#667788; text-transform:uppercase; letter-spacing:1px; margin-top:4px; font-family:monospace; }' +
  '.pm-stat-card { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:14px; text-align:center; flex:1; min-width:100px; }' +
  '.pm-stat-val { font-size:28px; font-weight:bold; color:#00ff88; font-family:monospace; }' +

  '.pm-metric-card { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:12px; text-align:center; }' +
  '.pm-metric-value { font-size:28px; font-weight:bold; font-family:monospace; }' +
  '.pm-metric-label { font-size:10px; color:#667788; text-transform:uppercase; letter-spacing:1px; margin-top:4px; font-family:monospace; }' +
  '.pm-metric-unit { font-size:14px; color:#667788; margin-left:4px; }' +

  '.pm-kpi-trend { font-size:11px; margin-top:4px; font-family:monospace; }' +

  '.pm-progress-fill { height:100%; border-radius:3px; transition:width 0.3s; }' +
  '.pm-progress-label { font-size:10px; color:#c8d6e5; margin-left:6px; font-family:monospace; }' +
  '.pm-progress-text { font-size:10px; color:#8899aa; font-family:monospace; }' +

  '.pm-domain-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(200px,1fr)); gap:10px; margin-bottom:12px; }' +
  '.pm-domain-card { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:10px; display:flex; align-items:center; gap:10px; }' +
  '.pm-domain-card:hover { border-color:#2a3a4a; }' +
  '.pm-domain-dot { width:10px; height:10px; border-radius:50%; flex-shrink:0; }' +
  '.pm-domain-info { flex:1; }' +
  '.pm-domain-name { font-size:11px; color:#c8d6e5; text-transform:uppercase; letter-spacing:1px; font-family:monospace; }' +
  '.pm-domain-text { font-size:10px; margin-top:2px; }' +

  '.pm-mission-row { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:10px 14px; margin-bottom:6px; }' +
  '.pm-mission-row:hover { border-color:#2a3a4a; }' +
  '.pm-mission-top { display:flex; align-items:center; justify-content:space-between; margin-bottom:6px; }' +
  '.pm-mission-name { font-size:12px; color:#00ff88; text-transform:uppercase; letter-spacing:1px; font-family:monospace; }' +
  '.pm-mission-type { font-size:10px; color:#667788; text-transform:uppercase; margin-left:8px; }' +
  '.pm-mission-status { font-size:10px; font-weight:bold; text-transform:uppercase; font-family:monospace; }' +
  '.pm-mission-pct { font-size:10px; color:#8899aa; margin-top:4px; font-family:monospace; }' +

  '.pm-clocks-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(120px,1fr)); gap:8px; margin-bottom:12px; }' +
  '.pm-clock-item { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:8px; text-align:center; font-family:monospace; font-size:11px; color:#c8d6e5; }' +

  '.pm-spark-row { display:flex; align-items:center; gap:8px; padding:4px 0; }' +
  '.pm-spark-label { font-size:10px; color:#667788; text-transform:uppercase; letter-spacing:1px; min-width:80px; font-family:monospace; }' +
  '.pm-spark-canvas { background:transparent; }' +

  '.pm-defcon-btns { display:flex; gap:4px; margin-bottom:8px; }' +

  '.pm-sector-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(180px,1fr)); gap:10px; margin-bottom:12px; }' +
  '.pm-sector-breakdown { margin-top:8px; }' +
  '.pm-sector-health-bar { height:6px; background:#1a2332; border-radius:3px; overflow:hidden; margin-top:4px; }' +
  '.pm-sector-health-fill { height:100%; border-radius:3px; transition:width 0.3s; }' +
  '.pm-sector-health-text { font-size:10px; margin-top:2px; font-family:monospace; }' +
  '.pm-sector-stats { display:flex; align-items:center; gap:4px; font-size:10px; color:#8899aa; font-family:monospace; }' +
  '.pm-sector-affected { color:#ff6600; font-weight:bold; }' +
  '.pm-sector-sep { color:#334455; }' +
  '.pm-sector-total { color:#667788; }' +
  '.pm-sector-bar-bg { height:6px; background:#1a2332; border-radius:3px; overflow:hidden; margin-top:4px; }' +
  '.pm-sector-bar { height:100%; border-radius:3px; transition:width 0.5s; background:#00ff88; }' +
  '.pm-sector-pct { font-size:10px; color:#8899aa; margin-top:2px; font-family:monospace; text-align:right; }' +

  '.pm-twin-search { margin-bottom:10px; }' +
  '.pm-dep-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:8px; }' +
  '.pm-dep-col { }' +
  '.pm-dep-hdr { font-size:10px; color:#00e5ff; text-transform:uppercase; letter-spacing:1px; padding-bottom:6px; border-bottom:1px solid #1a2332; margin-bottom:6px; font-family:monospace; }' +
  '.pm-dep-item-name { font-size:11px; color:#c8d6e5; margin-right:6px; }' +
  '.pm-dep-item-sector { font-size:10px; color:#667788; }' +
  '.pm-dep-none { font-size:11px; color:#334455; font-style:italic; padding:4px 0; }' +

  '.pm-sim-controls { display:flex; gap:12px; align-items:flex-end; flex-wrap:wrap; margin-bottom:12px; }' +
  '.pm-sim-field { display:flex; flex-direction:column; gap:4px; }' +
  '.pm-sim-results { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:14px; margin-top:10px; }' +
  '.pm-sim-impact { display:flex; gap:16px; margin-top:10px; }' +
  '.pm-sim-impact-item { flex:1; text-align:center; background:#080c14; border:1px solid #1a2332; border-radius:4px; padding:12px; }' +
  '.pm-sim-impact-val { font-size:28px; font-weight:bold; font-family:monospace; }' +
  '.pm-sim-impact-label { font-size:10px; color:#667788; text-transform:uppercase; letter-spacing:1px; margin-top:4px; font-family:monospace; }' +

  '.pm-cascade-timeline { padding:8px 0; }' +
  '.pm-cascade-timeline-container { margin-top:10px; padding:10px; background:#080c14; border:1px solid #1a2332; border-radius:4px; }' +
  '.pm-cascade-event { display:flex; align-items:center; gap:8px; padding:6px 10px; margin-bottom:4px; background:#0d1117; border-radius:3px; }' +
  '.pm-cascade-time { font-size:10px; color:#00e5ff; font-family:monospace; min-width:60px; }' +
  '.pm-cascade-node { font-size:11px; color:#c8d6e5; font-family:monospace; }' +
  '.pm-cascade-impact { font-size:10px; font-family:monospace; }' +
  '.pm-cascade-cause { font-size:10px; color:#8899aa; margin-left:auto; }' +
  '.pm-cascade-sector { font-size:10px; color:#667788; }' +
  '.pm-cascade-controls { display:flex; gap:12px; align-items:flex-end; flex-wrap:wrap; margin-bottom:12px; }' +
  '.pm-cascade-ctrl-group { display:flex; flex-direction:column; gap:4px; }' +

  '.pm-comparison { margin-top:12px; }' +
  '.pm-comparison-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:12px; }' +
  '.pm-comp-panel { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:12px; }' +
  '.pm-comp-title { font-size:11px; text-transform:uppercase; letter-spacing:1px; margin-bottom:8px; font-family:monospace; font-weight:bold; }' +
  '.pm-comp-stat { font-size:11px; color:#c8d6e5; padding:2px 0; }' +
  '.pm-comp-delta { font-size:12px; font-weight:bold; text-align:center; padding:8px; background:#0d1117; border:1px solid #1a2332; border-radius:4px; font-family:monospace; }' +

  '.pm-pop-impact { margin-top:10px; padding:10px; background:#0d1117; border:1px solid #1a2332; border-radius:4px; }' +

  '.pm-exposure-bar-wrap { height:6px; background:#1a2332; border-radius:3px; overflow:hidden; flex:1; }' +
  '.pm-exposure-bar { height:100%; border-radius:3px; }' +
  '.pm-exposure-val { font-size:11px; font-weight:bold; font-family:monospace; min-width:30px; text-align:right; }' +
  '.pm-exposure-factor { font-size:11px; color:#c8d6e5; padding:2px 0; display:flex; align-items:center; gap:8px; }' +

  '.pm-factor-name { font-size:11px; color:#c8d6e5; min-width:100px; }' +
  '.pm-factor-bar-wrap { height:6px; background:#1a2332; border-radius:3px; overflow:hidden; flex:1; }' +
  '.pm-factor-bar { height:100%; border-radius:3px; }' +
  '.pm-factor-score { font-size:10px; color:#8899aa; font-family:monospace; min-width:40px; text-align:right; }' +

  '.pm-terrain-bottom { margin-top:12px; }' +
  '.pm-svc-bar-row { display:flex; align-items:center; gap:8px; padding:3px 0; }' +
  '.pm-svc-bar-label { font-size:10px; color:#c8d6e5; min-width:80px; text-transform:uppercase; font-family:monospace; }' +
  '.pm-svc-bar-track { height:8px; background:#1a2332; border-radius:4px; overflow:hidden; flex:1; }' +
  '.pm-svc-bar-fill { height:100%; border-radius:4px; }' +
  '.pm-svc-bar-count { font-size:10px; color:#8899aa; font-family:monospace; min-width:30px; text-align:right; }' +
  '.pm-svc-badge { display:inline-block; padding:2px 6px; background:#111820; border:1px solid #1a2332; border-radius:3px; font-size:9px; color:#8899aa; margin:2px; font-family:monospace; }' +
  '.pm-svc-cell { padding:4px 8px; }' +
  '.pm-heat-cell { padding:4px 8px; font-size:11px; text-align:center; font-family:monospace; color:#c8d6e5; border:1px solid #111820; }' +

  '.pm-path-controls { display:flex; gap:8px; align-items:flex-end; margin-bottom:12px; flex-wrap:wrap; }' +
  '.pm-path-field { display:flex; flex-direction:column; gap:4px; }' +
  '.pm-path-arrow { color:#00ff88; font-size:16px; padding-top:14px; }' +
  '.pm-path-result { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:12px; margin-bottom:8px; }' +
  '.pm-path-meta { font-size:10px; color:#667788; margin-bottom:8px; display:flex; gap:12px; }' +
  '.pm-path-chain { }' +
  '.pm-path-hop { background:#080c14; border:1px solid #1a2332; border-radius:4px; padding:10px; margin-bottom:4px; }' +
  '.pm-path-hop-num { font-size:9px; color:#00e5ff; text-transform:uppercase; letter-spacing:1px; font-family:monospace; }' +
  '.pm-path-hop-name { font-size:12px; color:#c8d6e5; margin-top:2px; }' +
  '.pm-path-hop-action { font-size:10px; color:#ffaa00; margin-top:2px; }' +
  '.pm-path-hop-sector { font-size:10px; color:#667788; margin-top:2px; }' +
  '.pm-path-connector { text-align:center; color:#334455; font-size:12px; padding:2px 0; }' +

  '.pm-sigint-grid { display:grid; grid-template-columns:2fr 1fr; gap:12px; }' +
  '.pm-sigint-feed { }' +
  '.pm-sigint-corr { }' +
  '.pm-sigint-bottom-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:12px; }' +
  '.pm-intel-scroll { max-height:400px; overflow-y:auto; }' +
  '.pm-intel-class-banner { padding:3px 8px; font-size:9px; font-weight:bold; text-align:center; letter-spacing:2px; font-family:monospace; color:#fff; border-radius:3px 3px 0 0; }' +
  '.pm-intel-header { display:flex; align-items:center; justify-content:space-between; padding:6px 10px; background:#0d1117; }' +
  '.pm-intel-type-badge { display:inline-block; padding:2px 6px; border-radius:2px; font-size:9px; font-weight:bold; text-transform:uppercase; font-family:monospace; }' +
  '.pm-intel-id { font-size:10px; color:#8899aa; font-family:monospace; }' +
  '.pm-intel-timestamp { font-size:10px; color:#667788; font-family:monospace; }' +
  '.pm-intel-source { font-size:10px; color:#667788; padding:4px 10px; font-family:monospace; }' +
  '.pm-intel-summary { font-size:11px; color:#c8d6e5; padding:6px 10px 8px; line-height:1.4; }' +
  '.pm-intel-scores { display:flex; gap:12px; padding:4px 10px 8px; }' +
  '.pm-intel-timeline { margin-top:10px; }' +
  '.pm-intel-product { margin-top:12px; padding:12px; background:#0d1117; border:1px solid #1a2332; border-radius:4px; }' +

  '.pm-score-item { font-size:10px; color:#8899aa; font-family:monospace; }' +

  '.pm-corr-alert { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:10px; margin-bottom:6px; cursor:pointer; }' +
  '.pm-corr-alert:hover { border-color:#2a3a4a; }' +
  '.pm-corr-header { display:flex; align-items:center; gap:8px; margin-bottom:6px; }' +
  '.pm-corr-id { font-size:10px; color:#8899aa; font-family:monospace; }' +
  '.pm-corr-confidence { font-size:11px; font-weight:bold; font-family:monospace; }' +
  '.pm-corr-title { font-size:12px; color:#c8d6e5; margin-bottom:4px; }' +
  '.pm-corr-sources { display:flex; gap:4px; flex-wrap:wrap; margin-bottom:6px; }' +
  '.pm-corr-src-label { font-size:9px; color:#667788; text-transform:uppercase; letter-spacing:1px; margin-right:4px; }' +
  '.pm-corr-src-tag { display:inline-block; padding:2px 6px; background:#111820; border:1px solid #1a2332; border-radius:3px; font-size:9px; color:#00e5ff; font-family:monospace; }' +
  '.pm-corr-timestamp { font-size:10px; color:#667788; font-family:monospace; margin-top:4px; }' +
  '.pm-corr-action { background:#080c14; border:1px solid #1a2332; border-radius:4px; padding:8px 10px; margin-top:6px; }' +
  '.pm-corr-action-label { font-size:9px; color:#ffaa00; text-transform:uppercase; letter-spacing:1px; margin-bottom:4px; font-family:monospace; }' +
  '.pm-corr-action-text { font-size:11px; color:#c8d6e5; }' +
  '.pm-corr-expand-btn { background:transparent; border:1px solid #1a2332; color:#00e5ff; padding:3px 8px; font-size:9px; text-transform:uppercase; letter-spacing:1px; cursor:pointer; font-family:monospace; border-radius:3px; margin-top:6px; }' +
  '.pm-corr-expand-btn:hover { background:#111820; border-color:#00e5ff; }' +

  '.pm-timeline-connector { width:2px; height:16px; background:#1a2332; margin:0 auto; }' +
  '.pm-timeline-container { padding:10px 0; }' +
  '.pm-timeline-content { padding:8px 12px; background:#0d1117; border:1px solid #1a2332; border-radius:4px; margin-left:20px; }' +
  '.pm-timeline-label { font-size:11px; color:#c8d6e5; }' +
  '.pm-timeline-labels { display:flex; justify-content:space-between; font-size:9px; color:#667788; font-family:monospace; padding:4px 0; }' +
  '.pm-timeline-track { position:relative; height:30px; background:#111820; border-radius:4px; overflow:hidden; }' +
  '.pm-timeline-detail { padding:10px; background:#0d1117; border:1px solid #1a2332; border-radius:4px; margin-top:8px; }' +
  '.pm-timeline-detail-inner { padding:8px 12px; margin-bottom:6px; background:#080c14; border-radius:3px; }' +

  '.pm-analyst-workspace { padding:10px; background:#080c14; border:1px solid #1a2332; border-radius:4px; }' +

  '.pm-checkbox-group { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:8px; }' +
  '.pm-checkbox-label { display:flex; align-items:center; gap:4px; font-size:11px; color:#c8d6e5; cursor:pointer; padding:4px 8px; background:#0d1117; border:1px solid #1a2332; border-radius:3px; font-family:monospace; }' +
  '.pm-checkbox-label:hover { border-color:#2a3a4a; }' +
  '.pm-checkbox-row { display:flex; gap:6px; flex-wrap:wrap; margin-bottom:8px; }' +

  '.pm-form-row { display:flex; gap:12px; align-items:flex-end; flex-wrap:wrap; margin-bottom:10px; }' +
  '.pm-radio-group { display:flex; flex-direction:column; gap:6px; margin-bottom:10px; }' +
  '.pm-radio-label { display:flex; align-items:center; gap:8px; font-size:11px; color:#c8d6e5; cursor:pointer; padding:8px 12px; background:#0d1117; border:1px solid #1a2332; border-radius:4px; font-family:monospace; }' +
  '.pm-radio-label:hover { border-color:#2a3a4a; }' +
  '.pm-radio-desc { font-size:10px; color:#667788; margin-left:20px; margin-top:2px; }' +
  '.pm-range { width:100%; accent-color:#00ff88; }' +
  '.pm-slider { width:100%; accent-color:#00ff88; }' +

  '.pm-predict-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(280px,1fr)); gap:10px; }' +
  '.pm-predict-card-header { display:flex; align-items:center; justify-content:space-between; margin-bottom:6px; }' +
  '.pm-predict-horizon-badge { display:inline-block; padding:2px 6px; border-radius:2px; font-size:9px; font-weight:bold; color:#000; font-family:monospace; }' +
  '.pm-predict-status { font-size:10px; font-weight:bold; text-transform:uppercase; font-family:monospace; }' +
  '.pm-predict-name { font-size:12px; color:#c8d6e5; margin-bottom:6px; }' +
  '.pm-predict-ring { width:60px; height:60px; border-radius:50%; border:3px solid #1a2332; display:flex; align-items:center; justify-content:center; margin:8px auto; font-size:16px; font-weight:bold; font-family:monospace; }' +
  '.pm-predict-detail { background:#080c14; border:1px solid #1a2332; border-radius:4px; padding:8px 10px; margin-top:6px; }' +
  '.pm-predict-field { font-size:10px; color:#c8d6e5; padding:2px 0; }' +
  '.pm-predict-expand { background:transparent; border:1px solid #1a2332; color:#00e5ff; padding:3px 8px; font-size:9px; text-transform:uppercase; letter-spacing:1px; cursor:pointer; font-family:monospace; border-radius:3px; margin-top:6px; }' +
  '.pm-predict-expand:hover { background:#111820; border-color:#00e5ff; }' +

  '.pm-accuracy-bar { display:flex; gap:12px; margin-bottom:10px; }' +
  '.pm-accuracy-item { display:flex; align-items:center; gap:6px; }' +
  '.pm-accuracy-label { font-size:10px; color:#667788; text-transform:uppercase; font-family:monospace; }' +
  '.pm-accuracy-value { font-size:14px; font-weight:bold; font-family:monospace; }' +
  '.pm-accuracy-trend { font-size:10px; font-family:monospace; }' +

  '.pm-prob-bar-container { height:8px; background:#1a2332; border-radius:4px; overflow:hidden; flex:1; }' +
  '.pm-prob-bar { height:100%; border-radius:4px; }' +
  '.pm-risk-badge { display:inline-block; padding:2px 8px; border-radius:3px; font-size:9px; font-weight:bold; text-transform:uppercase; font-family:monospace; }' +

  '.pm-whatif-panel { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:14px; margin-bottom:12px; }' +
  '.pm-whatif-inputs { display:flex; flex-direction:column; gap:10px; }' +
  '.pm-whatif-output { margin-top:10px; }' +
  '.pm-whatif-result { background:#080c14; border:1px solid #1a2332; border-radius:4px; padding:14px; }' +
  '.pm-whatif-result-title { font-size:11px; color:#00ff88; text-transform:uppercase; letter-spacing:1px; margin-bottom:8px; font-family:monospace; }' +
  '.pm-whatif-scenario-desc { font-size:11px; color:#c8d6e5; margin-bottom:8px; line-height:1.4; }' +
  '.pm-whatif-metrics { display:grid; grid-template-columns:repeat(auto-fill,minmax(160px,1fr)); gap:10px; margin-top:8px; }' +
  '.pm-whatif-assessment { margin-top:10px; padding:10px; background:#0d1117; border:1px solid #1a2332; border-radius:4px; font-size:11px; color:#c8d6e5; line-height:1.4; }' +

  '.pm-product-buttons { display:flex; gap:6px; flex-wrap:wrap; margin-bottom:10px; }' +
  '.pm-product-output { margin-top:8px; }' +
  '.pm-product-placeholder { font-size:11px; color:#667788; padding:20px; text-align:center; background:#080c14; border:1px solid #1a2332; border-radius:4px; font-style:italic; }' +

  '.pm-report-template { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:14px; font-family:monospace; }' +
  '.pm-report-banner { padding:4px 0; text-align:center; font-size:10px; font-weight:bold; letter-spacing:2px; color:#fff; font-family:monospace; }' +
  '.pm-report-title { font-size:13px; color:#c8d6e5; text-align:center; text-transform:uppercase; letter-spacing:2px; padding:8px 0; font-weight:bold; }' +
  '.pm-report-line { font-size:11px; color:#c8d6e5; padding:2px 0; }' +
  '.pm-report-hr { border:none; border-top:1px solid #1a2332; margin:8px 0; }' +
  '.pm-report-body { font-size:11px; color:#c8d6e5; line-height:1.5; padding:4px 0; }' +
  '.pm-report-output { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:14px; font-family:monospace; }' +
  '.pm-report-classification { text-align:center; font-size:10px; font-weight:bold; color:#ff0040; letter-spacing:2px; padding:6px 0; background:#1a0008; border:1px solid #4d0015; border-radius:3px; margin-bottom:8px; font-family:monospace; }' +
  '.pm-report-type { font-size:12px; color:#00ff88; text-align:center; text-transform:uppercase; letter-spacing:2px; padding:6px 0; margin-bottom:8px; font-family:monospace; }' +
  '.pm-report-section { font-size:11px; color:#00e5ff; text-transform:uppercase; letter-spacing:1px; padding:6px 0 4px; margin-top:8px; font-family:monospace; }' +
  '.pm-report-divider { border-top:1px solid #1a2332; margin:8px 0; }' +
  '.pm-report-footer { font-size:10px; color:#ff0040; text-align:center; padding:6px 0; margin-top:8px; border-top:1px solid #1a2332; font-family:monospace; letter-spacing:1px; }' +
  '.pm-report-gen { margin-top:10px; }' +

  '.pm-engage-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; }' +
  '.pm-engage-target { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:12px; }' +
  '.pm-engage-collateral { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:12px; }' +
  '.pm-target-detail { margin-top:8px; }' +
  '.pm-target-info { padding:8px; background:#080c14; border:1px solid #1a2332; border-radius:4px; }' +
  '.pm-target-name { font-size:12px; color:#00ff88; text-transform:uppercase; letter-spacing:1px; font-family:monospace; margin-bottom:4px; }' +
  '.pm-target-field { font-size:10px; color:#c8d6e5; padding:2px 0; }' +

  '.pm-phase-timeline { display:flex; align-items:center; gap:0; overflow-x:auto; padding:10px 0; }' +
  '.pm-phase-step { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:10px; text-align:center; min-width:120px; flex-shrink:0; }' +
  '.pm-phase-icon { font-size:20px; margin-bottom:4px; }' +
  '.pm-phase-name { font-size:10px; color:#c8d6e5; text-transform:uppercase; letter-spacing:1px; font-family:monospace; }' +
  '.pm-phase-duration { font-size:9px; color:#667788; margin-top:2px; font-family:monospace; }' +
  '.pm-phase-connector { color:#334455; font-size:14px; padding:0 4px; flex-shrink:0; }' +

  '.pm-roe-grid { display:flex; flex-direction:column; gap:6px; }' +
  '.pm-roe-icon { font-size:14px; margin-right:6px; }' +
  '.pm-roe-text { display:flex; align-items:flex-start; gap:4px; }' +
  '.pm-roe-rule { font-size:11px; color:#c8d6e5; font-weight:bold; }' +
  '.pm-roe-desc { font-size:10px; color:#8899aa; margin-left:20px; margin-top:2px; }' +

  '.pm-op-timeline { margin-top:10px; }' +
  '.pm-op-tl-item { display:flex; align-items:center; gap:8px; margin-bottom:4px; }' +
  '.pm-op-tl-bar { height:20px; border-radius:3px; display:flex; align-items:center; padding:0 8px; min-width:40px; }' +
  '.pm-op-tl-days { font-size:9px; color:#fff; font-family:monospace; white-space:nowrap; }' +
  '.pm-op-total { font-size:11px; color:#ffaa00; text-transform:uppercase; letter-spacing:1px; margin-top:8px; font-family:monospace; }' +

  '.pm-cde-metrics { margin-top:10px; display:grid; grid-template-columns:repeat(auto-fill,minmax(180px,1fr)); gap:10px; }' +

  '.pm-wargame-scenarios { display:flex; flex-direction:column; gap:8px; }' +
  '.pm-scenario-header { display:flex; align-items:center; justify-content:space-between; margin-bottom:6px; }' +
  '.pm-scenario-name { font-size:12px; color:#c8d6e5; text-transform:uppercase; letter-spacing:1px; font-family:monospace; }' +
  '.pm-scenario-diff { display:inline-block; padding:2px 6px; border-radius:3px; font-size:9px; font-weight:bold; text-transform:uppercase; font-family:monospace; }' +
  '.pm-scenario-desc { font-size:11px; color:#8899aa; margin-bottom:6px; }' +
  '.pm-scenario-meta { display:flex; gap:12px; font-size:10px; color:#667788; }' +

  '.pm-team-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(180px,1fr)); gap:10px; margin-bottom:12px; }' +
  '.pm-team-card { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:12px; text-align:center; border-top:3px solid #1a2332; }' +
  '.pm-team-icon { font-size:24px; margin-bottom:4px; }' +
  '.pm-team-name { font-size:11px; text-transform:uppercase; letter-spacing:1px; font-family:monospace; margin-bottom:4px; }' +
  '.pm-team-role { font-size:10px; color:#8899aa; }' +
  '.pm-team-desc { font-size:10px; color:#667788; margin-top:6px; }' +

  '.pm-exercise-controls { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:10px; }' +
  '.pm-exercise-status { padding:8px 12px; background:#0d1117; border:1px solid #1a2332; border-radius:4px; margin-bottom:10px; font-size:11px; color:#c8d6e5; font-family:monospace; }' +
  '.pm-exercise-timeline { }' +
  '.pm-ex-event { display:flex; align-items:flex-start; gap:8px; padding:6px 0; border-bottom:1px solid #111820; }' +
  '.pm-ex-event-time { font-size:10px; color:#00e5ff; font-family:monospace; min-width:60px; flex-shrink:0; }' +
  '.pm-ex-event-marker { width:10px; height:10px; border-radius:50%; flex-shrink:0; margin-top:2px; }' +
  '.pm-ex-event-content { flex:1; }' +
  '.pm-ex-event-team { font-size:10px; font-weight:bold; font-family:monospace; }' +
  '.pm-ex-status-dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px; vertical-align:middle; }' +

  '.pm-ctrl-buttons { display:flex; gap:6px; margin-bottom:10px; }' +
  '.pm-ctrl-speed { display:flex; gap:4px; align-items:center; margin-bottom:8px; }' +
  '.pm-ctrl-inject { margin-top:8px; }' +
  '.pm-speed-btn { background:#111820; border:1px solid #1a2332; color:#c8d6e5; padding:4px 10px; font-size:10px; cursor:pointer; font-family:monospace; border-radius:3px; }' +
  '.pm-speed-btn:hover { border-color:#00ff88; color:#00ff88; }' +
  '.pm-speed-btn.active { background:#0d2137; border-color:#00ff88; color:#00ff88; }' +

  '.pm-scoring-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:12px; }' +
  '.pm-score-panel { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:12px; border-top:3px solid; }' +
  '.pm-score-team-name { font-size:12px; text-transform:uppercase; letter-spacing:2px; font-family:monospace; margin-bottom:4px; }' +
  '.pm-score-total { font-size:28px; font-weight:bold; font-family:monospace; margin-bottom:8px; }' +
  '.pm-score-breakdown { font-size:10px; color:#8899aa; }' +
  '.pm-score-item-row { display:flex; justify-content:space-between; padding:2px 0; font-family:monospace; }' +

  '.pm-aar-panel { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:14px; margin-top:10px; }' +
  '.pm-aar-section { margin-bottom:12px; }' +
  '.pm-aar-title { font-size:11px; color:#00e5ff; text-transform:uppercase; letter-spacing:1px; margin-bottom:6px; font-family:monospace; border-bottom:1px solid #111820; padding-bottom:4px; }' +
  '.pm-aar-item { font-size:11px; color:#c8d6e5; padding:3px 0; line-height:1.4; }' +

  '.pm-modal-header { display:flex; align-items:center; justify-content:space-between; padding:12px 16px; background:#111820; border-bottom:1px solid #1a2332; }' +
  '.pm-modal-close { background:transparent; border:none; color:#667788; font-size:20px; cursor:pointer; padding:0 4px; }' +
  '.pm-modal-close:hover { color:#ff4444; }' +
  '.pm-modal-body { padding:16px; max-height:70vh; overflow-y:auto; }' +

  '.pm-ci-filter-bar { display:flex; gap:6px; flex-wrap:wrap; margin-bottom:10px; }' +
  '.pm-ci-reports { display:flex; flex-direction:column; gap:8px; }' +
  '.pm-ci-report-card { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:12px; }' +
  '.pm-ci-report-card:hover { border-color:#2a3a4a; }' +
  '.pm-ci-report-header { display:flex; align-items:center; gap:8px; margin-bottom:6px; }' +
  '.pm-ci-report-id { font-size:10px; color:#8899aa; font-family:monospace; }' +
  '.pm-ci-report-title { font-size:12px; color:#c8d6e5; margin-bottom:4px; }' +
  '.pm-ci-report-date { font-size:10px; color:#667788; font-family:monospace; }' +
  '.pm-ci-report-summary { font-size:11px; color:#8899aa; line-height:1.4; margin-bottom:6px; }' +
  '.pm-ci-report-full { background:#080c14; border:1px solid #1a2332; border-radius:4px; padding:10px; margin-top:6px; }' +
  '.pm-ci-report-fulltext { font-size:11px; color:#c8d6e5; line-height:1.5; white-space:pre-wrap; font-family:monospace; }' +

  '.pm-deception-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(260px,1fr)); gap:10px; }' +
  '.pm-deception-card { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:12px; }' +
  '.pm-deception-card:hover { border-color:#2a3a4a; }' +
  '.pm-deception-card-header { display:flex; align-items:center; justify-content:space-between; margin-bottom:6px; }' +
  '.pm-deception-name { font-size:12px; color:#00ff88; text-transform:uppercase; letter-spacing:1px; font-family:monospace; }' +
  '.pm-deception-type { font-size:10px; color:#00e5ff; text-transform:uppercase; margin-bottom:4px; font-family:monospace; }' +
  '.pm-deception-detail { font-size:10px; color:#8899aa; padding:2px 0; }' +
  '.pm-deception-desc { font-size:11px; color:#667788; margin-top:6px; line-height:1.4; }' +

  '.pm-deploy-status { font-size:11px; color:#c8d6e5; padding:8px 0; font-family:monospace; }' +

  '.pm-containment-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(200px,1fr)); gap:10px; }' +
  '.pm-contain-icon { font-size:20px; margin-bottom:4px; }' +
  '.pm-contain-name { font-size:11px; color:#c8d6e5; text-transform:uppercase; letter-spacing:1px; font-family:monospace; margin-bottom:4px; }' +
  '.pm-contain-status { font-size:10px; color:#c8d6e5; margin-bottom:4px; }' +
  '.pm-contain-detail { font-size:10px; color:#8899aa; padding:1px 0; }' +
  '.pm-contain-scope { font-size:10px; color:#667788; margin-top:4px; }' +

  '.pm-response-log { max-height:300px; overflow-y:auto; background:#080c14; border:1px solid #1a2332; border-radius:4px; padding:10px; font-family:monospace; font-size:11px; }' +

  '.pm-playbook-list { display:flex; flex-direction:column; gap:8px; }' +
  '.pm-playbook-card { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:12px; }' +
  '.pm-playbook-card:hover { border-color:#2a3a4a; }' +
  '.pm-playbook-header { display:flex; align-items:center; justify-content:space-between; margin-bottom:6px; }' +
  '.pm-playbook-name { font-size:12px; color:#00ff88; text-transform:uppercase; letter-spacing:1px; font-family:monospace; }' +
  '.pm-playbook-team { font-size:10px; color:#8899aa; margin-bottom:4px; }' +
  '.pm-playbook-progress { display:flex; align-items:center; gap:8px; margin-bottom:6px; }' +
  '.pm-playbook-steps { font-size:10px; color:#667788; display:flex; flex-wrap:wrap; gap:4px 8px; }' +

  '.pm-killswitch-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(260px,1fr)); gap:10px; }' +
  '.pm-killswitch-warning { font-size:11px; color:#ff6600; text-align:center; padding:8px; background:#1a1000; border:1px solid #4d3300; border-radius:4px; margin-bottom:10px; font-family:monospace; }' +
  '.pm-ks-name { font-size:12px; color:#ff0040; text-transform:uppercase; letter-spacing:1px; font-family:monospace; margin-bottom:4px; }' +
  '.pm-ks-desc { font-size:11px; color:#c8d6e5; margin-bottom:6px; }' +
  '.pm-ks-status { font-size:10px; color:#8899aa; margin-bottom:6px; }' +
  '.pm-ks-confirm { background:#1a0008; border:1px solid #4d0015; border-radius:4px; padding:10px; margin-top:6px; }' +
  '.pm-ks-confirm-text { font-size:11px; color:#ff0040; margin-bottom:6px; font-family:monospace; }' +
  '.pm-ks-activated { background:#0a1a0a; border:1px solid #00ff88; border-radius:4px; padding:12px; text-align:center; }' +
  '.pm-ks-time { font-size:10px; color:#667788; font-family:monospace; margin-top:4px; }' +

  '.pm-status-green { color:#00ff88; }' +
  '.pm-status-red { color:#ff0040; }' +
  '.pm-status-yellow { color:#ffaa00; }' +
  '.pm-status-dim { color:#667788; }' +

  '.pm-tl-dot { width:10px; height:10px; border-radius:50%; background:#00ff88; flex-shrink:0; margin-top:4px; }' +
  '.pm-tl-content { flex:1; }' +
  '.pm-tl-time { font-size:10px; color:#00e5ff; font-family:monospace; }' +
  '.pm-tl-action { font-size:11px; color:#c8d6e5; margin-top:2px; }' +
  '.pm-tl-tags { display:flex; gap:4px; flex-wrap:wrap; margin-top:4px; }' +
  '.pm-tl-detail { font-size:10px; color:#667788; padding:2px 0; }' +

  '.pm-dep-tree { }' +
  '.pm-dep-category { background:#0d1117; border:1px solid #1a2332; border-radius:4px; margin-bottom:6px; cursor:pointer; }' +
  '.pm-dep-category:hover { border-color:#2a3a4a; }' +
  '.pm-dep-cat-body { padding:8px 12px; }' +
  '.pm-dep-name { font-size:11px; color:#c8d6e5; font-family:monospace; }' +
  '.pm-dep-ver { font-size:10px; color:#667788; font-family:monospace; margin-left:6px; }' +
  '.pm-dep-vendor { font-size:10px; color:#8899aa; margin-left:6px; }' +
  '.pm-dep-children { margin-left:16px; margin-top:4px; }' +
  '.pm-dep-child { font-size:10px; color:#667788; padding:1px 0; }' +

  '.pm-sc-search { margin-bottom:8px; }' +
  '.pm-license-bar { display:flex; height:20px; border-radius:4px; overflow:hidden; margin-bottom:8px; }' +
  '.pm-license-seg { display:flex; align-items:center; justify-content:center; font-size:8px; color:#fff; font-family:monospace; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; padding:0 4px; }' +

  '.pm-bda-form { margin-bottom:12px; }' +
  '.pm-bda-quadrant { display:grid; grid-template-columns:repeat(auto-fill,minmax(140px,1fr)); gap:10px; margin-bottom:12px; }' +
  '.pm-bda-quad-card { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:12px; text-align:center; }' +
  '.pm-bda-quad-label { font-size:10px; text-transform:uppercase; letter-spacing:1px; font-family:monospace; margin-bottom:4px; }' +
  '.pm-bda-quad-count { font-size:28px; font-weight:bold; font-family:monospace; }' +
  '.pm-bda-quad-pct { font-size:10px; color:#8899aa; font-family:monospace; margin-top:2px; }' +
  '.pm-bda-quad-ring { width:50px; height:50px; border-radius:50%; border:3px solid #1a2332; margin:6px auto 0; display:flex; align-items:center; justify-content:center; font-size:12px; font-weight:bold; font-family:monospace; }' +

  '.pm-attr-detail { background:#080c14; }' +
  '.pm-attr-detail-content { padding:10px; font-size:11px; color:#c8d6e5; }' +

  '.pm-recovery-timeline { margin-top:10px; }' +
  '.pm-rt-step { display:flex; align-items:flex-start; gap:10px; padding:8px 0; border-bottom:1px solid #111820; }' +
  '.pm-rt-marker { width:28px; height:28px; border-radius:50%; background:#0d2137; color:#00ff88; display:flex; align-items:center; justify-content:center; font-size:12px; font-weight:bold; flex-shrink:0; font-family:monospace; }' +
  '.pm-rt-content { flex:1; }' +
  '.pm-rt-name { font-size:11px; color:#c8d6e5; text-transform:uppercase; letter-spacing:1px; font-family:monospace; }' +
  '.pm-rt-time { font-size:10px; color:#00e5ff; font-family:monospace; margin-top:2px; }' +
  '.pm-rt-desc { font-size:10px; color:#8899aa; margin-top:2px; }' +

  '.pm-escalation-ladder { display:flex; flex-direction:column; gap:0; }' +
  '.pm-esc-number { font-size:10px; color:#ff6600; text-transform:uppercase; letter-spacing:2px; font-family:monospace; font-weight:bold; padding:8px 12px; background:#111820; border:1px solid #1a2332; border-bottom:none; }' +
  '.pm-esc-name { font-size:12px; color:#c8d6e5; padding:4px 12px; font-weight:bold; }' +
  '.pm-esc-desc { font-size:11px; color:#8899aa; padding:2px 12px; }' +
  '.pm-esc-approval { font-size:10px; color:#ffaa00; padding:2px 12px; font-family:monospace; }' +
  '.pm-esc-examples { font-size:10px; color:#667788; padding:2px 12px 8px; border-bottom:1px solid #1a2332; }' +
  '.pm-esc-connector { width:2px; height:12px; background:#1a2332; margin:0 auto; }' +

  '.pm-auth-check { color:#00ff88; font-weight:bold; }' +
  '.pm-auth-x { color:#ff0040; font-weight:bold; }' +
  '.pm-auth-cond { color:#ffaa00; font-size:9px; font-weight:bold; text-transform:uppercase; font-family:monospace; }' +

  '.pm-allied-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(240px,1fr)); gap:10px; }' +
  '.pm-allied-card { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:12px; }' +
  '.pm-allied-card:hover { border-color:#2a3a4a; }' +
  '.pm-allied-name { font-size:12px; color:#00ff88; text-transform:uppercase; letter-spacing:1px; font-family:monospace; margin-bottom:6px; }' +
  '.pm-allied-detail { font-size:10px; color:#c8d6e5; padding:2px 0; }' +
  '.pm-allied-expand-content { background:#080c14; border:1px solid #1a2332; border-radius:4px; padding:8px 10px; margin-top:6px; }' +
  '.pm-allied-expand-detail { font-size:10px; color:#8899aa; padding:2px 0; font-family:monospace; }' +

  '.pm-risk-benefit { margin-top:10px; padding:12px; background:#0d1117; border:1px solid #1a2332; border-radius:4px; }' +
  '.pm-rb-result { margin-top:10px; }' +
  '.pm-rb-ratio { font-size:14px; color:#ffaa00; font-weight:bold; font-family:monospace; margin-bottom:6px; }' +
  '.pm-risk-high { color:#ff0040; font-weight:bold; }' +

  '.pm-result-box { background:#0d1117; border:1px solid #1a2332; border-radius:4px; padding:12px; margin-top:8px; }' +
  '.pm-result-title { font-size:12px; color:#00ff88; text-transform:uppercase; letter-spacing:1px; margin-bottom:8px; font-family:monospace; }' +
  '.pm-result-detail { font-size:11px; color:#c8d6e5; padding:2px 0; }' +
  '.pm-result-success { background:#0a1a0a; border:1px solid #00aa55; border-radius:4px; padding:12px; color:#00ff88; font-size:11px; font-family:monospace; }' +
  '.pm-result-error { background:#1a0008; border:1px solid #660020; border-radius:4px; padding:12px; color:#ff0040; font-size:11px; font-family:monospace; }' +

  '.pm-prop-step { display:flex; align-items:center; gap:6px; padding:4px 0; font-size:11px; color:#c8d6e5; }' +
  '.pm-prop-step-label { font-size:10px; color:#00e5ff; font-family:monospace; font-weight:bold; }' +

  '.pm-aar-item { padding: 8px 12px; border-bottom: 1px solid #1a2332; font-size: 12px; color: #c8d6e5; line-height: 1.6; }' +
  '.pm-aar-panel { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; margin-top: 16px; }' +
  '.pm-aar-section { padding: 12px 16px; border-bottom: 1px solid #1a2332; }' +
  '.pm-aar-title { font-size: 11px; color: #00ff88; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 8px; font-weight: bold; }' +
  '.pm-accuracy-bar { display: flex; align-items: center; gap: 16px; padding: 8px 14px; background: #111820; border: 1px solid #1a2332; border-radius: 4px; margin-bottom: 12px; }' +
  '.pm-accuracy-item { display: flex; align-items: center; gap: 8px; }' +
  '.pm-accuracy-label { font-size: 10px; color: #667788; text-transform: uppercase; letter-spacing: 1px; }' +
  '.pm-accuracy-trend { font-size: 10px; }' +
  '.pm-accuracy-value { font-size: 14px; font-weight: bold; }' +
  '.pm-alert-box-title { font-size: 11px; color: #ffaa00; text-transform: uppercase; letter-spacing: 1px; padding: 8px 12px; background: rgba(255,170,0,0.08); border: 1px solid rgba(255,170,0,0.2); border-radius: 4px; margin-bottom: 8px; }' +
  '.pm-alert-count { font-size: 10px; color: #667788; margin-left: 8px; }' +
  '.pm-alert-id { font-size: 10px; color: #667788; font-family: monospace; min-width: 80px; }' +
  '.pm-alert-line { display: flex; align-items: center; gap: 8px; padding: 6px 12px; border-bottom: 1px solid #111820; font-size: 11px; color: #c8d6e5; }' +
  '.pm-alert-msg { font-size: 11px; color: #c8d6e5; flex: 1; }' +
  '.pm-alert-sev { font-size: 9px; font-weight: bold; color: #000; padding: 2px 6px; border-radius: 2px; text-transform: uppercase; min-width: 50px; text-align: center; display: inline-block; }' +
  '.pm-allied-card { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 14px; }' +
  '.pm-allied-card:hover { border-color: #2a3a4a; }' +
  '.pm-allied-detail { font-size: 11px; color: #8899aa; margin-bottom: 4px; }' +
  '.pm-allied-expand-content { padding: 10px 0; border-top: 1px solid #1a2332; margin-top: 8px; }' +
  '.pm-allied-expand-detail { font-size: 11px; color: #667788; margin-bottom: 4px; }' +
  '.pm-allied-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px; margin-top: 12px; }' +
  '.pm-allied-name { font-size: 13px; color: #00e5ff; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; font-weight: bold; }' +
  '.pm-analyst-workspace { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 14px; }' +
  '.pm-attr-detail { background: #080c14; }' +
  '.pm-attr-detail-content { padding: 12px 16px; font-size: 11px; color: #8899aa; line-height: 1.6; }' +
  '.pm-auth-check { color: #00ff88; font-weight: bold; font-size: 14px; }' +
  '.pm-auth-cond { color: #ffaa00; font-size: 9px; font-weight: bold; text-transform: uppercase; padding: 2px 6px; border: 1px solid #aa6600; border-radius: 2px; }' +
  '.pm-auth-x { color: #ff0040; font-weight: bold; font-size: 14px; }' +
  '.pm-bda-form { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 16px; margin-bottom: 16px; }' +
  '.pm-bda-quad-card { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 14px; text-align: center; }' +
  '.pm-bda-quad-count { font-size: 28px; font-weight: bold; margin-bottom: 4px; }' +
  '.pm-bda-quad-label { font-size: 10px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }' +
  '.pm-bda-quad-pct { font-size: 11px; color: #667788; margin-bottom: 8px; }' +
  '.pm-bda-quadrant { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px; margin-bottom: 16px; }' +
  '.pm-bda-quad-ring { width: 60px; height: 60px; border-radius: 50%; border: 3px solid currentColor; margin: 0 auto; display: flex; align-items: center; justify-content: center; opacity: 0.3; }' +
  '.pm-canvas { width: 100%; height: auto; display: block; background: #080c14; border: 1px solid #1a2332; border-radius: 4px; }' +
  '.pm-card-body { padding: 12px 14px; }' +
  '.pm-card-header { font-size: 11px; color: #00ff88; text-transform: uppercase; letter-spacing: 1px; padding: 8px 14px; border-left: 3px solid #00ff88; }' +
  '.pm-cascade-cause { font-size: 10px; color: #667788; }' +
  '.pm-cascade-controls { display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; margin-bottom: 16px; padding: 12px; background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; }' +
  '.pm-cascade-ctrl-group { display: flex; flex-direction: column; gap: 4px; }' +
  '.pm-cascade-event { padding: 8px 12px; border-bottom: 1px solid #111820; border-left: 3px solid #1a2332; display: flex; align-items: center; gap: 12px; }' +
  '.pm-cascade-impact { font-size: 11px; font-weight: bold; min-width: 60px; }' +
  '.pm-cascade-node { font-size: 11px; color: #c8d6e5; font-weight: bold; min-width: 120px; }' +
  '.pm-cascade-sector { font-size: 10px; color: #667788; }' +
  '.pm-cascade-time { font-size: 10px; color: #00e5ff; font-family: monospace; min-width: 60px; }' +
  '.pm-cascade-timeline { max-height: 300px; overflow-y: auto; background: #080c14; border: 1px solid #1a2332; border-radius: 4px; }' +
  '.pm-cascade-timeline-container { margin-top: 16px; }' +
  '.pm-cde-metrics { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; margin-top: 12px; }' +
  '.pm-center { text-align: center; }' +
  '.pm-checkbox-group { display: flex; flex-wrap: wrap; gap: 8px; margin: 8px 0; }' +
  '.pm-checkbox-label { display: flex; align-items: center; gap: 6px; font-size: 11px; color: #c8d6e5; cursor: pointer; padding: 4px 8px; border: 1px solid #1a2332; border-radius: 3px; background: #0d1117; }' +
  '.pm-checkbox-label:hover { border-color: #2a3a4a; }' +
  '.pm-checkbox-row { display: flex; flex-wrap: wrap; gap: 8px; margin: 8px 0; }' +
  '.pm-ci-filter-bar { display: flex; gap: 8px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }' +
  '.pm-ci-report-card { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 12px; margin-bottom: 8px; }' +
  '.pm-ci-report-card:hover { border-color: #2a3a4a; }' +
  '.pm-ci-report-date { font-size: 10px; color: #667788; }' +
  '.pm-ci-report-full { padding: 12px 0; border-top: 1px solid #1a2332; margin-top: 8px; }' +
  '.pm-ci-report-fulltext { font-size: 12px; color: #8899aa; line-height: 1.6; white-space: pre-wrap; }' +
  '.pm-ci-report-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }' +
  '.pm-ci-report-id { font-size: 10px; color: #00e5ff; font-family: monospace; }' +
  '.pm-ci-reports { margin-top: 12px; }' +
  '.pm-ci-report-summary { font-size: 11px; color: #8899aa; margin-bottom: 6px; line-height: 1.5; }' +
  '.pm-ci-report-title { font-size: 12px; color: #c8d6e5; font-weight: bold; margin-bottom: 4px; }' +
  '.pm-classification-banner { background: #cc0000; color: #fff; text-align: center; padding: 6px; font-size: 11px; font-weight: bold; letter-spacing: 4px; text-transform: uppercase; }' +
  '.pm-clock-item { text-align: center; padding: 8px; }' +
  '.pm-clocks-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 8px; margin: 12px 0; }' +
  '.pm-comparison { margin-top: 16px; }' +
  '.pm-comparison-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }' +
  '.pm-comp-delta { font-size: 12px; font-weight: bold; text-align: center; padding: 8px; background: #111820; border: 1px solid #1a2332; border-radius: 4px; margin-top: 8px; }' +
  '.pm-comp-panel { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 14px; }' +
  '.pm-comp-stat { font-size: 11px; color: #c8d6e5; margin-bottom: 4px; }' +
  '.pm-comp-title { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; font-weight: bold; }' +
  '.pm-contain-detail { font-size: 10px; color: #667788; margin-bottom: 2px; }' +
  '.pm-contain-icon { font-size: 20px; margin-bottom: 6px; }' +
  '.pm-containment-card { padding: 14px; background: #0d1117; border: 1px solid #1a2332; border-radius: 6px; }' +
  '.pm-contain-active { border-color: #00ff88; }' +
  '.pm-contain-standby { border-color: #eab30844; }' +
  '.pm-containment-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; margin-top: 12px; }' +
  '.pm-contain-name { font-size: 12px; color: #c8d6e5; font-weight: bold; margin-bottom: 4px; }' +
  '.pm-contain-scope { font-size: 10px; color: #00e5ff; text-transform: uppercase; margin-top: 4px; }' +
  '.pm-contain-status { font-size: 10px; color: #8899aa; margin-bottom: 4px; display: flex; align-items: center; gap: 6px; }' +
  '.pm-content { padding: 16px; flex: 1; overflow-y: auto; }' +
  '.pm-corr-action { padding: 10px 12px; background: #111820; border-top: 1px solid #1a2332; margin-top: 8px; border-radius: 0 0 4px 4px; }' +
  '.pm-corr-action-label { font-size: 9px; color: #00ff88; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px; }' +
  '.pm-corr-action-text { font-size: 11px; color: #c8d6e5; line-height: 1.5; }' +
  '.pm-corr-alert { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 12px; margin-bottom: 8px; cursor: pointer; }' +
  '.pm-corr-alert:hover { border-color: #2a3a4a; }' +
  '.pm-corr-confidence { font-size: 14px; font-weight: bold; }' +
  '.pm-corr-expand-btn { background: none; border: 1px solid #1a2332; color: #00e5ff; padding: 3px 10px; font-size: 9px; cursor: pointer; border-radius: 2px; text-transform: uppercase; letter-spacing: 1px; font-family: monospace; }' +
  '.pm-corr-expand-btn:hover { background: #1a2332; }' +
  '.pm-corr-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; }' +
  '.pm-corr-id { font-size: 10px; color: #00e5ff; font-family: monospace; }' +
  '.pm-corr-sources { display: flex; flex-wrap: wrap; gap: 6px; margin: 6px 0; align-items: center; }' +
  '.pm-corr-src-label { font-size: 9px; color: #667788; text-transform: uppercase; letter-spacing: 1px; }' +
  '.pm-corr-src-tag { font-size: 9px; color: #c8d6e5; background: #1a2332; padding: 2px 8px; border-radius: 2px; }' +
  '.pm-corr-timestamp { font-size: 10px; color: #667788; margin-top: 6px; }' +
  '.pm-corr-title { font-size: 12px; color: #c8d6e5; font-weight: bold; }' +
  '.pm-ctrl-buttons { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }' +
  '.pm-ctrl-inject { margin-top: 12px; padding: 12px; background: #111820; border: 1px solid #1a2332; border-radius: 4px; }' +
  '.pm-ctrl-speed { display: flex; gap: 4px; align-items: center; margin-bottom: 12px; }' +
  '.pm-deception-card { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 12px; }' +
  '.pm-deception-card:hover { border-color: #2a3a4a; }' +
  '.pm-deception-card-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }' +
  '.pm-deception-desc { font-size: 11px; color: #667788; margin-top: 6px; line-height: 1.4; }' +
  '.pm-deception-detail { font-size: 10px; color: #8899aa; margin-bottom: 3px; }' +
  '.pm-deception-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; margin-top: 12px; }' +
  '.pm-deception-name { font-size: 12px; color: #ffaa00; text-transform: uppercase; letter-spacing: 1px; font-weight: bold; }' +
  '.pm-deception-type { font-size: 10px; color: #00e5ff; text-transform: uppercase; margin-top: 4px; }' +
  '.pm-defcon-btns { display: flex; gap: 4px; margin: 8px 0; }' +
  '.pm-dep-cat-body { padding: 8px 12px; }' +
  '.pm-dep-category { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; margin-bottom: 8px; overflow: hidden; }' +
  '.pm-dep-child { font-size: 10px; color: #667788; padding: 2px 0 2px 16px; }' +
  '.pm-dep-children { margin-top: 4px; }' +
  '.pm-dep-col { flex: 1; min-width: 200px; }' +
  '.pm-dep-grid { display: flex; gap: 16px; margin-top: 12px; }' +
  '.pm-dep-hdr { font-size: 10px; color: #00ff88; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; padding-bottom: 4px; border-bottom: 1px solid #1a2332; }' +
  '.pm-dep-item-name { font-size: 11px; color: #c8d6e5; }' +
  '.pm-dep-item-sector { font-size: 10px; color: #667788; margin-left: 8px; }' +
  '.pm-deploy-status { font-size: 11px; color: #8899aa; margin-bottom: 12px; }' +
  '.pm-dep-name { font-size: 11px; color: #c8d6e5; font-weight: bold; }' +
  '.pm-dep-none { font-size: 11px; color: #667788; font-style: italic; }' +
  '.pm-dep-tree { margin-top: 12px; }' +
  '.pm-dep-vendor { font-size: 10px; color: #667788; margin-left: 8px; }' +
  '.pm-dep-ver { font-size: 10px; color: #00e5ff; margin-left: 6px; font-family: monospace; }' +
  '.pm-domain-card { display: flex; align-items: center; gap: 10px; padding: 10px 12px; background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; }' +
  '.pm-domain-card:hover { border-color: #2a3a4a; }' +
  '.pm-domain-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }' +
  '.pm-domain-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 8px; margin: 12px 0; }' +
  '.pm-domain-info { flex: 1; }' +
  '.pm-domain-name { font-size: 11px; color: #c8d6e5; text-transform: uppercase; letter-spacing: 1px; }' +
  '.pm-domain-text { font-size: 10px; }' +
  '.pm-dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; }' +
  '.pm-engage-collateral { margin-top: 12px; padding: 12px; background: #111820; border: 1px solid #1a2332; border-radius: 4px; }' +
  '.pm-engage-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }' +
  '.pm-engage-target { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 14px; }' +
  '.pm-escalation-ladder { margin-top: 12px; }' +
  '.pm-esc-approval { font-size: 10px; color: #ff6600; margin-top: 4px; }' +
  '.pm-esc-connector { width: 2px; height: 16px; background: #1a2332; margin: 0 auto; }' +
  '.pm-esc-desc { font-size: 11px; color: #8899aa; margin-bottom: 4px; line-height: 1.4; }' +
  '.pm-esc-examples { font-size: 10px; color: #667788; margin-top: 4px; font-style: italic; }' +
  '.pm-esc-name { font-size: 12px; color: #c8d6e5; font-weight: bold; margin-bottom: 4px; }' +
  '.pm-esc-number { font-size: 9px; color: #00ff88; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 4px; }' +
  '.pm-exercise-controls { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }' +
  '.pm-exercise-status { display: flex; align-items: center; gap: 8px; padding: 8px 14px; background: #111820; border: 1px solid #1a2332; border-radius: 4px; margin-bottom: 12px; font-size: 11px; color: #c8d6e5; }' +
  '.pm-exercise-timeline { margin-top: 12px; }' +
  '.pm-ex-event { display: flex; align-items: flex-start; gap: 10px; padding: 8px 12px; border-bottom: 1px solid #111820; }' +
  '.pm-ex-event-content { flex: 1; font-size: 11px; color: #c8d6e5; }' +
  '.pm-ex-event-marker { width: 8px; height: 8px; border-radius: 50%; margin-top: 4px; flex-shrink: 0; }' +
  '.pm-ex-event-team { font-size: 10px; font-weight: bold; text-transform: uppercase; }' +
  '.pm-ex-event-time { font-size: 9px; color: #667788; font-family: monospace; min-width: 50px; }' +
  '.pm-exposure-bar { height: 4px; border-radius: 2px; transition: width 0.3s; }' +
  '.pm-exposure-bar-wrap { height: 4px; background: #1a2332; border-radius: 2px; overflow: hidden; flex: 1; }' +
  '.pm-exposure-factor { margin-bottom: 6px; }' +
  '.pm-exposure-val { font-size: 11px; font-weight: bold; margin-left: 6px; }' +
  '.pm-ex-status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }' +
  '.pm-factor-bar { height: 6px; border-radius: 3px; }' +
  '.pm-factor-bar-wrap { height: 6px; background: #1a2332; border-radius: 3px; overflow: hidden; flex: 1; margin: 0 8px; }' +
  '.pm-factor-name { font-size: 10px; color: #8899aa; min-width: 80px; }' +
  '.pm-factor-score { font-size: 10px; color: #c8d6e5; font-family: monospace; min-width: 40px; text-align: right; }' +
  '.pm-filter-bar { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }' +
  '.pm-filter-btn { background: none; border: 1px solid #1a2332; color: #c8d6e5; padding: 4px 12px; font-size: 10px; cursor: pointer; border-radius: 2px; text-transform: uppercase; letter-spacing: 1px; font-family: monospace; }' +
  '.pm-filter-btn:hover { background: #1a2332; }' +
  '.pm-filter-btn.active { background: #1a2332; color: #00ff88; }' +
  '.pm-filter-label { font-size: 10px; color: #667788; text-transform: uppercase; letter-spacing: 1px; }' +
  '.pm-footer { padding: 8px 16px; font-size: 10px; color: #667788; text-align: center; border-top: 1px solid #1a2332; background: #080c14; }' +
  '.pm-form-row { display: flex; gap: 12px; align-items: flex-end; margin-bottom: 12px; flex-wrap: wrap; }' +
  '.pm-header-content { display: flex; flex-wrap: wrap; align-items: center; gap: 4px 16px; padding: 10px 16px; background: #0d1117; border-bottom: 1px solid #1a2332; }' +
  '.pm-header-meta { display: flex; align-items: center; gap: 12px; font-size: 10px; color: #667788; margin-left: auto; }' +
  '.pm-heat-cell { padding: 4px 8px; text-align: center; font-size: 11px; color: #c8d6e5; font-family: monospace; border: 1px solid #1a2332; }' +
  '.pm-intel-class-banner { padding: 3px 8px; font-size: 9px; font-weight: bold; color: #fff; text-align: center; letter-spacing: 2px; border-radius: 4px 4px 0 0; }' +
  '.pm-intel-header { display: flex; align-items: center; justify-content: space-between; padding: 8px 12px; }' +
  '.pm-intel-id { font-size: 10px; color: #00e5ff; font-family: monospace; }' +
  '.pm-intel-product { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 14px; margin-top: 12px; }' +
  '.pm-intel-scores { display: flex; gap: 12px; margin: 6px 0; }' +
  '.pm-intel-scroll { max-height: 400px; overflow-y: auto; }' +
  '.pm-intel-source { font-size: 10px; color: #667788; margin-bottom: 4px; text-transform: uppercase; letter-spacing: 1px; }' +
  '.pm-intel-summary { font-size: 11px; color: #c8d6e5; line-height: 1.5; padding: 6px 12px; }' +
  '.pm-intel-timeline { margin-top: 16px; position: relative; }' +
  '.pm-intel-timestamp { font-size: 10px; color: #667788; font-family: monospace; }' +
  '.pm-intel-type-badge { font-size: 9px; font-weight: bold; padding: 2px 8px; border-radius: 2px; text-transform: uppercase; letter-spacing: 1px; }' +
  '.pm-killswitch-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px; margin-top: 12px; }' +
  '.pm-killswitch-warning { background: rgba(255,0,64,0.1); border: 1px solid #ff0040; color: #ff0040; padding: 10px 14px; font-size: 11px; text-align: center; border-radius: 4px; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 1px; }' +
  '.pm-kpi-trend { font-size: 11px; margin-top: 4px; }' +
  '.pm-ks-activated { padding: 14px; text-align: center; background: rgba(255,0,64,0.1); border: 1px solid #ff0040; border-radius: 4px; }' +
  '.pm-ks-confirm { padding: 10px; background: rgba(255,0,64,0.1); border: 1px solid #ff0040; border-radius: 4px; margin-top: 8px; }' +
  '.pm-ks-confirm-text { font-size: 11px; color: #ff0040; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 1px; }' +
  '.pm-ks-desc { font-size: 11px; color: #8899aa; margin-bottom: 6px; line-height: 1.4; }' +
  '.pm-ks-name { font-size: 12px; color: #ff0040; text-transform: uppercase; letter-spacing: 1px; font-weight: bold; margin-bottom: 4px; }' +
  '.pm-ks-status { font-size: 10px; color: #667788; margin-bottom: 6px; }' +
  '.pm-ks-time { font-size: 10px; color: #667788; margin-top: 4px; }' +
  '.pm-label-sm { font-size: 9px; color: #667788; text-transform: uppercase; letter-spacing: 1px; }' +
  '.pm-license-bar { display: flex; height: 20px; border-radius: 3px; overflow: hidden; margin: 8px 0; border: 1px solid #1a2332; }' +
  '.pm-license-seg { display: flex; align-items: center; justify-content: center; font-size: 8px; color: #000; font-weight: bold; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }' +
  '.pm-metric-card { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 14px; text-align: center; }' +
  '.pm-metric-label { font-size: 10px; color: #667788; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }' +
  '.pm-metric-unit { font-size: 12px; color: #667788; margin-left: 2px; }' +
  '.pm-metric-value { font-size: 24px; font-weight: bold; color: #00ff88; }' +
  '.pm-mission-name { font-size: 13px; color: #00e5ff; text-transform: uppercase; letter-spacing: 1px; font-weight: bold; }' +
  '.pm-mission-pct { font-size: 10px; color: #667788; margin-top: 4px; }' +
  '.pm-mission-row { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 12px 14px; margin-bottom: 8px; }' +
  '.pm-mission-row:hover { border-color: #2a3a4a; }' +
  '.pm-mission-status { font-size: 10px; font-weight: bold; text-transform: uppercase; }' +
  '.pm-mission-top { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }' +
  '.pm-mission-type { font-size: 10px; color: #667788; text-transform: uppercase; letter-spacing: 1px; margin-left: 8px; }' +
  '.pm-modal-body { padding: 16px; max-height: 70vh; overflow-y: auto; }' +
  '.pm-modal-close { position: absolute; top: 10px; right: 14px; background: none; border: none; color: #c8d6e5; font-size: 20px; cursor: pointer; }' +
  '.pm-modal-close:hover { color: #ff0040; }' +
  '.pm-modal-header { padding: 12px 16px; background: #111820; border-bottom: 1px solid #1a2332; font-size: 12px; color: #00ff88; text-transform: uppercase; letter-spacing: 2px; position: relative; }' +
  '.pm-mono { font-family: monospace; font-size: 11px; color: #00e5ff; }' +
  '.pm-operator { font-size: 10px; color: #667788; }' +
  '.pm-op-timeline { margin-top: 12px; }' +
  '.pm-op-tl-bar { height: 24px; border-radius: 3px; display: flex; align-items: center; padding: 0 8px; font-size: 10px; color: #000; font-weight: bold; min-width: 30px; }' +
  '.pm-op-tl-days { font-size: 9px; color: #667788; margin-left: 8px; font-family: monospace; }' +
  '.pm-op-tl-item { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }' +
  '.pm-op-total { font-size: 11px; color: #ffaa00; text-transform: uppercase; letter-spacing: 1px; margin-top: 12px; padding: 8px 12px; background: #111820; border: 1px solid #1a2332; border-radius: 4px; }' +
  '.pm-panel-hdr { background: #111820; padding: 8px 14px; font-size: 11px; color: #00ff88; text-transform: uppercase; letter-spacing: 2px; border-bottom: 1px solid #1a2332; }' +
  '.pm-panel-title { font-size: 11px; color: #00ff88; text-transform: uppercase; letter-spacing: 2px; padding: 8px 0; margin-bottom: 8px; border-bottom: 1px solid #1a2332; }' +
  '.pm-path-arrow { font-size: 14px; color: #00ff88; padding: 4px 8px; text-align: center; }' +
  '.pm-path-chain { display: flex; flex-direction: column; align-items: center; margin-top: 12px; }' +
  '.pm-path-connector { font-size: 10px; color: #1a2332; text-align: center; padding: 2px 0; }' +
  '.pm-path-controls { display: flex; gap: 8px; align-items: flex-end; flex-wrap: wrap; margin-bottom: 12px; }' +
  '.pm-path-field { display: flex; flex-direction: column; gap: 4px; }' +
  '.pm-path-hop { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 10px 14px; width: 250px; text-align: center; }' +
  '.pm-path-hop:hover { border-color: #2a3a4a; }' +
  '.pm-path-hop-action { font-size: 10px; color: #ffaa00; text-transform: uppercase; margin-top: 4px; }' +
  '.pm-path-hop-name { font-size: 12px; color: #c8d6e5; font-weight: bold; }' +
  '.pm-path-hop-num { font-size: 9px; color: #00ff88; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 4px; }' +
  '.pm-path-hop-sector { font-size: 10px; color: #667788; margin-top: 2px; }' +
  '.pm-path-meta { font-size: 10px; color: #8899aa; margin-bottom: 8px; }' +
  '.pm-path-result { margin-top: 16px; }' +
  '.pm-phase-connector { color: #1a2332; font-size: 16px; display: flex; align-items: center; padding: 0 4px; }' +
  '.pm-phase-duration { font-size: 9px; color: #667788; }' +
  '.pm-phase-icon { font-size: 18px; margin-bottom: 4px; }' +
  '.pm-phase-name { font-size: 10px; color: #c8d6e5; text-transform: uppercase; letter-spacing: 1px; text-align: center; }' +
  '.pm-phase-step { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 10px; text-align: center; min-width: 100px; }' +
  '.pm-phase-step:hover { border-color: #2a3a4a; }' +
  '.pm-phase-timeline { display: flex; align-items: center; gap: 4px; overflow-x: auto; padding: 12px 0; }' +
  '.pm-playbook-card { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; margin-bottom: 8px; overflow: hidden; }' +
  '.pm-playbook-card:hover { border-color: #2a3a4a; }' +
  '.pm-playbook-header { display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; }' +
  '.pm-playbook-list { margin-top: 12px; }' +
  '.pm-playbook-name { font-size: 12px; color: #00e5ff; text-transform: uppercase; letter-spacing: 1px; font-weight: bold; }' +
  '.pm-playbook-progress { padding: 6px 14px; display: flex; align-items: center; gap: 8px; }' +
  '.pm-playbook-steps { padding: 0; }' +
  '.pm-playbook-team { font-size: 10px; color: #667788; padding: 4px 14px; }' +
  '.pm-pop-impact { margin-top: 12px; }' +
  '.pm-predict-card-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; flex-wrap: wrap; gap: 6px; }' +
  '.pm-predict-detail { padding: 10px 14px; background: #080c14; border-top: 1px solid #1a2332; margin-top: 8px; }' +
  '.pm-predict-expand { background: none; border: 1px solid #1a2332; color: #00e5ff; padding: 3px 10px; font-size: 9px; cursor: pointer; border-radius: 2px; text-transform: uppercase; letter-spacing: 1px; font-family: monospace; margin-top: 8px; }' +
  '.pm-predict-expand:hover { background: #1a2332; }' +
  '.pm-predict-field { font-size: 11px; color: #8899aa; margin-bottom: 4px; }' +
  '.pm-predict-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px; margin-top: 12px; }' +
  '.pm-predict-horizon-badge { font-size: 9px; font-weight: bold; color: #000; padding: 2px 8px; border-radius: 2px; text-transform: uppercase; }' +
  '.pm-predict-name { font-size: 12px; color: #c8d6e5; font-weight: bold; }' +
  '.pm-predict-ring { width: 50px; height: 50px; border-radius: 50%; border: 3px solid currentColor; display: flex; align-items: center; justify-content: center; font-size: 14px; font-weight: bold; }' +
  '.pm-predict-status { font-size: 10px; font-weight: bold; text-transform: uppercase; }' +
  '.pm-prob-bar { height: 6px; border-radius: 3px; transition: width 0.3s; }' +
  '.pm-prob-bar-container { height: 6px; background: #1a2332; border-radius: 3px; overflow: hidden; margin-top: 4px; }' +
  '.pm-product-buttons { display: flex; gap: 8px; margin: 8px 0; flex-wrap: wrap; }' +
  '.pm-product-output { margin-top: 12px; }' +
  '.pm-product-placeholder { font-size: 11px; color: #667788; font-style: italic; padding: 20px; text-align: center; background: #080c14; border: 1px dashed #1a2332; border-radius: 4px; }' +
  '.pm-progress-fill { height: 100%; border-radius: 3px; transition: width 0.3s; }' +
  '.pm-progress-label { font-size: 10px; color: #c8d6e5; margin-left: 8px; font-family: monospace; }' +
  '.pm-progress-text { font-size: 10px; color: #667788; font-family: monospace; }' +
  '.pm-prop-step { display: flex; align-items: flex-start; gap: 8px; padding: 6px 0; border-bottom: 1px solid #111820; font-size: 11px; color: #c8d6e5; }' +
  '.pm-prop-step-label { font-size: 9px; color: #00ff88; text-transform: uppercase; letter-spacing: 1px; font-weight: bold; white-space: nowrap; }' +
  '.pm-radio-desc { font-size: 10px; color: #667788; margin-top: 2px; }' +
  '.pm-radio-group { display: flex; flex-direction: column; gap: 6px; margin: 8px 0; }' +
  '.pm-radio-label { display: flex; align-items: flex-start; gap: 8px; padding: 8px 12px; border: 1px solid #1a2332; border-radius: 4px; cursor: pointer; background: #0d1117; font-size: 11px; color: #c8d6e5; }' +
  '.pm-radio-label:hover { border-color: #2a3a4a; }' +
  '.pm-range { width: 100%; accent-color: #00ff88; background: #1a2332; height: 4px; border-radius: 2px; appearance: none; -webkit-appearance: none; }' +
  '.pm-range::-webkit-slider-thumb { appearance: none; -webkit-appearance: none; width: 14px; height: 14px; background: #00ff88; border-radius: 50%; cursor: pointer; }' +
  '.pm-rb-ratio { font-size: 14px; color: #c8d6e5; margin-bottom: 8px; }' +
  '.pm-rb-result { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 14px; margin-top: 12px; }' +
  '.pm-recovery-timeline { margin-top: 12px; }' +
  '.pm-report-banner { padding: 4px 8px; font-size: 10px; font-weight: bold; color: #fff; text-align: center; letter-spacing: 2px; text-transform: uppercase; }' +
  '.pm-report-body { font-size: 11px; color: #c8d6e5; line-height: 1.6; padding: 6px 0; }' +
  '.pm-report-classification { font-size: 10px; color: #ff0040; text-align: center; padding: 6px; border: 1px solid #ff0040; border-radius: 2px; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 2px; font-weight: bold; }' +
  '.pm-report-divider { height: 1px; background: #1a2332; margin: 12px 0; }' +
  '.pm-report-footer { font-size: 10px; color: #ff0040; text-align: center; padding: 8px; border-top: 1px solid #1a2332; margin-top: 12px; text-transform: uppercase; letter-spacing: 2px; }' +
  '.pm-report-gen { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 16px; margin-top: 12px; }' +
  '.pm-report-hr { border: none; border-top: 1px solid #1a2332; margin: 10px 0; }' +
  '.pm-report-line { font-size: 11px; color: #c8d6e5; padding: 3px 0; }' +
  '.pm-report-output { background: #080c14; border: 1px solid #1a2332; border-radius: 4px; padding: 16px; margin-top: 12px; font-family: monospace; }' +
  '.pm-report-section { font-size: 11px; color: #00ff88; text-transform: uppercase; letter-spacing: 1px; margin: 10px 0 6px; font-weight: bold; }' +
  '.pm-report-template { background: #080c14; border: 1px solid #1a2332; border-radius: 4px; padding: 16px; margin-top: 12px; }' +
  '.pm-report-title { font-size: 13px; color: #00ff88; text-align: center; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 12px; font-weight: bold; }' +
  '.pm-report-type { font-size: 13px; color: #00e5ff; text-align: center; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 12px; font-weight: bold; }' +
  '.pm-response-log { max-height: 300px; overflow-y: auto; background: #080c14; border: 1px solid #1a2332; border-radius: 4px; padding: 8px; margin-top: 8px; font-size: 11px; color: #c8d6e5; font-family: monospace; }' +
  '.pm-result-box { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 14px; margin-top: 12px; }' +
  '.pm-result-detail { font-size: 11px; color: #8899aa; margin-bottom: 4px; }' +
  '.pm-result-error { color: #ff0040; font-size: 12px; padding: 10px; background: rgba(255,0,64,0.08); border: 1px solid rgba(255,0,64,0.2); border-radius: 4px; }' +
  '.pm-result-success { color: #00ff88; font-size: 12px; padding: 10px; background: rgba(0,255,136,0.08); border: 1px solid rgba(0,255,136,0.2); border-radius: 4px; }' +
  '.pm-result-title { font-size: 12px; color: #00e5ff; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; font-weight: bold; }' +
  '.pm-risk-badge { font-size: 9px; font-weight: bold; padding: 2px 8px; border-radius: 2px; text-transform: uppercase; }' +
  '.pm-risk-benefit { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 16px; }' +
  '.pm-risk-high { color: #ff0040; font-weight: bold; }' +
  '.pm-roe-desc { font-size: 11px; color: #8899aa; line-height: 1.4; }' +
  '.pm-roe-grid { display: grid; gap: 8px; margin-top: 12px; }' +
  '.pm-roe-icon { font-size: 14px; margin-right: 8px; }' +
  '.pm-roe-rule { font-size: 12px; color: #c8d6e5; font-weight: bold; margin-bottom: 4px; }' +
  '.pm-roe-text { flex: 1; }' +
  '.pm-rt-content { flex: 1; }' +
  '.pm-rt-desc { font-size: 11px; color: #8899aa; margin-top: 2px; }' +
  '.pm-rt-marker { width: 28px; height: 28px; background: #0d2137; color: #00ff88; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: bold; flex-shrink: 0; }' +
  '.pm-rt-name { font-size: 12px; color: #c8d6e5; font-weight: bold; }' +
  '.pm-rt-step { display: flex; gap: 12px; align-items: flex-start; padding: 10px 0; border-bottom: 1px solid #111820; }' +
  '.pm-rt-time { font-size: 10px; color: #00e5ff; font-family: monospace; }' +
  '.pm-scenario-desc { font-size: 11px; color: #8899aa; margin-bottom: 6px; line-height: 1.4; }' +
  '.pm-scenario-diff { font-size: 9px; font-weight: bold; padding: 2px 8px; border-radius: 2px; text-transform: uppercase; }' +
  '.pm-scenario-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; }' +
  '.pm-scenario-meta { display: flex; gap: 12px; font-size: 10px; color: #667788; }' +
  '.pm-scenario-name { font-size: 12px; color: #c8d6e5; font-weight: bold; }' +
  '.pm-score-breakdown { margin-top: 8px; }' +
  '.pm-score-item { font-size: 10px; color: #8899aa; margin-right: 12px; }' +
  '.pm-score-item-row { display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #111820; font-size: 11px; color: #c8d6e5; }' +
  '.pm-score-panel { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 14px; border-top: 3px solid; }' +
  '.pm-score-team-name { font-size: 11px; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 4px; font-weight: bold; }' +
  '.pm-score-total { font-size: 28px; font-weight: bold; margin-bottom: 8px; }' +
  '.pm-scoring-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 12px; }' +
  '.pm-sc-search { margin-bottom: 12px; }' +
  '.pm-section-header { font-size: 14px; color: #00ff88; text-transform: uppercase; letter-spacing: 3px; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid #1a2332; }' +
  '.pm-section-sub { font-size: 11px; color: #00e5ff; text-transform: uppercase; letter-spacing: 1px; margin: 16px 0 8px; padding-bottom: 4px; border-bottom: 1px solid #111820; }' +
  '.pm-sector-affected { font-size: 12px; color: #ff0040; font-weight: bold; }' +
  '.pm-sector-bar { height: 6px; border-radius: 3px; background: #00ff88; transition: width 0.5s; }' +
  '.pm-sector-bar-bg { height: 6px; background: #1a2332; border-radius: 3px; overflow: hidden; margin-top: 4px; }' +
  '.pm-sector-breakdown { margin-top: 8px; }' +
  '.pm-sector-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; margin: 12px 0; }' +
  '.pm-sector-health-bar { height: 4px; background: #1a2332; border-radius: 2px; overflow: hidden; margin-top: 6px; }' +
  '.pm-sector-health-fill { height: 100%; border-radius: 2px; transition: width 0.3s; }' +
  '.pm-sector-health-text { font-size: 10px; margin-top: 4px; }' +
  '.pm-sector-pct { font-size: 10px; color: #667788; font-family: monospace; }' +
  '.pm-sector-sep { color: #1a2332; margin: 0 4px; }' +
  '.pm-sector-stats { display: flex; align-items: center; gap: 4px; font-size: 10px; color: #667788; }' +
  '.pm-sector-total { font-size: 10px; color: #8899aa; }' +
  '.pm-session { font-size: 10px; color: #667788; }' +
  '.pm-sigint-bottom-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 16px; }' +
  '.pm-sigint-corr { margin-top: 16px; }' +
  '.pm-sigint-feed { flex: 1; }' +
  '.pm-sigint-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 16px; }' +
  '.pm-sim-controls { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 14px; margin-bottom: 12px; }' +
  '.pm-sim-field { display: flex; flex-direction: column; gap: 4px; margin-bottom: 8px; }' +
  '.pm-sim-impact { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 12px; margin-top: 12px; }' +
  '.pm-sim-impact-item { background: #111820; border: 1px solid #1a2332; border-radius: 4px; padding: 12px; text-align: center; }' +
  '.pm-sim-impact-label { font-size: 9px; color: #667788; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }' +
  '.pm-sim-impact-val { font-size: 22px; font-weight: bold; }' +
  '.pm-sim-results { background: #080c14; border: 1px solid #1a2332; border-radius: 4px; padding: 14px; margin-top: 12px; }' +
  '.pm-slider { width: 100%; accent-color: #00ff88; }' +
  '.pm-spark-canvas { display: block; }' +
  '.pm-spark-label { font-size: 10px; color: #667788; min-width: 100px; text-transform: uppercase; letter-spacing: 1px; }' +
  '.pm-spark-row { display: flex; align-items: center; gap: 12px; margin-bottom: 6px; }' +
  '.pm-speed-btn { background: #111820; border: 1px solid #1a2332; color: #c8d6e5; padding: 4px 10px; font-size: 10px; cursor: pointer; border-radius: 2px; font-family: monospace; }' +
  '.pm-speed-btn:hover { border-color: #00ff88; color: #00ff88; }' +
  '.pm-stat-box { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 12px; text-align: center; min-width: 120px; }' +
  '.pm-stat-card { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 14px; text-align: center; }' +
  '.pm-stat-label { font-size: 9px; color: #667788; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }' +
  '.pm-stat-row { display: flex; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }' +
  '.pm-status-dim { color: #667788; font-size: 10px; }' +
  '.pm-status-green { color: #00ff88; font-weight: bold; }' +
  '.pm-status-red { color: #ff0040; font-weight: bold; }' +
  '.pm-status-yellow { color: #ffaa00; font-weight: bold; }' +
  '.pm-stat-val { font-size: 24px; font-weight: bold; color: #00ff88; }' +
  '.pm-stat-value { font-size: 22px; font-weight: bold; }' +
  '.pm-subsection-title { font-size: 11px; color: #00e5ff; text-transform: uppercase; letter-spacing: 1px; margin: 14px 0 8px; padding-bottom: 4px; border-bottom: 1px solid #111820; }' +
  '.pm-svc-badge { font-size: 9px; background: #1a2332; color: #c8d6e5; padding: 2px 6px; border-radius: 2px; margin-right: 4px; display: inline-block; margin-bottom: 2px; }' +
  '.pm-svc-bar-count { font-size: 10px; color: #c8d6e5; font-family: monospace; min-width: 30px; text-align: right; }' +
  '.pm-svc-bar-fill { height: 100%; border-radius: 3px; }' +
  '.pm-svc-bar-label { font-size: 10px; color: #8899aa; min-width: 80px; }' +
  '.pm-svc-bar-row { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }' +
  '.pm-svc-bar-track { flex: 1; height: 8px; background: #1a2332; border-radius: 3px; overflow: hidden; }' +
  '.pm-svc-cell { padding: 4px 8px; }' +
  '.pm-target-detail { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 14px; margin-top: 12px; }' +
  '.pm-target-field { font-size: 11px; color: #8899aa; margin-bottom: 4px; }' +
  '.pm-target-info { margin-bottom: 8px; }' +
  '.pm-target-name { font-size: 13px; color: #c8d6e5; font-weight: bold; margin-bottom: 6px; }' +
  '.pm-team-card { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 14px; text-align: center; border-top: 3px solid; }' +
  '.pm-team-desc { font-size: 10px; color: #667788; margin-top: 6px; line-height: 1.4; }' +
  '.pm-team-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px; margin: 12px 0; }' +
  '.pm-team-icon { font-size: 24px; margin-bottom: 6px; }' +
  '.pm-team-name { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; font-weight: bold; margin-bottom: 4px; }' +
  '.pm-team-role { font-size: 10px; color: #8899aa; }' +
  '.pm-terrain-bottom { margin-top: 16px; }' +
  '.pm-timeline-connector { width: 2px; height: 16px; background: #1a2332; margin: 0 auto; }' +
  '.pm-timeline-container { margin-top: 12px; }' +
  '.pm-timeline-content { padding: 8px 12px; background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; }' +
  '.pm-timeline-detail { font-size: 10px; color: #667788; margin-top: 4px; }' +
  '.pm-timeline-detail-inner { padding: 10px 14px; margin-top: 8px; }' +
  '.pm-timeline-label { font-size: 11px; color: #c8d6e5; margin-bottom: 2px; }' +
  '.pm-timeline-labels { display: flex; gap: 12px; margin-bottom: 8px; flex-wrap: wrap; }' +
  '.pm-timeline-track { position: relative; height: 40px; background: #111820; border: 1px solid #1a2332; border-radius: 4px; overflow: hidden; }' +
  '.pm-tl-action { font-size: 11px; color: #c8d6e5; font-weight: bold; margin-bottom: 4px; }' +
  '.pm-tl-content { flex: 1; }' +
  '.pm-tl-detail { font-size: 10px; color: #667788; margin-top: 2px; }' +
  '.pm-tl-dot { width: 10px; height: 10px; border-radius: 50%; background: #00ff88; flex-shrink: 0; margin-top: 4px; }' +
  '.pm-tl-tags { display: flex; gap: 4px; margin-top: 4px; flex-wrap: wrap; }' +
  '.pm-tl-time { font-size: 9px; color: #00e5ff; font-family: monospace; margin-bottom: 2px; }' +
  '.pm-twin-search { margin-bottom: 12px; }' +
  '.pm-val-accent { color: #00ff88; font-weight: bold; }' +
  '.pm-version { font-size: 10px; color: #667788; }' +
  '.pm-wargame-scenarios { margin-top: 12px; }' +
  '.pm-whatif-assessment { font-size: 11px; color: #c8d6e5; margin-top: 8px; padding: 10px; background: #111820; border: 1px solid #1a2332; border-radius: 4px; line-height: 1.5; }' +
  '.pm-whatif-inputs { display: flex; flex-direction: column; gap: 8px; margin-bottom: 12px; }' +
  '.pm-whatif-metrics { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; margin-top: 12px; }' +
  '.pm-whatif-output { margin-top: 12px; }' +
  '.pm-whatif-panel { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 14px; }' +
  '.pm-whatif-result { background: #080c14; border: 1px solid #1a2332; border-radius: 4px; padding: 14px; }' +
  '.pm-whatif-result-title { font-size: 12px; color: #00ff88; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; font-weight: bold; }' +
  '.pm-whatif-scenario-desc { font-size: 11px; color: #8899aa; margin-bottom: 12px; line-height: 1.5; }' +
  '.pm-cc-top { display: grid; grid-template-columns: 1fr 2fr; gap: 16px; margin-bottom: 16px; }' +
  '.pm-cc-mid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }' +
  '.pm-cc-bot { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin-bottom: 16px; }' +
  '@media (max-width: 900px) { .pm-cc-top, .pm-cc-mid, .pm-cc-bot { grid-template-columns: 1fr; } }' +

  /* ====== 3D VISUAL UPGRADE ====== */
  '.pm-defcon-btn { width: 42px; height: 42px; border: 2px solid #2a3a4a; border-radius: 4px; background: linear-gradient(180deg, #1a2030 0%, #0d1117 100%); color: #667788; font-family: "Courier New", monospace; font-size: 15px; font-weight: bold; cursor: pointer; transition: all 0.25s ease; box-shadow: 0 3px 10px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.06); position: relative; overflow: hidden; }' +
  '.pm-defcon-sheen-removed { display:none; }' +
  '.pm-defcon-btn:hover { border-color: #00ff88; color: #00ff88; box-shadow: 0 4px 20px rgba(0,255,136,0.25), inset 0 1px 0 rgba(0,255,136,0.15); transform: translateY(-2px); }' +
  '.pm-defcon-btn:active { transform: translateY(1px); box-shadow: 0 1px 4px rgba(0,0,0,0.6); }' +
  '.pm-defcon-btn-active { border-color: #ff6600 !important; color: #fff !important; background: linear-gradient(180deg, #ff6600 0%, #cc4400 100%) !important; box-shadow: 0 0 24px rgba(255,102,0,0.5), 0 6px 16px rgba(255,102,0,0.35), inset 0 1px 0 rgba(255,255,255,0.25) !important; text-shadow: 0 0 10px rgba(255,255,255,0.6); }' +
  '.pm-defcon-btns { display: flex; gap: 6px; margin: 12px 0; justify-content: center; }' +
  '.pm-card { background: #0d1117 !important; border: 1px solid #1a2a3a !important; border-radius: 6px !important; box-shadow: 0 4px 16px rgba(0,0,0,0.4), ; transition: all 0.3s ease; }' +
  '.pm-card:hover { border-color: rgba(0,255,136,0.25) !important; box-shadow: 0 8px 32px rgba(0,0,0,0.5), 0 0 20px rgba(0,255,136,0.06); transform: translateY(-1px); }' +
  '.pm-card-line-removed { display:none; }' +
  '.pm-card-header { font-size: 11px; color: #00ff88; text-transform: uppercase; letter-spacing: 2px; padding: 0 0 8px; border-left: 3px solid #00ff88; padding-left: 10px; font-weight: bold; text-shadow: 0 0 8px rgba(0,255,136,0.3); }' +
  '.pm-panel { background: #0d1117 !important; border: 1px solid #1a2a3a !important; border-radius: 8px !important; margin-bottom: 16px; overflow: hidden; box-shadow: 0 4px 24px rgba(0,0,0,0.5), ; position: relative; }' +
  '.pm-panel-line-removed { display:none; }' +
  '.pm-panel-hdr { background: #111820 !important; padding: 10px 16px !important; font-size: 11px; color: #00ff88 !important; text-transform: uppercase; letter-spacing: 2px !important; font-weight: bold; border-bottom: 1px solid #1a2a3a; display: flex; align-items: center; justify-content: space-between;  }' +
  '.pm-header-upgraded { display:none; }' +
  '.pm-header-glow { display:none; }' +
  '.pm-title { text-shadow: 0 0 20px rgba(0,255,136,0.6), 0 0 40px rgba(0,255,136,0.2) !important; }' +
  '.pm-class-banner { background: linear-gradient(180deg, #dd0000 0%, #aa0000 100%) !important; box-shadow: 0 2px 12px rgba(200,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.15); text-shadow: 0 1px 2px rgba(0,0,0,0.5); }' +
  '.pm-tab { background: #0d1117 !important; border-radius: 4px !important; box-shadow: 0 2px 6px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.04); }' +
  '.pm-tab-sheen-removed { display:none; }' +
  '.pm-tab:hover { background: #111820 !important; color: #99aabb !important; transform: translateY(-1px); }' +
  '.pm-tab.active, .pm-tab-active { background: #0d1117 !important; color: #00ff88 !important; border-color: #00ff88 !important; box-shadow: 0 0 16px rgba(0,255,136,0.15), 0 4px 12px rgba(0,0,0,0.4) !important;  }' +
  '.pm-alert-sev { display: inline-block; font-size: 9px; font-weight: bold; padding: 3px 8px; border-radius: 3px; text-transform: uppercase; letter-spacing: 1px; min-width: 70px; flex-shrink: 0; text-align: center; color: #fff; box-shadow: 0 2px 6px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.1); }' +
  '.pm-alert-time { font-size: 10px; color: #445566; font-family: "Courier New", monospace; min-width: 65px; flex-shrink: 0; }' +
  '.pm-alert-id { font-size: 10px; color: #556677; font-family: "Courier New", monospace; min-width: 90px; flex-shrink: 0; }' +
  '.pm-alert-msg { flex: 1; color: #aabbcc; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }' +
  '.pm-alert-count { font-size: 10px; color: #667788; font-weight: normal; }' +
  '.pm-alert-item { padding: 8px 14px; border-bottom: 1px solid #111820; font-size: 12px; display: flex; align-items: center; gap: 10px; transition: background 0.15s; }' +
  '.pm-alert-item:hover { background: rgba(0,255,136,0.03); }' +
  '.pm-domain-row { display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; border-bottom: 1px solid #111820; transition: all 0.2s; border-left: 3px solid transparent; }' +
  '.pm-domain-row:hover { background: rgba(0,255,136,0.03); border-left-color: rgba(0,255,136,0.3); }' +
  '.pm-domain-name { font-size: 12px; font-weight: bold; color: #c8d6e5; text-transform: uppercase; letter-spacing: 1px; }' +
  '.pm-domain-status { font-size: 11px; font-weight: bold; }' +
  '.pm-mission-row { padding: 12px 16px; border-bottom: 1px solid #111820; }' +
  '.pm-mission-row:hover { background: rgba(0,255,136,0.03); }' +
  '.pm-mission-top { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 6px; flex-wrap: wrap; }' +
  '.pm-mission-name { font-size: 13px; font-weight: bold; color: #c8d6e5; letter-spacing: 1px; text-transform: uppercase; }' +
  '.pm-mission-type { font-size: 10px; color: #667788; text-transform: uppercase; letter-spacing: 1px; }' +
  '.pm-mission-status { font-size: 9px; font-weight: bold; padding: 3px 10px; border-radius: 3px; text-transform: uppercase; box-shadow: 0 2px 6px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.1); }' +
  '.pm-mission-progress { width: 100%; height: 6px; background: #111820; border-radius: 3px; overflow: hidden; box-shadow: inset 0 1px 3px rgba(0,0,0,0.5); margin-top: 6px; }' +
  '.pm-mission-progress-fill { height: 100%; border-radius: 3px; background: linear-gradient(90deg, #00ff88, #00cc66); box-shadow: 0 0 8px rgba(0,255,136,0.3); }' +
  '.pm-mission-pct { font-size: 10px; color: #667788; font-family: "Courier New", monospace; margin-top: 4px; }' +
  '.pm-gauge { filter: drop-shadow(0 4px 16px rgba(0,0,0,0.5)); }' +
  '.pm-kpi-value { font-size: 28px; font-weight: bold; text-shadow: 0 0 12px currentColor; }' +
  '.pm-kpi-label { font-size: 9px; color: #556677; text-transform: uppercase; letter-spacing: 2px; margin-top: 4px; }' +
  '.pm-wrap { background: #0a0e17 !important; }' +
  '.pm-section-title {  position: relative; }' +
  '.pm-section-title::after { content: ""; position: absolute; bottom: -1px; left: 0; width: 60px; height: 1px; background: #00ff88; box-shadow: 0 0 10px rgba(0,255,136,0.5); }' +
  '.pm-clocks-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(100px, 1fr)); gap: 8px; }' +
  '.pm-clock-card { background: linear-gradient(180deg, #111820 0%, #0a0e17 100%); border: 1px solid #1a2332; border-radius: 6px; padding: 8px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.3); }' +
  '.pm-clock-label { font-size: 8px; color: #445566; text-transform: uppercase; letter-spacing: 2px; }' +
  '.pm-clock-time { font-size: 16px; font-weight: bold; color: #00ff88; font-family: "Courier New", monospace;  margin-top: 2px; }' +
  '.pm-health-item { display: flex; align-items: center; gap: 12px; padding: 8px 0; }' +
  '.pm-health-label { font-size: 10px; font-weight: bold; color: #667788; text-transform: uppercase; letter-spacing: 2px; min-width: 60px; }' +
  '.pm-health-val { font-size: 12px; color: #00ff88; font-weight: bold; text-shadow: 0 0 6px rgba(0,255,136,0.3); }' +
  '.pm-health-canvas { border-radius: 4px; box-shadow: 0 2px 8px rgba(0,0,0,0.3); }' +
  '.pm-status-bar { background: linear-gradient(180deg, #111820 0%, #0a0e17 100%) !important; box-shadow: 0 -4px 16px rgba(0,0,0,0.3); }' +
  '.pm-canvas { border-radius: 6px; box-shadow: 0 4px 16px rgba(0,0,0,0.4); }' +

  /* Pro overrides for second style block */
  '[data-style=pro] .pm-classification-banner { background: #18181b !important; font-size: 10px !important; letter-spacing: .08em !important; }' +
  '[data-style=pro] .pm-class-banner { background: #18181b !important; font-size: 10px !important; letter-spacing: .08em !important; }' +
  '[data-style=pro] [style*="background:#cc0000"] { background: #18181b !important; }' +
  '[data-style=pro] .pm-header { border-bottom-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-ci-report-id { color: #71717a !important; }' +
  '[data-style=pro] .pm-ci-report-title { color: #18181b !important; }' +
  '[data-style=pro] .pm-ci-report-summary { color: #71717a !important; }' +
  '[data-style=pro] .pm-ci-report-fulltext { color: #3f3f46 !important; }' +
  '[data-style=pro] .pm-ci-report-card { background: #fff !important; border-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-ci-report-card:hover { border-color: #d4d4d8 !important; }' +
  '[data-style=pro] .pm-health-val { color: #16a34a !important; text-shadow: none !important; }' +
  '[data-style=pro] .pm-status-bar { background: #f9fafb !important; box-shadow: 0 -1px 0 #e5e5e5 !important; }' +
  '[data-style=pro] .pm-clock-item { color: #3f3f46 !important; }' +
  '[data-style=pro] .pm-comp-delta { background: #f4f4f5 !important; border-color: #e5e5e5 !important; color: #18181b !important; }' +

  /* OMNI ANALYSIS SUITE (pivot / attribution / exposure / report) */
  '.pm-hl { background: rgba(0,229,255,0.22); color: #00e5ff; border-radius: 2px; padding: 0 1px; }' +
  '.pm-pivot-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 12px; align-items: start; }' +
  '.pm-hitcard { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 12px; }' +
  '.pm-hitcard-hdr { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; gap: 8px; }' +
  '.pm-hitline { font-size: 11px; padding: 5px 0; border-bottom: 1px solid #111820; line-height: 1.5; word-break: break-word; }' +
  '.pm-hitline:last-child { border-bottom: none; }' +
  '.pm-kv { display: flex; gap: 8px; font-size: 11px; padding: 3px 0; }' +
  '.pm-kv-k { color: #667788; min-width: 90px; text-transform: uppercase; letter-spacing: 1px; font-size: 9px; }' +
  '.pm-bar-track { background: #111820; border-radius: 3px; height: 10px; width: 100%; overflow: hidden; }' +
  '.pm-bar-fill { height: 100%; border-radius: 3px; }' +
  '.pm-clickrow { cursor: pointer; }' +
  '.pm-rowsel td { background: rgba(0,255,136,0.08) !important; border-top: 1px solid #00ff88; border-bottom: 1px solid #00ff88; }' +
  '[data-style=pro] .pm-hl { background: #dbeafe !important; color: #1d4ed8 !important; }' +
  '[data-style=pro] .pm-hitcard { background: #fff !important; border-color: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-hitline { border-bottom-color: #f4f4f5 !important; color: #3f3f46 !important; }' +
  '[data-style=pro] .pm-kv-k { color: #71717a !important; }' +
  '[data-style=pro] .pm-bar-track { background: #e5e5e5 !important; }' +
  '[data-style=pro] .pm-rowsel td { background: #f0f9f4 !important; border-color: #16a34a !important; }' +

  '</style>';

// Merge PM_CSS_EXT into PM_CSS as a single style block, then render
PM_CSS = PM_CSS.slice(0, -8) + PM_CSS_EXT.slice(7);
render();

// ============================================================================
// ADDITIONAL ANALYSIS ALGORITHMS
// ============================================================================
function analyzeAttackSurface() {
  var surface = {
    externalFacing: 0,
    criticalExposed: 0,
    unpatched: 0,
    scadaExposed: 0,
    totalVulns: 0,
    riskScore: 0
  };

  for (var i = 0; i < INFRA_NODES.length; i++) {
    var node = INFRA_NODES[i];
    if (node.deps.length === 0) surface.externalFacing++;
    if (node.criticality >= 9) {
      surface.criticalExposed++;
    }
    var vulns = getVulnsForNode(node.id);
    surface.totalVulns += vulns.length;
    if (node.type === 'scada' || node.type === 'control') {
      surface.scadaExposed++;
    }
  }

  surface.riskScore = Math.min(100,
    surface.externalFacing * 2 +
    surface.criticalExposed * 8 +
    surface.totalVulns * 5 +
    surface.scadaExposed * 10
  );

  return surface;
}

function analyzeThreatLandscape() {
  var landscape = {
    totalAPTs: APT_GROUPS.length,
    activeAPTs: 0,
    topThreatLevel: 0,
    nationBreakdown: {},
    targetBreakdown: {},
    tacticsUsed: {},
    recentCampaigns: 0
  };

  for (var i = 0; i < APT_GROUPS.length; i++) {
    var apt = APT_GROUPS[i];
    if (apt.active) landscape.activeAPTs++;
    if (apt.threatLevel > landscape.topThreatLevel) landscape.topThreatLevel = apt.threatLevel;
    landscape.nationBreakdown[apt.nation] = (landscape.nationBreakdown[apt.nation] || 0) + 1;
    for (var t = 0; t < apt.targets.length; t++) {
      landscape.targetBreakdown[apt.targets[t]] = (landscape.targetBreakdown[apt.targets[t]] || 0) + 1;
    }
    for (var tp = 0; tp < apt.ttps.length; tp++) {
      landscape.tacticsUsed[apt.ttps[tp]] = (landscape.tacticsUsed[apt.ttps[tp]] || 0) + 1;
    }
  }

  for (var c = 0; c < APT_CAMPAIGNS.length; c++) {
    if (APT_CAMPAIGNS[c].status === 'active') landscape.recentCampaigns++;
  }

  return landscape;
}

function analyzeSupplyChainRisk() {
  var analysis = {
    totalComponents: SUPPLY_CHAIN.length,
    criticalRisk: 0,
    highRisk: 0,
    mediumRisk: 0,
    lowRisk: 0,
    totalVulns: 0,
    avgRiskScore: 0,
    categoryRisks: {},
    vendorConcentration: {},
    outdatedAudits: 0
  };

  var totalScore = 0;
  var now = new Date();
  for (var i = 0; i < SUPPLY_CHAIN.length; i++) {
    var comp = SUPPLY_CHAIN[i];
    totalScore += comp.riskScore;
    if (comp.riskScore >= 40) analysis.criticalRisk++;
    else if (comp.riskScore >= 25) analysis.highRisk++;
    else if (comp.riskScore >= 15) analysis.mediumRisk++;
    else analysis.lowRisk++;
    analysis.totalVulns += comp.vulns.length;
    if (!analysis.categoryRisks[comp.category]) {
      analysis.categoryRisks[comp.category] = {count: 0, totalRisk: 0, vulns: 0};
    }
    analysis.categoryRisks[comp.category].count++;
    analysis.categoryRisks[comp.category].totalRisk += comp.riskScore;
    analysis.categoryRisks[comp.category].vulns += comp.vulns.length;
    analysis.vendorConcentration[comp.vendor] = (analysis.vendorConcentration[comp.vendor] || 0) + 1;
    var auditDate = new Date(comp.lastAudit);
    var daysSinceAudit = Math.floor((now - auditDate) / (1000 * 60 * 60 * 24));
    if (daysSinceAudit > 90) analysis.outdatedAudits++;
  }
  analysis.avgRiskScore = Math.round(totalScore / SUPPLY_CHAIN.length);

  return analysis;
}

function analyzeGeoRisk() {
  var analysis = {
    criticalRegions: [],
    highProbEvents: [],
    correlatedTriggers: [],
    totalRiskScore: 0
  };

  for (var i = 0; i < GEO_TRIGGERS.length; i++) {
    var trigger = GEO_TRIGGERS[i];
    if (trigger.escalationRisk === 'critical') {
      analysis.criticalRegions.push(trigger);
    }
    if (trigger.probability >= 60) {
      analysis.highProbEvents.push(trigger);
    }
    analysis.totalRiskScore += trigger.probability * (
      trigger.escalationRisk === 'critical' ? 4 :
      trigger.escalationRisk === 'high' ? 3 :
      trigger.escalationRisk === 'medium' ? 2 : 1
    );
  }

  for (var j = 0; j < GEO_TRIGGERS.length; j++) {
    for (var k = j + 1; k < GEO_TRIGGERS.length; k++) {
      var overlap = false;
      for (var a = 0; a < GEO_TRIGGERS[j].relatedAPTs.length; a++) {
        if (GEO_TRIGGERS[k].relatedAPTs.indexOf(GEO_TRIGGERS[j].relatedAPTs[a]) !== -1) {
          overlap = true;
          break;
        }
      }
      if (overlap) {
        analysis.correlatedTriggers.push({
          trigger1: GEO_TRIGGERS[j].id,
          trigger2: GEO_TRIGGERS[k].id,
          sharedAPTs: GEO_TRIGGERS[j].relatedAPTs.filter(function(apt) {
            return GEO_TRIGGERS[k].relatedAPTs.indexOf(apt) !== -1;
          })
        });
      }
    }
  }

  return analysis;
}

function simulateMultiNodeCascade(nodeIds, attackType) {
  var allAffected = [];
  var allTimelines = [];
  var minute = 0;

  for (var n = 0; n < nodeIds.length; n++) {
    var result = getCascade(nodeIds[n], attackType);
    for (var a = 0; a < result.affected.length; a++) {
      if (allAffected.indexOf(result.affected[a]) === -1) {
        allAffected.push(result.affected[a]);
      }
    }
    for (var t = 0; t < result.timeline.length; t++) {
      allTimelines.push({
        minute: result.timeline[t].minute + (n * 5),
        node: result.timeline[t].node,
        effect: result.timeline[t].effect,
        origin: nodeIds[n]
      });
    }
  }

  allTimelines.sort(function(a, b) { return a.minute - b.minute; });

  var totalPop = getTotalPopulation(allAffected);
  var sectorBreakdown = countBySector(allAffected);

  return {
    affected: allAffected,
    timeline: allTimelines,
    totalPopulation: totalPop,
    sectorBreakdown: sectorBreakdown,
    economicImpact: totalPop * randInt(100, 300),
    duration: allTimelines.length > 0 ? allTimelines[allTimelines.length - 1].minute : 0
  };
}

function findCriticalPath(sourceId, targetId) {
  var visited = {};
  var queue = [{node: sourceId, path: [sourceId], cost: 0}];
  visited[sourceId] = true;

  while (queue.length > 0) {
    var current = queue.shift();
    if (current.node === targetId) {
      return current;
    }

    var dependents = getDependents(current.node);
    var deps = getNodeById(current.node);
    var neighbors = [];

    for (var d = 0; d < dependents.length; d++) {
      neighbors.push(dependents[d].id);
    }
    if (deps) {
      for (var dp = 0; dp < deps.deps.length; dp++) {
        neighbors.push(deps.deps[dp]);
      }
    }

    for (var n = 0; n < neighbors.length; n++) {
      if (!visited[neighbors[n]]) {
        visited[neighbors[n]] = true;
        var neighborNode = getNodeById(neighbors[n]);
        var cost = current.cost + (neighborNode ? (10 - neighborNode.criticality) : 5);
        queue.push({
          node: neighbors[n],
          path: current.path.concat([neighbors[n]]),
          cost: cost
        });
      }
    }
  }

  return {node: targetId, path: [], cost: -1};
}

function assessRecoveryOrder(affectedNodes) {
  var nodes = [];
  for (var i = 0; i < affectedNodes.length; i++) {
    var node = getNodeById(affectedNodes[i]);
    if (node) {
      var depCount = 0;
      for (var d = 0; d < node.deps.length; d++) {
        if (affectedNodes.indexOf(node.deps[d]) !== -1) depCount++;
      }
      nodes.push({
        id: node.id,
        name: node.name,
        sector: node.sector,
        criticality: node.criticality,
        population: node.population,
        unresolvedDeps: depCount,
        priority: node.criticality * 10 + node.population / 100000 - depCount * 5
      });
    }
  }

  nodes.sort(function(a, b) {
    if (a.unresolvedDeps !== b.unresolvedDeps) return a.unresolvedDeps - b.unresolvedDeps;
    return b.priority - a.priority;
  });

  return nodes;
}

function generateExerciseScore(actions) {
  var scores = {detection: 0, containment: 0, recovery: 0, reporting: 0, total: 0};
  var maxScores = {detection: 25, containment: 25, recovery: 30, reporting: 20};

  if (actions.detectionTime < 15) scores.detection = 25;
  else if (actions.detectionTime < 30) scores.detection = 20;
  else if (actions.detectionTime < 60) scores.detection = 15;
  else scores.detection = 10;

  if (actions.containmentTime < 30) scores.containment = 25;
  else if (actions.containmentTime < 60) scores.containment = 20;
  else if (actions.containmentTime < 120) scores.containment = 15;
  else scores.containment = 10;

  if (actions.recoveryTime < 240) scores.recovery = 30;
  else if (actions.recoveryTime < 480) scores.recovery = 25;
  else if (actions.recoveryTime < 1440) scores.recovery = 15;
  else scores.recovery = 10;

  scores.reporting = actions.reportQuality || 15;
  scores.total = scores.detection + scores.containment + scores.recovery + scores.reporting;

  return scores;
}

function getIntelCorrelations(feedId) {
  var feed = null;
  for (var i = 0; i < INTEL_FEEDS.length; i++) {
    if (INTEL_FEEDS[i].id === feedId) { feed = INTEL_FEEDS[i]; break; }
  }
  if (!feed) return [];

  var correlations = [];
  for (var j = 0; j < INTEL_FEEDS.length; j++) {
    if (INTEL_FEEDS[j].id === feedId) continue;
    var isRelated = feed.related.indexOf(INTEL_FEEDS[j].id) !== -1 ||
                    INTEL_FEEDS[j].related.indexOf(feedId) !== -1;
    if (isRelated) {
      correlations.push(INTEL_FEEDS[j]);
    }
  }
  return correlations;
}

function buildDependencyTree(nodeId, depth, maxDepth) {
  if (depth > (maxDepth || 5)) return null;
  var node = getNodeById(nodeId);
  if (!node) return null;

  var children = [];
  var dependents = getDependents(nodeId);
  for (var i = 0; i < dependents.length; i++) {
    var child = buildDependencyTree(dependents[i].id, depth + 1, maxDepth);
    if (child) children.push(child);
  }

  return {
    id: node.id,
    name: node.name,
    sector: node.sector,
    criticality: node.criticality,
    status: node.status,
    children: children
  };
}

function estimateRecoveryTime(affectedNodes) {
  var baseTime = 0;
  for (var i = 0; i < affectedNodes.length; i++) {
    var node = getNodeById(affectedNodes[i]);
    if (!node) continue;
    if (node.type === 'nuclear' || node.type === 'nuclear_cmd') baseTime += 480;
    else if (node.type === 'scada' || node.type === 'control') baseTime += 240;
    else if (node.criticality >= 9) baseTime += 120;
    else if (node.criticality >= 7) baseTime += 60;
    else baseTime += 30;
  }
  return baseTime;
}

function calculateEconomicImpact(affectedNodes, durationMinutes) {
  var totalPop = getTotalPopulation(affectedNodes);
  var sectors = countBySector(affectedNodes);

  var baseCost = totalPop * 10;
  if (sectors.FINANCIAL) baseCost *= 3;
  if (sectors.ENERGY) baseCost *= 2;
  if (sectors.HEALTHCARE) baseCost *= 2.5;
  if (sectors.GOVERNMENT) baseCost *= 1.5;

  var durationMultiplier = 1 + (durationMinutes / 60) * 0.5;
  return Math.round(baseCost * durationMultiplier);
}


// ============================================================================
// ADVANCED THREAT HUNTING QUERIES
// ============================================================================
var HUNT_QUERIES = [
  {id:'HQ01',name:'Anomalous SCADA Commands',description:'Detect Modbus write commands to PLC registers outside normal operating ranges',query:'protocol=modbus AND function_code IN (5,6,15,16) AND register_value NOT IN (normal_range)',dataSource:'OT Network Monitor',mitre:'T1059',priority:'critical',schedule:'continuous',lastRun:'2026-09-13T02:00:00Z',results:3},
  {id:'HQ02',name:'Living-off-the-Land Detection',description:'Identify suspicious use of legitimate system tools for malicious purposes',query:'process.name IN (certutil,mshta,regsvr32,rundll32,wmic,cscript,wscript,msiexec) AND parent NOT IN (expected_parents)',dataSource:'EDR/Sysmon',mitre:'T1218',priority:'high',schedule:'every 15 min',lastRun:'2026-09-13T01:45:00Z',results:12},
  {id:'HQ03',name:'Beacon Pattern Detection',description:'Identify periodic C2 beacon patterns using statistical analysis of connection timing',query:'SELECT src_ip, dst_ip, COUNT(*) as conns, STDDEV(interval_seconds) as jitter FROM flows WHERE jitter < 5 GROUP BY src_ip, dst_ip HAVING conns > 100',dataSource:'Network Flows',mitre:'T1071',priority:'high',schedule:'every 30 min',lastRun:'2026-09-13T01:30:00Z',results:2},
  {id:'HQ04',name:'Credential Access Patterns',description:'Hunt for LSASS access, SAM dump, and credential harvesting techniques',query:'event.code IN (4624,4625,4648,4672) AND logon_type IN (3,10) AND NOT src_ip IN (known_admin_hosts)',dataSource:'Windows Security',mitre:'T1003',priority:'critical',schedule:'every 5 min',lastRun:'2026-09-13T01:55:00Z',results:8},
  {id:'HQ05',name:'DNS Exfiltration Hunt',description:'Detect DNS queries with unusual length, entropy, or frequency indicative of data exfiltration',query:'dns.query_length > 50 OR dns.subdomain_entropy > 3.5 OR dns.query_count_per_minute > 100',dataSource:'DNS Logs',mitre:'T1048',priority:'high',schedule:'every 10 min',lastRun:'2026-09-13T01:50:00Z',results:5},
  {id:'HQ06',name:'Lateral Movement via RDP',description:'Detect unusual RDP connections from non-admin workstations or at unusual hours',query:'event.code=4624 AND logon_type=10 AND NOT src_ip IN (admin_workstations) OR time NOT IN (business_hours)',dataSource:'Windows Security',mitre:'T1021.001',priority:'medium',schedule:'every 15 min',lastRun:'2026-09-13T01:45:00Z',results:4},
  {id:'HQ07',name:'WMI Persistence Hunt',description:'Detect WMI event subscriptions used for persistence mechanisms',query:'event.code IN (19,20,21) AND NOT consumer IN (known_legitimate)',dataSource:'Sysmon',mitre:'T1546.003',priority:'high',schedule:'every 30 min',lastRun:'2026-09-13T01:30:00Z',results:1},
  {id:'HQ08',name:'Suspicious PowerShell Execution',description:'Detect encoded, obfuscated, or download-cradle PowerShell executions',query:'process.name=powershell.exe AND (command_line CONTAINS "-enc" OR command_line CONTAINS "IEX" OR command_line CONTAINS "DownloadString")',dataSource:'PowerShell Logging',mitre:'T1059.001',priority:'high',schedule:'every 5 min',lastRun:'2026-09-13T01:55:00Z',results:7},
  {id:'HQ09',name:'Network Share Discovery',description:'Detect enumeration of network shares which may indicate reconnaissance',query:'event.code=5140 AND DISTINCT(share_name) > 5 PER (src_ip, 10min)',dataSource:'Windows Security',mitre:'T1135',priority:'medium',schedule:'every 15 min',lastRun:'2026-09-13T01:45:00Z',results:3},
  {id:'HQ10',name:'Abnormal Process Tree',description:'Identify suspicious parent-child process relationships',query:'(parent=winword.exe AND child IN (cmd,powershell,wscript)) OR (parent=svchost.exe AND child=cmd.exe AND NOT expected)',dataSource:'Sysmon',mitre:'T1059',priority:'critical',schedule:'continuous',lastRun:'2026-09-13T02:00:00Z',results:1},
  {id:'HQ11',name:'Certificate Anomaly',description:'Detect SSL/TLS connections using self-signed or recently created certificates',query:'tls.cert.not_before > (now - 7d) OR tls.cert.issuer = tls.cert.subject',dataSource:'Network Monitor',mitre:'T1587.003',priority:'medium',schedule:'every 30 min',lastRun:'2026-09-13T01:30:00Z',results:15},
  {id:'HQ12',name:'Cloud Token Theft',description:'Detect use of cloud service tokens from unusual locations or IP addresses',query:'cloud.event=AssumeRole AND src_ip NOT IN (known_corporate_ips) AND user NOT IN (service_accounts)',dataSource:'Cloud Trail',mitre:'T1550.001',priority:'high',schedule:'every 10 min',lastRun:'2026-09-13T01:50:00Z',results:2},
  {id:'HQ13',name:'Firmware Integrity Check',description:'Verify PLC and RTU firmware hashes against known-good baselines',query:'ics.device_type IN (plc,rtu) AND firmware_hash NOT IN (baseline_hashes)',dataSource:'ICS Monitor',mitre:'T0839',priority:'critical',schedule:'every 1 hour',lastRun:'2026-09-13T01:00:00Z',results:0},
  {id:'HQ14',name:'BGP Route Anomaly',description:'Detect unexpected BGP announcements or route hijacking attempts',query:'bgp.event=announcement AND prefix NOT IN (expected_prefixes) OR origin_as NOT IN (expected_origins)',dataSource:'BGP Monitor',mitre:'T1557',priority:'critical',schedule:'continuous',lastRun:'2026-09-13T02:00:00Z',results:1},
  {id:'HQ15',name:'Data Staging Detection',description:'Identify large archive file creation in temp or user directories',query:'file.extension IN (zip,7z,rar,tar.gz) AND file.size > 100MB AND file.path CONTAINS (temp,appdata)',dataSource:'EDR',mitre:'T1074',priority:'high',schedule:'every 15 min',lastRun:'2026-09-13T01:45:00Z',results:3}
];

// ============================================================================
// THREAT INTELLIGENCE INDICATORS OF COMPROMISE
// ============================================================================
var IOC_DATABASE = [
  {type:'ip',value:'185.220.101.42',threat:'APT28',confidence:'high',firstSeen:'2026-07-15',lastSeen:'2026-09-13',source:'NSA/CSS',tags:['C2','Scanning']},
  {type:'ip',value:'185.220.101.43',threat:'APT28',confidence:'high',firstSeen:'2026-07-15',lastSeen:'2026-09-12',source:'NSA/CSS',tags:['C2']},
  {type:'ip',value:'185.220.101.44',threat:'APT28',confidence:'medium',firstSeen:'2026-08-01',lastSeen:'2026-09-11',source:'Mandiant',tags:['Infrastructure']},
  {type:'ip',value:'91.219.237.13',threat:'Sandworm',confidence:'high',firstSeen:'2026-08-10',lastSeen:'2026-09-13',source:'GCHQ',tags:['C2','Exfiltration']},
  {type:'ip',value:'91.219.237.14',threat:'Sandworm',confidence:'high',firstSeen:'2026-08-10',lastSeen:'2026-09-12',source:'GCHQ',tags:['Staging']},
  {type:'ip',value:'91.219.237.15',threat:'Sandworm',confidence:'medium',firstSeen:'2026-08-15',lastSeen:'2026-09-10',source:'US-CERT',tags:['Scanning']},
  {type:'ip',value:'45.155.205.88',threat:'Unknown',confidence:'medium',firstSeen:'2026-09-01',lastSeen:'2026-09-13',source:'Honeypot',tags:['Credential Testing']},
  {type:'ip',value:'193.42.111.27',threat:'Turla',confidence:'low',firstSeen:'2026-09-05',lastSeen:'2026-09-13',source:'Honeypot',tags:['DNS Recon']},
  {type:'ip',value:'77.83.247.91',threat:'APT28',confidence:'medium',firstSeen:'2026-09-08',lastSeen:'2026-09-13',source:'NCSC',tags:['VPN Probing']},
  {type:'ip',value:'212.193.30.15',threat:'APT29',confidence:'low',firstSeen:'2026-09-10',lastSeen:'2026-09-13',source:'Honeypot',tags:['Credential Testing']},
  {type:'ip',value:'103.75.190.11',threat:'OceanLotus',confidence:'medium',firstSeen:'2026-09-11',lastSeen:'2026-09-13',source:'VirusTotal',tags:['C2 Callback']},
  {type:'domain',value:'update-service-cdn[.]com',threat:'APT28',confidence:'high',firstSeen:'2026-07-20',lastSeen:'2026-09-12',source:'Mandiant',tags:['C2','Phishing']},
  {type:'domain',value:'secure-microsoft-auth[.]net',threat:'APT28',confidence:'high',firstSeen:'2026-08-01',lastSeen:'2026-09-10',source:'US-CERT',tags:['Credential Harvesting']},
  {type:'domain',value:'api-cloud-services[.]com',threat:'APT29',confidence:'high',firstSeen:'2026-06-15',lastSeen:'2026-09-11',source:'CrowdStrike',tags:['C2']},
  {type:'domain',value:'global-dns-resolver[.]net',threat:'Sandworm',confidence:'medium',firstSeen:'2026-08-20',lastSeen:'2026-09-13',source:'GCHQ',tags:['C2']},
  {type:'domain',value:'scada-firmware-update[.]com',threat:'Sandworm',confidence:'high',firstSeen:'2026-09-01',lastSeen:'2026-09-12',source:'CISA',tags:['Malware Delivery']},
  {type:'domain',value:'blockchain-exchange-api[.]io',threat:'Lazarus',confidence:'high',firstSeen:'2026-08-15',lastSeen:'2026-09-10',source:'FBI',tags:['Crypto Theft']},
  {type:'domain',value:'defi-protocol-bridge[.]org',threat:'Lazarus',confidence:'high',firstSeen:'2026-09-01',lastSeen:'2026-09-09',source:'FBI',tags:['Crypto Theft']},
  {type:'hash',value:'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',threat:'Sandworm',confidence:'high',firstSeen:'2026-09-01',lastSeen:'2026-09-12',source:'CISA',tags:['Industroyer2 Variant']},
  {type:'hash',value:'f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5',threat:'Sandworm',confidence:'high',firstSeen:'2026-09-05',lastSeen:'2026-09-11',source:'Dragos',tags:['CaddyWiper Variant']},
  {type:'hash',value:'1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',threat:'APT28',confidence:'high',firstSeen:'2026-07-15',lastSeen:'2026-09-13',source:'NSA/CSS',tags:['X-Agent Variant']},
  {type:'hash',value:'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',threat:'APT29',confidence:'high',firstSeen:'2026-06-01',lastSeen:'2026-09-11',source:'Mandiant',tags:['MagicWeb']},
  {type:'hash',value:'deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678',threat:'Lazarus',confidence:'high',firstSeen:'2026-08-15',lastSeen:'2026-09-10',source:'FBI',tags:['TraderTraitor']},
  {type:'hash',value:'cafebabe12345678cafebabe12345678cafebabe12345678cafebabe12345678',threat:'APT41',confidence:'high',firstSeen:'2026-05-20',lastSeen:'2026-09-09',source:'Unit 42',tags:['ShadowPad Variant']},
  {type:'hash',value:'0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',threat:'Kimsuky',confidence:'medium',firstSeen:'2026-09-01',lastSeen:'2026-09-06',source:'ACSC',tags:['Custom Backdoor']},
  {type:'yara',value:'rule Industroyer2_variant { strings: $a = { 68 65 6C 6C 6F 20 77 6F 72 6C 64 } condition: $a }',threat:'Sandworm',confidence:'high',firstSeen:'2026-09-01',lastSeen:'2026-09-12',source:'CISA',tags:['ICS Malware']},
  {type:'yara',value:'rule XAgent_beacon { strings: $s1 = "POST /api/v1/check" condition: $s1 }',threat:'APT28',confidence:'high',firstSeen:'2026-07-15',lastSeen:'2026-09-13',source:'NSA/CSS',tags:['Beacon Pattern']},
  {type:'snort',value:'alert tcp any any -> any 502 (msg:"Modbus Write Multiple Registers - Suspicious"; content:"|00 00 00 00 00|"; offset:0; depth:5; sid:1000001; rev:1;)',threat:'ICS Attack',confidence:'medium',firstSeen:'2026-08-01',lastSeen:'2026-09-13',source:'ICS-CERT',tags:['SCADA']},
  {type:'snort',value:'alert tcp any any -> any 4840 (msg:"OPC-UA Suspicious Read Request"; content:"|4F 50 43|"; sid:1000002; rev:1;)',threat:'ICS Attack',confidence:'medium',firstSeen:'2026-08-15',lastSeen:'2026-09-12',source:'ICS-CERT',tags:['SCADA']},
  {type:'email',value:'security-update@microsoft-support-center[.]com',threat:'APT28',confidence:'high',firstSeen:'2026-08-01',lastSeen:'2026-09-10',source:'CISA',tags:['Phishing']},
  {type:'email',value:'admin@cloud-service-portal[.]net',threat:'APT29',confidence:'medium',firstSeen:'2026-07-01',lastSeen:'2026-09-08',source:'FBI',tags:['Phishing']},
  {type:'email',value:'support@blockchain-verify[.]io',threat:'Lazarus',confidence:'high',firstSeen:'2026-08-20',lastSeen:'2026-09-05',source:'FBI',tags:['Social Engineering']},
  {type:'mutex',value:'Global\\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}',threat:'APT28',confidence:'high',firstSeen:'2026-07-15',lastSeen:'2026-09-13',source:'Mandiant',tags:['X-Agent']},
  {type:'mutex',value:'Global\\ShadowPadMtx2026',threat:'APT41',confidence:'high',firstSeen:'2026-05-15',lastSeen:'2026-09-09',source:'Unit 42',tags:['ShadowPad']},
  {type:'registry',value:'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemHealthMonitor',threat:'Sandworm',confidence:'high',firstSeen:'2026-09-01',lastSeen:'2026-09-12',source:'CISA',tags:['Persistence']},
  {type:'registry',value:'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\CloudSync',threat:'APT29',confidence:'medium',firstSeen:'2026-06-01',lastSeen:'2026-09-11',source:'CrowdStrike',tags:['Persistence']},
  {type:'useragent',value:'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36 Edg/90.0.818.66',threat:'APT28',confidence:'low',firstSeen:'2026-07-15',lastSeen:'2026-09-13',source:'Proxy Logs',tags:['C2 Communication']},
  {type:'certificate',value:'CN=Microsoft Update Service, O=Microsoft Corporation (FAKE)',threat:'APT28',confidence:'high',firstSeen:'2026-08-01',lastSeen:'2026-09-12',source:'CT Logs',tags:['Fake Certificate']},
  {type:'certificate',value:'CN=cloud-services-auth.net, O=Cloud Services Inc (FAKE)',threat:'APT29',confidence:'high',firstSeen:'2026-06-15',lastSeen:'2026-09-11',source:'CT Logs',tags:['Fake Certificate']},
  {type:'url',value:'hxxps://update-service-cdn[.]com/api/v2/check?id=',threat:'APT28',confidence:'high',firstSeen:'2026-07-20',lastSeen:'2026-09-12',source:'Mandiant',tags:['C2 Endpoint']}
];

// ============================================================================
// EXTENDED SITUATION AWARENESS DATA
// ============================================================================
var GLOBAL_ALERTS_EXTENDED = [
  {time:'2026-09-13T02:14:00Z',severity:'CRITICAL',source:'NSA/CSS',message:'SIGINT intercept confirms imminent Sandworm operation against European energy grid',sector:'ENERGY',actionRequired:true},
  {time:'2026-09-13T01:45:00Z',severity:'HIGH',source:'CISA',message:'Emergency directive issued for immediate patching of PAN-OS CVE-2024-3400 across all federal networks',sector:'GOVERNMENT',actionRequired:true},
  {time:'2026-09-13T01:30:00Z',severity:'HIGH',source:'FBI',message:'Flash alert: LockBit 4.0 variant with wiper capability targeting healthcare sector this weekend',sector:'HEALTHCARE',actionRequired:true},
  {time:'2026-09-13T01:00:00Z',severity:'CRITICAL',source:'ODNI',message:'National intelligence estimate: China has pre-positioned destructive access across US CI for Taiwan contingency',sector:'ALL',actionRequired:true},
  {time:'2026-09-12T22:30:00Z',severity:'HIGH',source:'NCSC-UK',message:'Active exploitation detected: zero-day in enterprise email gateway affecting multiple government departments',sector:'GOVERNMENT',actionRequired:true},
  {time:'2026-09-12T20:00:00Z',severity:'MEDIUM',source:'US-CERT',message:'Advisory: Increased scanning from Chinese IP space targeting Fortinet and Ivanti VPN endpoints',sector:'TELECOM',actionRequired:false},
  {time:'2026-09-12T18:00:00Z',severity:'HIGH',source:'ICS-CERT',message:'Critical vulnerabilities discovered in Schneider Electric Modicon PLCs affecting water and energy SCADA',sector:'WATER',actionRequired:true},
  {time:'2026-09-12T16:00:00Z',severity:'MEDIUM',source:'Recorded Future',message:'Dark web listing: zero-day exploit for Palo Alto GlobalProtect, asking price $2.5M',sector:'ALL',actionRequired:false},
  {time:'2026-09-12T14:00:00Z',severity:'HIGH',source:'CrowdStrike',message:'Scattered Spider campaign targeting telecom providers via SIM swapping and social engineering',sector:'TELECOM',actionRequired:true},
  {time:'2026-09-12T12:00:00Z',severity:'CRITICAL',source:'DIA',message:'Intelligence indicates DPRK cyber operators relocated to joint facility in Shenyang for combined operations',sector:'FINANCIAL',actionRequired:false},
  {time:'2026-09-12T10:00:00Z',severity:'HIGH',source:'ACSC',message:'Salt Typhoon access to telecom infrastructure more extensive than assessed - includes lawful intercept systems',sector:'TELECOM',actionRequired:true},
  {time:'2026-09-12T08:00:00Z',severity:'MEDIUM',source:'Shodan',message:'Spike in scanning activity targeting telecom infrastructure from Chinese IP ranges',sector:'TELECOM',actionRequired:false},
  {time:'2026-09-11T22:00:00Z',severity:'CRITICAL',source:'NSA/CSS',message:'Volt Typhoon infrastructure expanded with 200+ new compromised SOHO routers in Southeast Asia',sector:'TELECOM',actionRequired:true},
  {time:'2026-09-11T20:00:00Z',severity:'HIGH',source:'Europol',message:'LockBit affiliate program restructuring with focus on critical infrastructure targets in Western Europe',sector:'ALL',actionRequired:false},
  {time:'2026-09-11T18:00:00Z',severity:'MEDIUM',source:'Mossad',message:'Iranian cyber operators testing destructive malware against simulated water treatment environment',sector:'WATER',actionRequired:false}
];

// ============================================================================
// RISK MATRIX DATA
// ============================================================================
var RISK_MATRIX = {
  likelihood: ['Rare','Unlikely','Possible','Likely','Almost Certain'],
  consequence: ['Insignificant','Minor','Moderate','Major','Catastrophic'],
  ratings: [
    [1,2,3,4,5],
    [2,4,6,8,10],
    [3,6,9,12,15],
    [4,8,12,16,20],
    [5,10,15,20,25]
  ],
  thresholds: {
    low: {max: 4, color: '#00ff88', label: 'LOW'},
    medium: {max: 9, color: '#ffaa00', label: 'MEDIUM'},
    high: {max: 15, color: '#ff6600', label: 'HIGH'},
    critical: {max: 25, color: '#ff0040', label: 'CRITICAL'}
  }
};

function getRiskLevel(score) {
  if (score <= RISK_MATRIX.thresholds.low.max) return RISK_MATRIX.thresholds.low;
  if (score <= RISK_MATRIX.thresholds.medium.max) return RISK_MATRIX.thresholds.medium;
  if (score <= RISK_MATRIX.thresholds.high.max) return RISK_MATRIX.thresholds.high;
  return RISK_MATRIX.thresholds.critical;
}

// ============================================================================
// BATTLE DAMAGE ASSESSMENT TEMPLATES
// ============================================================================
var BDA_TEMPLATES = [
  {id:'BDA01',opName:'IRON SHIELD',date:'2026-09-12',type:'Defensive',classification:'TS/SCI',
    targets:[{node:'PG16',status:'defended',damage:'none'},{node:'EN19',status:'defended',damage:'minor'}],
    adversary:{name:'Sandworm',unit:'GRU Unit 74455',confidence:'HIGH'},
    timeline:[
      {time:'T-72h',event:'Intelligence warning of imminent operation'},
      {time:'T-24h',event:'Enhanced monitoring deployed on SCADA systems'},
      {time:'T-0h',event:'Initial intrusion attempt detected and blocked'},
      {time:'T+2h',event:'Secondary attack vector identified and contained'},
      {time:'T+6h',event:'All adversary access eliminated'},
      {time:'T+12h',event:'Full forensic collection completed'},
      {time:'T+24h',event:'After action review initiated'}
    ],
    evidence:['Network captures (2.3 GB)','Malware samples (3)','SIEM logs (45K events)','Memory dumps (2)'],
    lessonsLearned:['SCADA monitoring detected anomaly within 2 minutes','Need improved OT/IT boundary monitoring','Cross-sector communication was effective'],
    recommendations:['Deploy additional OT sensors','Update ICS incident response playbook','Conduct quarterly SCADA security exercises']
  },
  {id:'BDA02',opName:'MIDNIGHT WATCH',date:'2026-09-08',type:'Intelligence Collection',classification:'TS/SCI',
    targets:[{node:'TC14',status:'monitored',damage:'none'},{node:'TC03',status:'monitored',damage:'none'}],
    adversary:{name:'APT29',unit:'SVR',confidence:'HIGH'},
    timeline:[
      {time:'T-1w',event:'Threat intelligence indicated cloud targeting campaign'},
      {time:'T-3d',event:'Hunt team deployed to cloud environments'},
      {time:'T-1d',event:'Suspicious OAuth application identified'},
      {time:'T+0h',event:'Adversary backdoor discovered in Azure AD'},
      {time:'T+4h',event:'All compromised tokens revoked'},
      {time:'T+8h',event:'Adversary evicted from cloud environment'},
      {time:'T+24h',event:'Post-compromise assessment completed'}
    ],
    evidence:['Cloud audit logs (120K events)','OAuth app analysis','Token usage timeline','Lateral movement map'],
    lessonsLearned:['Cloud-native detection capabilities insufficient','Need MFA on all service accounts','Third-party app review process needs improvement'],
    recommendations:['Implement cloud CASB','Deploy cloud-specific EDR','Quarterly OAuth app audit']
  }
];

// ============================================================================
// COMMUNICATION TEMPLATES
// ============================================================================
var COMMS_TEMPLATES = {
  sectors: {
    internal: [
      {name:'SOC Alert',audience:'SOC Team',urgency:'Immediate',template:'[SEVERITY] alert detected on [SYSTEM]. [DESCRIPTION]. Immediate investigation required. Reference: [TICKET]'},
      {name:'Executive Brief',audience:'C-Suite',urgency:'Within 1 hour',template:'EXECUTIVE CYBER BRIEF\nIncident: [SUMMARY]\nImpact: [IMPACT]\nStatus: [STATUS]\nActions: [ACTIONS]\nNext Update: [TIME]'},
      {name:'Board Notification',audience:'Board of Directors',urgency:'Within 4 hours',template:'BOARD NOTIFICATION - CYBER INCIDENT\nDate: [DATE]\nSeverity: [SEVERITY]\nBusiness Impact: [IMPACT]\nResponse Status: [STATUS]\nRegulatory Implications: [REGULATORY]'},
      {name:'All-Hands Update',audience:'All Employees',urgency:'As needed',template:'IMPORTANT: Cybersecurity Incident Update\nWe are aware of [SITUATION]. Our security team is actively responding. [INSTRUCTIONS]. For questions, contact [CONTACT].'}
    ],
    external: [
      {name:'CISA Notification',audience:'CISA',urgency:'Within 72 hours',template:'CISA INCIDENT REPORT\nOrganization: [ORG]\nIncident Type: [TYPE]\nDate Detected: [DATE]\nImpact: [IMPACT]\nIOCs: [IOCS]\nAssistance Requested: [ASSISTANCE]'},
      {name:'FBI Notification',audience:'FBI Cyber Division',urgency:'As appropriate',template:'FBI CYBER INCIDENT REPORT\nIC3 Reference: [REF]\nIncident Description: [DESCRIPTION]\nSuspected Attribution: [ATTRIBUTION]\nEvidence Available: [EVIDENCE]'},
      {name:'ISAC Alert',audience:'Sector ISAC',urgency:'Within 24 hours',template:'ISAC MEMBER ALERT\nThreat: [THREAT]\nIOCs: [IOCS]\nRecommended Actions: [ACTIONS]\nConfidence: [CONFIDENCE]'},
      {name:'Press Statement',audience:'Media',urgency:'As directed by PAO',template:'[ORG] is aware of a cybersecurity incident affecting [SCOPE]. We are working with law enforcement and cybersecurity experts to investigate and respond. [CUSTOMER_IMPACT]. We will provide updates as appropriate.'}
    ]
  }
};

// ============================================================================
// FINAL UTILITY: RENDER HELPERS FOR EXTENDED DATA
// ============================================================================
function renderActorDetail(aptId) {
  var profile = null;
  for (var i = 0; i < ACTOR_PROFILES.length; i++) {
    if (ACTOR_PROFILES[i].aptId === aptId) { profile = ACTOR_PROFILES[i]; break; }
  }
  if (!profile) return '<div class="pm-no-data">No detailed profile available for this actor</div>';

  var apt = getAPTById(aptId);
  var campaigns = getCampaignsForAPT(aptId);
  var techniques = getTechniquesForAPT(aptId);

  var html = '<div class="pm-actor-card">' +
    '<div class="pm-actor-name">' + esc(apt ? apt.name : aptId) + '</div>' +
    '<div class="pm-actor-nation pm-mb-8">' + esc(apt ? apt.nation : 'Unknown') + ' | Threat Level: ' + esc(apt ? String(apt.threatLevel) : '?') + '/10</div>' +
    '<div class="pm-text-sm pm-mb-12">' + esc(profile.overview) + '</div>' +
    '<div class="pm-label">Motivation</div><div class="pm-text-sm pm-mb-12">' + esc(profile.motivation) + '</div>';

  if (profile.tools && profile.tools.length > 0) {
    html += '<div class="pm-label pm-mb-8">Tools & Malware</div><div class="pm-flex-wrap pm-mb-12">';
    for (var t = 0; t < profile.tools.length; t++) {
      html += '<span class="pm-tag">' + esc(profile.tools[t]) + '</span>';
    }
    html += '</div>';
  }

  if (profile.timeline && profile.timeline.length > 0) {
    html += '<div class="pm-label pm-mb-8">Notable Operations Timeline</div><div class="pm-timeline pm-scroll-y" style="max-height:200px;">';
    for (var tl = 0; tl < profile.timeline.length; tl++) {
      html += '<div class="pm-timeline-item pm-timeline-red">' +
        '<div class="pm-timeline-time">' + esc(String(profile.timeline[tl].year)) + '</div>' +
        '<div class="pm-text-sm">' + esc(profile.timeline[tl].event) + '</div>' +
      '</div>';
    }
    html += '</div>';
  }

  if (campaigns.length > 0) {
    html += '<div class="pm-label pm-mb-8 pm-mt-12">Active Campaigns (' + esc(String(campaigns.length)) + ')</div>';
    for (var c = 0; c < campaigns.length; c++) {
      var camp = campaigns[c];
      html += '<div class="pm-campaign-card">' +
        '<div class="pm-campaign-title">' + esc(camp.name) + '</div>' +
        '<div class="pm-text-xs pm-text-muted pm-mb-8">' + esc(camp.description) + '</div>' +
        '<div class="pm-text-xs">Started: ' + esc(camp.startDate) + ' | Victims: ' + esc(String(camp.victims)) + ' | Status: <span class="pm-text-' + (camp.status === 'active' ? 'red' : 'green') + '">' + esc(camp.status) + '</span></div>' +
      '</div>';
    }
  }

  html += '</div>';
  return html;
}

function renderIOCSummary() {
  var byType = {};
  var byThreat = {};
  for (var i = 0; i < IOC_DATABASE.length; i++) {
    var ioc = IOC_DATABASE[i];
    byType[ioc.type] = (byType[ioc.type] || 0) + 1;
    byThreat[ioc.threat] = (byThreat[ioc.threat] || 0) + 1;
  }

  var html = '<div class="pm-grid-2">' +
    '<div class="pm-card"><div class="pm-card-title">IOCs by Type</div>';
  var typeKeys = Object.keys(byType);
  for (var tk = 0; tk < typeKeys.length; tk++) {
    var pct = Math.round((byType[typeKeys[tk]] / IOC_DATABASE.length) * 100);
    html += '<div class="pm-flex-between pm-mb-8"><span class="pm-text-xs">' + esc(typeKeys[tk]) + '</span><span class="pm-text-xs pm-text-muted">' + esc(String(byType[typeKeys[tk]])) + '</span></div>' +
      '<div class="pm-progress pm-mb-8"><div class="pm-progress-bar pm-progress-blue" style="width:' + pct + '%;"></div></div>';
  }
  html += '</div><div class="pm-card"><div class="pm-card-title">IOCs by Threat Actor</div>';
  var threatKeys = Object.keys(byThreat).sort(function(a, b) { return byThreat[b] - byThreat[a]; });
  for (var thk = 0; thk < threatKeys.length; thk++) {
    var tPct = Math.round((byThreat[threatKeys[thk]] / IOC_DATABASE.length) * 100);
    html += '<div class="pm-flex-between pm-mb-8"><span class="pm-text-xs">' + esc(threatKeys[thk]) + '</span><span class="pm-text-xs pm-text-muted">' + esc(String(byThreat[threatKeys[thk]])) + '</span></div>' +
      '<div class="pm-progress pm-mb-8"><div class="pm-progress-bar pm-progress-red" style="width:' + tPct + '%;"></div></div>';
  }
  html += '</div></div>';
  return html;
}

function renderComplianceOverview() {
  var html = '<div class="pm-grid-2">';
  for (var i = 0; i < COMPLIANCE_STATUS.length; i++) {
    var comp = COMPLIANCE_STATUS[i];
    var color = comp.coverage >= 90 ? '#00ff88' : (comp.coverage >= 75 ? '#ffaa00' : '#ff0040');
    html += '<div class="pm-compliance-card">' +
      '<div class="pm-flex-between pm-mb-8">' +
        '<span class="pm-text-sm pm-text-bold">' + esc(comp.framework) + '</span>' +
        '<span class="pm-badge pm-badge-' + (comp.status === 'compliant' ? 'info' : 'medium') + '">' + esc(comp.status) + '</span>' +
      '</div>' +
      '<div class="pm-compliance-bar">' +
        '<span class="pm-text-xs" style="color:' + color + ';">' + esc(String(comp.coverage)) + '%</span>' +
        '<div class="pm-progress" style="flex:1;"><div class="pm-progress-bar" style="width:' + comp.coverage + '%;background:' + color + ';"></div></div>' +
      '</div>' +
      '<div class="pm-text-xs pm-text-muted">Last Assessment: ' + esc(comp.lastAssessment) + '</div>';
    if (comp.gaps.length > 0) {
      html += '<div class="pm-text-xs pm-text-muted pm-mt-12">Gaps: ' + esc(comp.gaps.join(', ')) + '</div>';
    }
    html += '</div>';
  }
  html += '</div>';
  return html;
}

function renderHuntDashboard() {
  var html = '<div class="pm-grid-4 pm-mb-16">';
  var totalResults = 0, criticalHunts = 0, activeHunts = HUNT_QUERIES.length;
  for (var i = 0; i < HUNT_QUERIES.length; i++) {
    totalResults += HUNT_QUERIES[i].results;
    if (HUNT_QUERIES[i].priority === 'critical') criticalHunts++;
  }
  html += '<div class="pm-kpi"><div class="pm-kpi-value">' + esc(String(activeHunts)) + '</div><div class="pm-kpi-label">Active Hunts</div></div>' +
    '<div class="pm-kpi"><div class="pm-kpi-value pm-text-red">' + esc(String(criticalHunts)) + '</div><div class="pm-kpi-label">Critical Priority</div></div>' +
    '<div class="pm-kpi"><div class="pm-kpi-value pm-text-yellow">' + esc(String(totalResults)) + '</div><div class="pm-kpi-label">Total Findings</div></div>' +
    '<div class="pm-kpi"><div class="pm-kpi-value pm-text-green">' + esc(String(IOC_DATABASE.length)) + '</div><div class="pm-kpi-label">Active IOCs</div></div>' +
  '</div>';

  html += '<div class="pm-table-wrap"><table class="pm-table pm-compact pm-striped">' +
    '<tr><th>Hunt</th><th>Priority</th><th>Data Source</th><th>MITRE</th><th>Schedule</th><th>Last Run</th><th>Results</th></tr>';
  for (var h = 0; h < HUNT_QUERIES.length; h++) {
    var hunt = HUNT_QUERIES[h];
    html += '<tr>' +
      '<td>' + esc(hunt.name) + '</td>' +
      '<td><span class="pm-badge pm-badge-' + hunt.priority + '">' + esc(hunt.priority) + '</span></td>' +
      '<td class="pm-text-xs">' + esc(hunt.dataSource) + '</td>' +
      '<td class="pm-text-xs"><span class="pm-tag">' + esc(hunt.mitre) + '</span></td>' +
      '<td class="pm-text-xs">' + esc(hunt.schedule) + '</td>' +
      '<td class="pm-text-xs pm-text-muted">' + esc(fmtTime(hunt.lastRun)) + '</td>' +
      '<td class="' + (hunt.results > 0 ? 'pm-text-yellow' : 'pm-text-green') + '">' + esc(String(hunt.results)) + '</td>' +
    '</tr>';
  }
  html += '</table></div>';
  return html;
}

function renderVulnDashboard() {
  var critCount = 0, highCount = 0, kevCount = 0, exploitCount = 0;
  for (var i = 0; i < VULN_DATABASE.length; i++) {
    if (VULN_DATABASE[i].cvss >= 9.0) critCount++;
    else if (VULN_DATABASE[i].cvss >= 7.0) highCount++;
    if (VULN_DATABASE[i].kev) kevCount++;
    if (VULN_DATABASE[i].exploitAvailable) exploitCount++;
  }

  var html = '<div class="pm-grid-4 pm-mb-16">' +
    '<div class="pm-kpi"><div class="pm-kpi-value">' + esc(String(VULN_DATABASE.length)) + '</div><div class="pm-kpi-label">Tracked CVEs</div></div>' +
    '<div class="pm-kpi"><div class="pm-kpi-value pm-text-red">' + esc(String(critCount)) + '</div><div class="pm-kpi-label">Critical (9.0+)</div></div>' +
    '<div class="pm-kpi"><div class="pm-kpi-value pm-text-yellow">' + esc(String(kevCount)) + '</div><div class="pm-kpi-label">CISA KEV</div></div>' +
    '<div class="pm-kpi"><div class="pm-kpi-value pm-text-red">' + esc(String(exploitCount)) + '</div><div class="pm-kpi-label">Exploit Available</div></div>' +
  '</div>';

  html += '<div class="pm-table-wrap"><table class="pm-table pm-compact pm-striped">' +
    '<tr><th>CVE</th><th>Product</th><th>Vendor</th><th>CVSS</th><th>Type</th><th>KEV</th><th>Exploit</th><th>Patch</th><th>Affected Nodes</th></tr>';
  var sorted = VULN_DATABASE.slice().sort(function(a, b) { return b.cvss - a.cvss; });
  for (var v = 0; v < sorted.length; v++) {
    var vuln = sorted[v];
    var cvssClass = vuln.cvss >= 9.0 ? 'pm-vuln-cvss-critical' : (vuln.cvss >= 7.0 ? 'pm-vuln-cvss-high' : 'pm-vuln-cvss-medium');
    html += '<tr>' +
      '<td class="pm-text-xs pm-text-bold">' + esc(vuln.cve) + '</td>' +
      '<td class="pm-text-xs">' + esc(vuln.product) + '</td>' +
      '<td class="pm-text-xs">' + esc(vuln.vendor) + '</td>' +
      '<td class="pm-vuln-cvss ' + cvssClass + '">' + esc(String(vuln.cvss)) + '</td>' +
      '<td class="pm-text-xs">' + esc(vuln.type) + '</td>' +
      '<td>' + (vuln.kev ? '<span class="pm-text-red">YES</span>' : '<span class="pm-text-muted">No</span>') + '</td>' +
      '<td>' + (vuln.exploitAvailable ? '<span class="pm-text-red">YES</span>' : '<span class="pm-text-muted">No</span>') + '</td>' +
      '<td>' + (vuln.patchAvailable ? '<span class="pm-text-green">YES</span>' : '<span class="pm-text-red">NO</span>') + '</td>' +
      '<td class="pm-text-xs">' + esc(vuln.affectedNodes.join(', ') || 'None mapped') + '</td>' +
    '</tr>';
  }
  html += '</table></div>';
  return html;
}


// ============================================================================
// EXTENDED INFRASTRUCTURE NODE METADATA
// ============================================================================
var NODE_METADATA = {
  'PG01': {lat:39.95,lon:-75.15,altitude:0,facility:'Nuclear Generation Station Alpha',address:'Classified',securityLevel:'TS/SCI',lastInspection:'2026-08-15',personnelCount:450,backupPower:true,physicalSecurity:'Armed guards, biometric access, CCTV, motion sensors, perimeter fence',networkSegment:'10.1.1.0/24',firewallRules:28,idsSignatures:1200,lastPentest:'2026-06-01',pentestFindings:3},
  'PG02': {lat:33.74,lon:-84.39,altitude:0,facility:'Nuclear Generation Station Bravo',address:'Classified',securityLevel:'TS/SCI',lastInspection:'2026-08-20',personnelCount:380,backupPower:true,physicalSecurity:'Armed guards, biometric access, CCTV, motion sensors, perimeter fence',networkSegment:'10.1.1.0/24',firewallRules:25,idsSignatures:1200,lastPentest:'2026-06-15',pentestFindings:2},
  'PG07': {lat:40.71,lon:-74.01,altitude:0,facility:'Metro Substation 1',address:'123 Grid Ave, Metro City',securityLevel:'SECRET',lastInspection:'2026-09-01',personnelCount:25,backupPower:true,physicalSecurity:'Electronic locks, CCTV, alarm system',networkSegment:'10.1.4.0/24',firewallRules:15,idsSignatures:800,lastPentest:'2026-07-01',pentestFindings:5},
  'PG14': {lat:38.89,lon:-77.03,altitude:0,facility:'National Grid Operations Center',address:'Classified',securityLevel:'SECRET',lastInspection:'2026-09-05',personnelCount:120,backupPower:true,physicalSecurity:'Multi-factor access, CCTV, security operations center',networkSegment:'10.1.6.0/24',firewallRules:45,idsSignatures:2000,lastPentest:'2026-05-15',pentestFindings:8},
  'WT01': {lat:41.88,lon:-87.63,altitude:0,facility:'Central Water Treatment Facility',address:'500 Water St, Central City',securityLevel:'CONFIDENTIAL',lastInspection:'2026-08-25',personnelCount:85,backupPower:true,physicalSecurity:'Fence, CCTV, badge access',networkSegment:'10.2.1.0/24',firewallRules:12,idsSignatures:600,lastPentest:'2026-07-15',pentestFindings:7},
  'TC03': {lat:37.77,lon:-122.42,altitude:0,facility:'Primary Fiber Hub',address:'200 Telecom Blvd',securityLevel:'SECRET',lastInspection:'2026-09-10',personnelCount:60,backupPower:true,physicalSecurity:'Biometric access, CCTV, NOC',networkSegment:'10.3.2.0/24',firewallRules:55,idsSignatures:2500,lastPentest:'2026-06-01',pentestFindings:4},
  'TC14': {lat:39.04,lon:-77.49,altitude:0,facility:'National Internet Exchange Point',address:'Classified',securityLevel:'SECRET',lastInspection:'2026-09-08',personnelCount:45,backupPower:true,physicalSecurity:'Multi-layer access, CCTV, armed guards',networkSegment:'10.3.7.0/24',firewallRules:75,idsSignatures:3000,lastPentest:'2026-05-01',pentestFindings:6},
  'FN01': {lat:40.71,lon:-74.01,altitude:0,facility:'National Stock Exchange Data Center',address:'11 Wall St',securityLevel:'SECRET',lastInspection:'2026-09-12',personnelCount:200,backupPower:true,physicalSecurity:'Armed guards, biometric, mantrap, CCTV',networkSegment:'10.5.1.0/24',firewallRules:90,idsSignatures:3500,lastPentest:'2026-04-01',pentestFindings:2},
  'FN03': {lat:52.37,lon:4.90,altitude:0,facility:'SWIFT Gateway Operations',address:'Classified',securityLevel:'TS/SCI',lastInspection:'2026-09-01',personnelCount:30,backupPower:true,physicalSecurity:'Maximum security, multi-factor biometric',networkSegment:'10.5.2.0/24',firewallRules:120,idsSignatures:4000,lastPentest:'2026-03-01',pentestFindings:1},
  'HC01': {lat:42.36,lon:-71.06,altitude:0,facility:'Metro Hospital Network A - Data Center',address:'100 Medical Center Dr',securityLevel:'CONFIDENTIAL',lastInspection:'2026-08-20',personnelCount:150,backupPower:true,physicalSecurity:'Badge access, CCTV, visitor management',networkSegment:'10.6.1.0/24',firewallRules:35,idsSignatures:1500,lastPentest:'2026-07-01',pentestFindings:12},
  'GV01': {lat:38.89,lon:-77.03,altitude:0,facility:'SIPRNet Gateway Facility',address:'Classified',securityLevel:'TS/SCI',lastInspection:'2026-09-05',personnelCount:80,backupPower:true,physicalSecurity:'SCIF, armed guards, EMP shielding, TEMPEST',networkSegment:'10.7.1.0/24',firewallRules:200,idsSignatures:5000,lastPentest:'2026-02-01',pentestFindings:1},
  'GV10': {lat:38.95,lon:-77.15,altitude:0,facility:'Military Command Center',address:'Classified',securityLevel:'TS/SCI',lastInspection:'2026-09-10',personnelCount:500,backupPower:true,physicalSecurity:'Maximum security, underground facility',networkSegment:'10.7.7.0/24',firewallRules:300,idsSignatures:6000,lastPentest:'2026-01-15',pentestFindings:0},
  'EN19': {lat:29.76,lon:-95.37,altitude:0,facility:'Pipeline SCADA Master Control',address:'200 Energy Way, Houston',securityLevel:'SECRET',lastInspection:'2026-08-15',personnelCount:40,backupPower:true,physicalSecurity:'Biometric access, CCTV, fence, guards',networkSegment:'10.8.12.0/24',firewallRules:30,idsSignatures:1000,lastPentest:'2026-06-15',pentestFindings:9}
};

// ============================================================================
// NETWORK SEGMENTATION MAP
// ============================================================================
var NETWORK_SEGMENTS = [
  {segment:'10.1.0.0/16',name:'Power Grid Zone',vlan:100,firewall:'FW-PG-01',aclRules:45,dmz:false,itOtBoundary:true,monitoring:'Full IDS/IPS',encryption:'IPSec VPN',lastReview:'2026-08-01'},
  {segment:'10.2.0.0/16',name:'Water Treatment Zone',vlan:200,firewall:'FW-WT-01',aclRules:32,dmz:false,itOtBoundary:true,monitoring:'Full IDS/IPS',encryption:'IPSec VPN',lastReview:'2026-07-15'},
  {segment:'10.3.0.0/16',name:'Telecom Zone',vlan:300,firewall:'FW-TC-01',aclRules:78,dmz:true,itOtBoundary:false,monitoring:'Full IDS/IPS + DPI',encryption:'TLS 1.3',lastReview:'2026-09-01'},
  {segment:'10.4.0.0/16',name:'Transport Zone',vlan:400,firewall:'FW-TR-01',aclRules:38,dmz:false,itOtBoundary:true,monitoring:'IDS',encryption:'IPSec VPN',lastReview:'2026-08-10'},
  {segment:'10.5.0.0/16',name:'Financial Zone',vlan:500,firewall:'FW-FN-01',aclRules:120,dmz:true,itOtBoundary:false,monitoring:'Full IDS/IPS + WAF',encryption:'TLS 1.3 + mTLS',lastReview:'2026-09-05'},
  {segment:'10.6.0.0/16',name:'Healthcare Zone',vlan:600,firewall:'FW-HC-01',aclRules:55,dmz:true,itOtBoundary:true,monitoring:'IDS/IPS',encryption:'TLS 1.3',lastReview:'2026-08-20'},
  {segment:'10.7.0.0/16',name:'Government Zone',vlan:700,firewall:'FW-GV-01',aclRules:200,dmz:false,itOtBoundary:false,monitoring:'Full IDS/IPS + DPI + NSM',encryption:'Suite B / CNSA',lastReview:'2026-09-10'},
  {segment:'10.8.0.0/16',name:'Energy Zone',vlan:800,firewall:'FW-EN-01',aclRules:42,dmz:false,itOtBoundary:true,monitoring:'Full IDS/IPS',encryption:'IPSec VPN',lastReview:'2026-08-15'},
  {segment:'10.9.0.0/16',name:'Management Zone',vlan:900,firewall:'FW-MGMT-01',aclRules:150,dmz:false,itOtBoundary:false,monitoring:'Full IDS/IPS + UEBA',encryption:'TLS 1.3 + mTLS',lastReview:'2026-09-08'},
  {segment:'10.10.0.0/16',name:'DMZ',vlan:1000,firewall:'FW-DMZ-01',aclRules:95,dmz:true,itOtBoundary:false,monitoring:'Full IDS/IPS + WAF + DPI',encryption:'TLS 1.3',lastReview:'2026-09-12'}
];

// ============================================================================
// DECEPTION OPERATION CONFIGS
// ============================================================================
var DECEPTION_OPS = [
  {id:'DEC01',name:'PHANTOM WEB',type:'honeypot',subtype:'Web Server',target:'External attackers',deployment:'DMZ',technology:'Cowrie + custom web app',ports:[80,443,8080,8443],
    interactions:{total:1247,unique_ips:89,techniques_observed:['Directory brute force','SQL injection','XSS probing','Admin page scanning','Credential stuffing'],
    attribution_hits:[{apt:'APT28',confidence:'medium',evidence:'Known scanning pattern and IP overlap'}]},
    status:'active',deployed:'2026-06-01',lastTriggered:'2026-09-13T02:12:00Z'},
  {id:'DEC02',name:'GHOST SHARE',type:'honey_token',subtype:'SMB Network Share',target:'Internal lateral movement',deployment:'Internal network',technology:'Custom SMB honeypot',ports:[445,139],
    interactions:{total:342,unique_ips:23,techniques_observed:['SMB enumeration','NTLM hash capture','File listing','Credential testing'],
    attribution_hits:[{apt:'Sandworm',confidence:'low',evidence:'TTPs consistent but inconclusive'}]},
    status:'active',deployed:'2026-07-15',lastTriggered:'2026-09-13T01:45:00Z'},
  {id:'DEC03',name:'DECOY SCADA',type:'honeypot',subtype:'ICS/SCADA System',target:'ICS-targeting actors',deployment:'OT DMZ',technology:'Conpot + custom Siemens S7 emulation',ports:[502,102,80,443,4840],
    interactions:{total:56,unique_ips:12,techniques_observed:['Modbus enumeration','S7comm scanning','HMI access attempts'],
    attribution_hits:[]},
    status:'active',deployed:'2026-08-01',lastTriggered:null},
  {id:'DEC04',name:'BAIT CREDS',type:'honey_token',subtype:'Credential Set',target:'Credential theft detection',deployment:'Active Directory',technology:'Custom honey accounts in AD',ports:[],
    interactions:{total:89,unique_ips:15,techniques_observed:['LDAP bind attempts','Kerberos TGT requests','RDP login','SSH login'],
    attribution_hits:[{apt:'Unknown',confidence:'low',evidence:'Automated credential testing'}]},
    status:'active',deployed:'2026-05-15',lastTriggered:'2026-09-13T01:00:00Z'},
  {id:'DEC05',name:'FAKE DNS',type:'honeypot',subtype:'DNS Server',target:'DNS reconnaissance',deployment:'DMZ',technology:'Custom DNS responder',ports:[53],
    interactions:{total:892,unique_ips:156,techniques_observed:['Zone transfer requests','DNS enumeration','Subdomain brute force','DNS cache poisoning'],
    attribution_hits:[{apt:'Turla',confidence:'low',evidence:'DNS reconnaissance pattern similar'}]},
    status:'active',deployed:'2026-06-15',lastTriggered:'2026-09-13T01:52:00Z'},
  {id:'DEC06',name:'SHADOW DB',type:'honey_token',subtype:'Database',target:'Data exfiltration detection',deployment:'Internal network',technology:'MySQL honeypot with fake PII',ports:[3306],
    interactions:{total:0,unique_ips:0,techniques_observed:[],attribution_hits:[]},
    status:'active',deployed:'2026-08-15',lastTriggered:null},
  {id:'DEC07',name:'MIRAGE VPN',type:'honeypot',subtype:'VPN Gateway',target:'VPN exploitation',deployment:'DMZ',technology:'Custom OpenVPN/IKE responder',ports:[443,1194,500,4500],
    interactions:{total:178,unique_ips:34,techniques_observed:['IKE negotiation','Certificate harvesting','Credential brute force','VPN exploit attempts'],
    attribution_hits:[{apt:'APT28',confidence:'medium',evidence:'Used known APT28 client certificate'}]},
    status:'active',deployed:'2026-07-01',lastTriggered:'2026-09-13T01:30:00Z'},
  {id:'DEC08',name:'GHOST MAIL',type:'honey_token',subtype:'Email Account',target:'Email compromise detection',deployment:'Email infrastructure',technology:'Monitored mailbox with tracking',ports:[],
    interactions:{total:67,unique_ips:28,techniques_observed:['IMAP login','SMTP relay','Contact enumeration','Attachment download'],
    attribution_hits:[{apt:'APT29',confidence:'low',evidence:'OAuth token usage pattern'}]},
    status:'active',deployed:'2026-06-01',lastTriggered:'2026-09-13T01:15:00Z'},
  {id:'DEC09',name:'PHANTOM API',type:'honeypot',subtype:'REST API',target:'API exploitation',deployment:'DMZ',technology:'Custom API honeypot',ports:[443,8443],
    interactions:{total:0,unique_ips:0,techniques_observed:[],attribution_hits:[]},
    status:'active',deployed:'2026-09-10',lastTriggered:null},
  {id:'DEC10',name:'DECOY AD',type:'honeypot',subtype:'Active Directory',target:'AD exploitation',deployment:'Internal network',technology:'Custom AD replica',ports:[389,636,88,445],
    interactions:{total:0,unique_ips:0,techniques_observed:[],attribution_hits:[]},
    status:'standby',deployed:'2026-09-01',lastTriggered:null},
  {id:'DEC11',name:'BAIT DOC',type:'honey_token',subtype:'Document Beacon',target:'Document theft tracking',deployment:'File shares',technology:'Canary documents with web beacons',ports:[],
    interactions:{total:23,unique_ips:8,techniques_observed:['Document opening from external IP','C2 callback from beacon'],
    attribution_hits:[{apt:'OceanLotus',confidence:'medium',evidence:'Callback to known APT32 infrastructure'}]},
    status:'active',deployed:'2026-07-15',lastTriggered:'2026-09-13T00:30:00Z'},
  {id:'DEC12',name:'SHADOW CERT',type:'honey_token',subtype:'TLS Certificate',target:'Certificate theft detection',deployment:'Certificate stores',technology:'Monitored certificates with unique serial numbers',ports:[],
    interactions:{total:0,unique_ips:0,techniques_observed:[],attribution_hits:[]},
    status:'active',deployed:'2026-08-01',lastTriggered:null}
];

// ============================================================================
// RENDER HELPERS FOR EXTENDED SECTIONS
// ============================================================================
function renderNetworkFlows() {
  var html = '<div class="pm-section-title">Network Flow Analysis</div>' +
    '<div class="pm-grid-3 pm-mb-16">';
  var totalFlows = NETWORK_FLOWS.length;
  var anomalous = 0;
  var encrypted = 0;
  var scadaFlows = 0;
  for (var f = 0; f < NETWORK_FLOWS.length; f++) {
    if (NETWORK_FLOWS[f].anomaly) anomalous++;
    if (NETWORK_FLOWS[f].encrypted) encrypted++;
    if (NETWORK_FLOWS[f].protocol.indexOf('Modbus') !== -1 || NETWORK_FLOWS[f].protocol.indexOf('SCADA') !== -1 || NETWORK_FLOWS[f].protocol.indexOf('DNP3') !== -1 || NETWORK_FLOWS[f].protocol.indexOf('OPC') !== -1) scadaFlows++;
  }
  html += '<div class="pm-kpi"><div class="pm-kpi-value">' + esc(String(totalFlows)) + '</div><div class="pm-kpi-label">Monitored Flows</div></div>' +
    '<div class="pm-kpi"><div class="pm-kpi-value pm-text-red">' + esc(String(anomalous)) + '</div><div class="pm-kpi-label">Anomalous</div></div>' +
    '<div class="pm-kpi"><div class="pm-kpi-value pm-text-green">' + Math.round((encrypted/totalFlows)*100) + '%</div><div class="pm-kpi-label">Encrypted</div></div>' +
  '</div>';

  html += '<div class="pm-card pm-mb-16"><div class="pm-scroll-y">';
  for (var fl = 0; fl < NETWORK_FLOWS.length; fl++) {
    var flow = NETWORK_FLOWS[fl];
    var flowClass = flow.anomaly ? 'pm-flow-anomaly' : '';
    var srcNode = getNodeById(flow.source);
    var dstNode = getNodeById(flow.dest);
    html += '<div class="pm-flow-line ' + flowClass + '">' +
      '<span class="pm-text-xs" style="min-width:60px;">' + esc(flow.source) + '</span>' +
      '<span class="pm-text-green">&#8594;</span>' +
      '<span class="pm-text-xs" style="min-width:60px;">' + esc(flow.dest) + '</span>' +
      '<span class="pm-tag">' + esc(flow.protocol) + '</span>' +
      '<span class="pm-text-xs pm-text-muted">:' + esc(String(flow.port)) + '</span>' +
      '<span class="pm-text-xs pm-text-muted" style="margin-left:auto;">' + esc(flow.bandwidth) + '</span>' +
      (flow.encrypted ? '<span class="pm-text-green pm-text-xs">[+]</span>' : '<span class="pm-text-red pm-text-xs">[-]</span>') +
      (flow.anomaly ? '<span class="pm-badge pm-badge-critical">ANOMALY</span>' : '') +
    '</div>';
  }
  html += '</div></div>';
  return html;
}

function renderSegmentationMap() {
  var html = '<div class="pm-section-title">Network Segmentation</div>' +
    '<div class="pm-table-wrap pm-mb-16"><table class="pm-table pm-compact">' +
    '<tr><th>Segment</th><th>Zone</th><th>VLAN</th><th>Firewall</th><th>ACLs</th><th>DMZ</th><th>IT/OT</th><th>Monitoring</th><th>Encryption</th><th>Last Review</th></tr>';
  for (var s = 0; s < NETWORK_SEGMENTS.length; s++) {
    var seg = NETWORK_SEGMENTS[s];
    html += '<tr>' +
      '<td class="pm-text-xs">' + esc(seg.segment) + '</td>' +
      '<td class="pm-text-xs">' + esc(seg.name) + '</td>' +
      '<td class="pm-text-xs">' + esc(String(seg.vlan)) + '</td>' +
      '<td class="pm-text-xs">' + esc(seg.firewall) + '</td>' +
      '<td>' + esc(String(seg.aclRules)) + '</td>' +
      '<td>' + (seg.dmz ? '<span class="pm-text-yellow">Yes</span>' : '<span class="pm-text-muted">No</span>') + '</td>' +
      '<td>' + (seg.itOtBoundary ? '<span class="pm-text-red">Yes</span>' : '<span class="pm-text-muted">No</span>') + '</td>' +
      '<td class="pm-text-xs">' + esc(seg.monitoring) + '</td>' +
      '<td class="pm-text-xs">' + esc(seg.encryption) + '</td>' +
      '<td class="pm-text-xs pm-text-muted">' + esc(seg.lastReview) + '</td>' +
    '</tr>';
  }
  html += '</table></div>';
  return html;
}

function renderDeceptionDashboard() {
  var html = '<div class="pm-grid-4 pm-mb-16">';
  var totalInteractions = 0;
  var triggeredOps = 0;
  var attributionHits = 0;
  for (var i = 0; i < DECEPTION_OPS.length; i++) {
    totalInteractions += DECEPTION_OPS[i].interactions.total;
    if (DECEPTION_OPS[i].lastTriggered) triggeredOps++;
    attributionHits += DECEPTION_OPS[i].interactions.attribution_hits.length;
  }
  html += '<div class="pm-kpi"><div class="pm-kpi-value">' + esc(String(DECEPTION_OPS.length)) + '</div><div class="pm-kpi-label">Active Deceptions</div></div>' +
    '<div class="pm-kpi"><div class="pm-kpi-value pm-text-yellow">' + esc(String(triggeredOps)) + '</div><div class="pm-kpi-label">Triggered</div></div>' +
    '<div class="pm-kpi"><div class="pm-kpi-value pm-text-red">' + esc(String(totalInteractions)) + '</div><div class="pm-kpi-label">Total Interactions</div></div>' +
    '<div class="pm-kpi"><div class="pm-kpi-value pm-text-green">' + esc(String(attributionHits)) + '</div><div class="pm-kpi-label">Attribution Hits</div></div>' +
  '</div>';

  html += '<div class="pm-grid-2">';
  for (var d = 0; d < DECEPTION_OPS.length; d++) {
    var op = DECEPTION_OPS[d];
    var borderColor = op.lastTriggered ? '#ff0040' : '#1a2332';
    html += '<div class="pm-card" style="border-color:' + borderColor + ';">' +
      '<div class="pm-flex-between pm-mb-8">' +
        '<span class="pm-text-sm pm-text-bold">' + esc(op.name) + '</span>' +
        '<span class="pm-badge pm-badge-' + (op.status === 'active' ? 'info' : 'medium') + '">' + esc(op.status) + '</span>' +
      '</div>' +
      '<div class="pm-text-xs pm-text-muted pm-mb-8">' + esc(op.subtype) + ' | Deployed: ' + esc(op.deployed) + '</div>' +
      '<div class="pm-text-xs pm-mb-8">Interactions: <span class="pm-text-yellow">' + esc(String(op.interactions.total)) + '</span> | Unique IPs: <span class="pm-text-blue">' + esc(String(op.interactions.unique_ips)) + '</span></div>';
    if (op.interactions.techniques_observed.length > 0) {
      html += '<div class="pm-flex-wrap pm-mb-8">';
      for (var t = 0; t < Math.min(3, op.interactions.techniques_observed.length); t++) {
        html += '<span class="pm-tag">' + esc(op.interactions.techniques_observed[t]) + '</span>';
      }
      if (op.interactions.techniques_observed.length > 3) html += '<span class="pm-text-xs pm-text-muted">+' + (op.interactions.techniques_observed.length - 3) + '</span>';
      html += '</div>';
    }
    if (op.interactions.attribution_hits.length > 0) {
      for (var a = 0; a < op.interactions.attribution_hits.length; a++) {
        var hit = op.interactions.attribution_hits[a];
        html += '<div class="pm-text-xs pm-mt-12" style="border-left:2px solid #ffaa00;padding-left:8px;">Attribution: <span class="pm-text-yellow">' + esc(hit.apt) + '</span> (' + esc(hit.confidence) + ' confidence)</div>';
      }
    }
    if (op.lastTriggered) {
      html += '<div class="pm-text-xs pm-text-red pm-mt-12 pm-blink">Last triggered: ' + esc(fmtTime(op.lastTriggered)) + '</div>';
    }
    html += '</div>';
  }
  html += '</div>';
  return html;
}

function renderNationProfiles() {
  var html = '<div class="pm-grid-2">';
  for (var n = 0; n < NATION_PROFILES.length; n++) {
    var nation = NATION_PROFILES[n];
    var tierClass = 'pm-tier-' + nation.tier;
    html += '<div class="pm-nation-card">' +
      '<div class="pm-flex-between pm-mb-8">' +
        '<span class="pm-text-sm pm-text-bold">' + esc(nation.nation) + '</span>' +
        '<span class="pm-nation-tier ' + tierClass + '">TIER ' + esc(String(nation.tier)) + '</span>' +
      '</div>' +
      '<div class="pm-text-xs pm-mb-8"><b>Units:</b> ' + esc(nation.units.join(', ')) + '</div>' +
      '<div class="pm-text-xs pm-mb-8"><b>Capability:</b> ' + esc(nation.capability) + '</div>' +
      '<div class="pm-text-xs pm-mb-8"><b>Notable Ops:</b> ' + esc(nation.notableOps.join(', ')) + '</div>' +
      '<div class="pm-text-xs pm-mb-8"><b>Primary Targets:</b> ' + esc(nation.primaryTargets.join(', ')) + '</div>' +
      '<div class="pm-grid-2" style="gap:8px;">' +
        '<div class="pm-text-xs"><b>Operators:</b> ' + esc(nation.estimatedOperators) + '</div>' +
        '<div class="pm-text-xs"><b>Budget:</b> ' + esc(nation.budget) + '</div>' +
      '</div>' +
      '<div class="pm-text-xs pm-text-muted pm-mt-12">' + esc(nation.assessment) + '</div>' +
    '</div>';
  }
  html += '</div>';
  return html;
}

function renderPlaybookDetail(playbookId) {
  var playbook = getPlaybookById(playbookId);
  if (!playbook) return '<div class="pm-no-data">Playbook not found</div>';

  var html = '<div class="pm-card pm-mb-16">' +
    '<div class="pm-flex-between pm-mb-12">' +
      '<div>' +
        '<div class="pm-text-sm pm-text-bold pm-text-green">' + esc(playbook.name) + '</div>' +
        '<div class="pm-text-xs pm-text-muted">Category: ' + esc(playbook.category) + ' | Severity: ' + esc(playbook.severity) + '</div>' +
      '</div>' +
      '<span class="pm-badge pm-badge-' + playbook.severity + '">' + esc(playbook.severity) + '</span>' +
    '</div>';

  for (var s = 0; s < playbook.steps.length; s++) {
    var step = playbook.steps[s];
    html += '<div class="pm-playbook-step">' +
      '<div class="step-num">' + esc(String(step.order)) + '</div>' +
      '<div style="flex:1;">' +
        '<div class="pm-text-sm">' + esc(step.action) + '</div>' +
        '<div class="pm-flex pm-mt-12" style="gap:12px;">' +
          '<span class="pm-text-xs pm-text-muted">Duration: ' + esc(step.duration) + '</span>' +
          '<span class="pm-text-xs pm-text-muted">Tool: ' + esc(step.tool) + '</span>' +
          (step.automated ? '<span class="pm-playbook-auto">AUTOMATED</span>' : '<span class="pm-playbook-manual">MANUAL</span>') +
        '</div>' +
      '</div>' +
    '</div>';
  }
  html += '</div>';
  return html;
}

function renderAllPlaybooks() {
  var html = '';
  for (var i = 0; i < IR_PLAYBOOKS.length; i++) {
    html += renderPlaybookDetail(IR_PLAYBOOKS[i].id);
  }
  return html;
}

function renderMitreHeatmap() {
  var tactics = ['Initial Access','Execution','Persistence','Defense Evasion','Credential Access','Command and Control','Collection','Exfiltration','Impact'];
  var html = '<div class="pm-section-title">MITRE ATT&CK Coverage</div>' +
    '<div class="pm-card pm-mb-16">';

  for (var t = 0; t < tactics.length; t++) {
    var tacticTechniques = [];
    for (var m = 0; m < MITRE_TECHNIQUES.length; m++) {
      if (MITRE_TECHNIQUES[m].tactic === tactics[t]) tacticTechniques.push(MITRE_TECHNIQUES[m]);
    }
    if (tacticTechniques.length > 0) {
      html += '<div class="pm-label pm-mb-8 pm-mt-12">' + esc(tactics[t]) + ' (' + esc(String(tacticTechniques.length)) + ' techniques)</div>' +
        '<div class="pm-flex-wrap pm-mb-8">';
      for (var tt = 0; tt < tacticTechniques.length; tt++) {
        var tech = tacticTechniques[tt];
        var isUsed = tech.usedBy.length > 0;
        html += '<div class="pm-mitre-cell ' + (isUsed ? 'pm-mitre-used' : 'pm-mitre-unused') + '" title="' + esc(tech.name + ' - Used by: ' + (tech.usedBy.join(', ') || 'None')) + '">' +
          esc(tech.id) + '<br><span style="font-size:7px;">' + esc(tech.name.substring(0, 20)) + '</span>' +
        '</div>';
      }
      html += '</div>';
    }
  }
  html += '</div>';
  return html;
}


// ============================================================================
// ADDITIONAL WARGAME SCENARIO DETAILS
// ============================================================================
var WARGAME_DETAILS = {
  'WG01': {
    redObjectives: ['Gain initial access to power grid SCADA via spearphishing', 'Establish persistence on grid control systems', 'Modify PLC ladder logic to cause transformer overload', 'Maintain access for 4+ hours undetected', 'Deploy wiper malware on IT systems'],
    blueObjectives: ['Detect initial compromise within 30 minutes', 'Identify SCADA manipulation before physical impact', 'Isolate compromised segments without cascading outage', 'Restore grid operations within 4 hours', 'Collect forensic evidence for attribution'],
    whiteInjects: ['Media reports emerging about outages', 'Hospital backup generators beginning to fail', 'Nuclear plant cooling systems losing monitoring capability', 'Governor requesting status update', 'CISA offering support team'],
    resources: {red: {operators: 5, infrastructure: '10 C2 servers, 50 proxy nodes, 3 zero-days', budget: 'Unlimited'}, blue: {analysts: 12, tools: 'SIEM, EDR, IDS, OT monitoring, DFIR kit', access: 'Full network access'}},
    historicalResults: [{date: '2026-03-15', redScore: 72, blueScore: 68, keyFinding: 'SCADA monitoring detected anomaly but response was delayed by 45 minutes'}, {date: '2026-06-20', redScore: 58, blueScore: 82, keyFinding: 'Improved OT monitoring detected PLC modification within 3 minutes'}]
  },
  'WG02': {
    redObjectives: ['Compromise water treatment SCADA via exposed HMI', 'Alter chemical dosing parameters', 'Disable safety interlocks', 'Maintain changes for 2+ hours', 'Cover tracks in SCADA logs'],
    blueObjectives: ['Detect SCADA manipulation before unsafe water reaches distribution', 'Identify all compromised PLCs', 'Restore safe water chemistry', 'Coordinate with public health authorities'],
    whiteInjects: ['Public health complaint cluster reported', 'Water quality sensor readings inconsistent', 'Media inquiring about water safety', 'State environmental agency requesting report'],
    resources: {red: {operators: 3, infrastructure: '5 C2 servers, Modbus exploit framework', budget: 'Moderate'}, blue: {analysts: 8, tools: 'ICS monitoring, SCADA historian, SIEM', access: 'OT and IT network access'}},
    historicalResults: [{date: '2026-04-10', redScore: 65, blueScore: 75, keyFinding: 'Chemical dosing anomaly detected by process sensors but SCADA compromise was not identified'}]
  },
  'WG03': {
    redObjectives: ['Compromise software vendor build pipeline', 'Insert malicious code into trusted update', 'Gain access to financial clearing house via trojanized update', 'Manipulate fund transfers', 'Exfiltrate financial data'],
    blueObjectives: ['Identify supply chain compromise vector', 'Map lateral movement through financial network', 'Prevent unauthorized fund transfers', 'Coordinate with financial regulators and law enforcement'],
    whiteInjects: ['SEC inquiry about suspicious trading patterns', 'Third-party vendor reports potential breach', 'Flash crash triggered by compromised systems', 'Congressional committee requests briefing'],
    resources: {red: {operators: 8, infrastructure: '15 C2 servers, supply chain tools, custom financial malware', budget: 'State-level'}, blue: {analysts: 15, tools: 'SIEM, EDR, DLP, SWIFT monitoring, fraud detection', access: 'Full IT access, limited OT'}},
    historicalResults: [{date: '2026-05-22', redScore: 78, blueScore: 62, keyFinding: 'Supply chain vector was not detected for 6 hours, allowing significant lateral movement'}]
  }
};

// ============================================================================
// CYBER KILL CHAIN MAPPING
// ============================================================================
var KILL_CHAIN_STAGES = [
  {stage: 1, name: 'Reconnaissance', description: 'Adversary identifies and selects targets, collects information', mitre: ['T1595', 'T1592', 'T1589', 'T1590'], indicators: ['OSINT collection', 'Domain enumeration', 'Social media profiling', 'Job posting analysis', 'Technology stack identification'], defenses: ['Minimize public exposure', 'Monitor for scanning', 'Implement deception', 'OPSEC training']},
  {stage: 2, name: 'Weaponization', description: 'Adversary creates deliverable payload coupled with exploit', mitre: ['T1587', 'T1588', 'T1583', 'T1584'], indicators: ['Malware development', 'Exploit acquisition', 'Infrastructure setup', 'Domain registration', 'Certificate creation'], defenses: ['Threat intelligence', 'Domain monitoring', 'Certificate transparency monitoring']},
  {stage: 3, name: 'Delivery', description: 'Adversary transmits the weapon to the target environment', mitre: ['T1566', 'T1190', 'T1195', 'T1189'], indicators: ['Phishing emails', 'Watering hole sites', 'Supply chain packages', 'USB drops', 'Exploit traffic'], defenses: ['Email filtering', 'Web filtering', 'SCA/SBOM', 'USB controls', 'WAF']},
  {stage: 4, name: 'Exploitation', description: 'Adversary exploits vulnerability to execute code on target', mitre: ['T1203', 'T1059', 'T1204'], indicators: ['Exploit artifacts', 'Crash dumps', 'Anomalous process creation', 'Memory corruption', 'Shellcode'], defenses: ['Patching', 'ASLR/DEP', 'Application whitelisting', 'Exploit prevention']},
  {stage: 5, name: 'Installation', description: 'Adversary installs malware to maintain persistent access', mitre: ['T1547', 'T1543', 'T1546', 'T1053'], indicators: ['New services', 'Registry modifications', 'Scheduled tasks', 'Startup items', 'DLL side-loading'], defenses: ['EDR', 'Application control', 'File integrity monitoring', 'Behavioral analytics']},
  {stage: 6, name: 'Command & Control', description: 'Adversary establishes remote communication channel', mitre: ['T1071', 'T1573', 'T1090', 'T1572'], indicators: ['Beacon patterns', 'DNS tunneling', 'Encrypted channels', 'Protocol anomalies', 'Cloud service abuse'], defenses: ['Network monitoring', 'DNS analysis', 'SSL inspection', 'Proxy controls', 'Anomaly detection']},
  {stage: 7, name: 'Actions on Objectives', description: 'Adversary accomplishes their mission goals', mitre: ['T1005', 'T1486', 'T1485', 'T1565', 'T1498'], indicators: ['Data staging', 'Encryption activity', 'Deletion commands', 'Exfiltration traffic', 'Destructive behavior'], defenses: ['DLP', 'Backup verification', 'Data classification', 'Segmentation', 'Recovery planning']}
];

// ============================================================================
// EXERCISE ASSESSMENT RUBRICS
// ============================================================================
var ASSESSMENT_RUBRICS = [
  {category: 'Incident Detection', weight: 25, criteria: [
    {item: 'Time to initial detection', excellent: '< 15 min', good: '15-30 min', acceptable: '30-60 min', poor: '> 60 min'},
    {item: 'Detection method', excellent: 'Automated alert', good: 'Proactive hunt', acceptable: 'User report', poor: 'External notification'},
    {item: 'Alert triage accuracy', excellent: '> 95% true positive', good: '80-95%', acceptable: '60-80%', poor: '< 60%'},
    {item: 'Scope assessment', excellent: 'All affected systems identified', good: 'Most systems identified', acceptable: 'Key systems identified', poor: 'Scope underestimated'}
  ]},
  {category: 'Containment', weight: 25, criteria: [
    {item: 'Time to contain', excellent: '< 30 min', good: '30-60 min', acceptable: '1-2 hours', poor: '> 2 hours'},
    {item: 'Containment effectiveness', excellent: 'No further spread', good: 'Minimal spread', acceptable: 'Some spread before contained', poor: 'Containment failed'},
    {item: 'Business impact of containment', excellent: 'Minimal disruption', good: 'Brief disruption', acceptable: 'Moderate disruption', poor: 'Significant disruption'},
    {item: 'Evidence preservation', excellent: 'Full evidence collected', good: 'Key evidence preserved', acceptable: 'Some evidence lost', poor: 'Evidence destroyed'}
  ]},
  {category: 'Eradication & Recovery', weight: 30, criteria: [
    {item: 'Root cause identification', excellent: 'Accurate and complete', good: 'Mostly accurate', acceptable: 'Partially identified', poor: 'Not identified'},
    {item: 'Remediation completeness', excellent: 'All artifacts removed', good: 'Known artifacts removed', acceptable: 'Some artifacts remain', poor: 'Incomplete remediation'},
    {item: 'Recovery time', excellent: '< 4 hours', good: '4-12 hours', acceptable: '12-24 hours', poor: '> 24 hours'},
    {item: 'Recovery verification', excellent: 'Full verification conducted', good: 'Key systems verified', acceptable: 'Partial verification', poor: 'No verification'}
  ]},
  {category: 'Communication', weight: 20, criteria: [
    {item: 'Internal notification', excellent: '< 15 min to leadership', good: '15-30 min', acceptable: '30-60 min', poor: '> 60 min'},
    {item: 'External notification', excellent: 'Timely and accurate', good: 'Timely', acceptable: 'Delayed', poor: 'Not provided'},
    {item: 'Status updates', excellent: 'Regular and detailed', good: 'Regular', acceptable: 'Sporadic', poor: 'None'},
    {item: 'Post-incident report', excellent: 'Comprehensive AAR', good: 'Adequate report', acceptable: 'Brief summary', poor: 'No report'}
  ]}
];

// ============================================================================
// THREAT INTELLIGENCE SHARING STANDARDS
// ============================================================================
var TI_STANDARDS = [
  {name: 'STIX 2.1', description: 'Structured Threat Information Expression - standard format for cyber threat intelligence', useCase: 'Sharing IOCs, TTPs, threat actors, campaigns, vulnerabilities', format: 'JSON', adoption: 'High', supportedBy: ['MITRE', 'OASIS', 'CISA', 'NATO']},
  {name: 'TAXII 2.1', description: 'Trusted Automated Exchange of Intelligence Information - transport protocol for STIX', useCase: 'Automated sharing of STIX objects between organizations', format: 'HTTPS REST API', adoption: 'High', supportedBy: ['MITRE', 'OASIS', 'CISA']},
  {name: 'OpenIOC', description: 'Open Indicators of Compromise - XML-based IOC format', useCase: 'Sharing technical indicators for incident response', format: 'XML', adoption: 'Medium', supportedBy: ['Mandiant', 'FireEye']},
  {name: 'MISP', description: 'Malware Information Sharing Platform - open-source threat sharing', useCase: 'Collaborative threat intelligence sharing between organizations', format: 'JSON/XML', adoption: 'High', supportedBy: ['CIRCL', 'NATO', 'EU CERTs']},
  {name: 'CybOX', description: 'Cyber Observable Expression - standardized cyber observable objects', useCase: 'Describing cyber observables in a standardized way', format: 'JSON/XML', adoption: 'Medium', supportedBy: ['MITRE', 'DHS']},
  {name: 'VERIS', description: 'Vocabulary for Event Recording and Incident Sharing', useCase: 'Standardized incident recording and analysis', format: 'JSON', adoption: 'Medium', supportedBy: ['Verizon DBIR']},
  {name: 'ATT&CK', description: 'Adversarial Tactics, Techniques, and Common Knowledge', useCase: 'Describing adversary behavior and mapping defenses', format: 'STIX 2.1', adoption: 'Very High', supportedBy: ['MITRE', 'Global adoption']}
];

// ============================================================================
// ALERT SEVERITY DEFINITIONS
// ============================================================================
var ALERT_DEFINITIONS = {
  CRITICAL: {
    sla: '15 minutes',
    response: 'Immediate',
    notification: 'SOC Manager, CISO, CTO',
    examples: ['Active data exfiltration', 'Ransomware deployment', 'SCADA manipulation', 'Confirmed APT activity', 'Nuclear system compromise'],
    color: '#ff0040',
    escalation: 'Auto-escalate to Level 3+'
  },
  HIGH: {
    sla: '1 hour',
    response: 'Priority',
    notification: 'SOC Manager, Team Lead',
    examples: ['Lateral movement detected', 'Credential compromise', 'Privilege escalation', 'Malware execution', 'DDoS attack'],
    color: '#ff6600',
    escalation: 'Escalate to Level 2 within 30 min if unresolved'
  },
  MEDIUM: {
    sla: '4 hours',
    response: 'Standard',
    notification: 'SOC Analyst',
    examples: ['Suspicious process', 'Failed authentication cluster', 'Policy violation', 'Vulnerability scan detected', 'Anomalous traffic'],
    color: '#ffaa00',
    escalation: 'Escalate if pattern persists'
  },
  LOW: {
    sla: '24 hours',
    response: 'Scheduled',
    notification: 'Queue for review',
    examples: ['Informational alert', 'Compliance check', 'Routine scan', 'Configuration drift', 'Certificate expiry warning'],
    color: '#00aaff',
    escalation: 'Batch review during shift'
  },
  INFO: {
    sla: '72 hours',
    response: 'As available',
    notification: 'Log for record',
    examples: ['System health check', 'Patch status', 'User activity report', 'Performance metric', 'Scheduled maintenance'],
    color: '#00ff88',
    escalation: 'No escalation'
  }
};

// ============================================================================
// CROSS-SECTOR DEPENDENCY ANALYSIS
// ============================================================================
function analyzeCrossSectorDependencies() {
  var matrix = {};
  var sectors = ['POWER_GRID', 'WATER', 'TELECOM', 'TRANSPORT', 'FINANCIAL', 'HEALTHCARE', 'GOVERNMENT', 'ENERGY'];

  for (var s = 0; s < sectors.length; s++) {
    matrix[sectors[s]] = {};
    for (var d = 0; d < sectors.length; d++) {
      matrix[sectors[s]][sectors[d]] = 0;
    }
  }

  for (var n = 0; n < INFRA_NODES.length; n++) {
    var node = INFRA_NODES[n];
    for (var dep = 0; dep < node.deps.length; dep++) {
      var depNode = getNodeById(node.deps[dep]);
      if (depNode && depNode.sector !== node.sector) {
        matrix[node.sector][depNode.sector]++;
      }
    }
  }

  return matrix;
}

function renderDependencyMatrix() {
  var matrix = analyzeCrossSectorDependencies();
  var sectors = ['POWER_GRID', 'WATER', 'TELECOM', 'TRANSPORT', 'FINANCIAL', 'HEALTHCARE', 'GOVERNMENT', 'ENERGY'];
  var shortNames = ['PWR', 'WTR', 'TEL', 'TRN', 'FIN', 'HLT', 'GOV', 'ENG'];

  var html = '<div class="pm-section-title">Cross-Sector Dependency Matrix</div>' +
    '<div class="pm-card pm-mb-16">' +
    '<div class="pm-text-xs pm-text-muted pm-mb-8">Rows depend on columns. Higher numbers indicate greater cross-sector dependency.</div>' +
    '<div class="pm-table-wrap"><table class="pm-table pm-compact">' +
    '<tr><th>Depends On &#8594;</th>';
  for (var h = 0; h < shortNames.length; h++) {
    html += '<th class="pm-text-center">' + esc(shortNames[h]) + '</th>';
  }
  html += '<th>Total</th></tr>';

  for (var r = 0; r < sectors.length; r++) {
    var rowTotal = 0;
    html += '<tr><td class="pm-text-bold">' + esc(shortNames[r]) + '</td>';
    for (var c = 0; c < sectors.length; c++) {
      var val = matrix[sectors[r]][sectors[c]];
      rowTotal += val;
      var cellColor = val === 0 ? '#0d1117' : (val >= 5 ? '#2a0d0d' : (val >= 3 ? '#2a1a0d' : '#0d1a2a'));
      var textColor = val === 0 ? '#334455' : (val >= 5 ? '#ff0040' : (val >= 3 ? '#ffaa00' : '#00aaff'));
      html += '<td class="pm-text-center" style="background:' + cellColor + ';color:' + textColor + ';">' + (r === c ? '-' : esc(String(val))) + '</td>';
    }
    html += '<td class="pm-text-center pm-text-bold">' + esc(String(rowTotal)) + '</td></tr>';
  }
  html += '</table></div></div>';
  return html;
}

function renderSectorRiskComparison() {
  var sectors = ['POWER_GRID', 'WATER', 'TELECOM', 'TRANSPORT', 'FINANCIAL', 'HEALTHCARE', 'GOVERNMENT', 'ENERGY'];
  var shortNames = ['Power Grid', 'Water', 'Telecom', 'Transport', 'Financial', 'Healthcare', 'Government', 'Energy'];

  var html = '<div class="pm-section-title">Sector Risk Comparison</div>' +
    '<div class="pm-card pm-mb-16"><div class="pm-table-wrap"><table class="pm-table">' +
    '<tr><th>Sector</th><th>Nodes</th><th>Health</th><th>Risk Score</th><th>Cross-Sector Deps</th><th>Max Population Impact</th><th>Active Threats</th></tr>';

  for (var s = 0; s < sectors.length; s++) {
    var nodes = getSectorNodes(sectors[s]);
    var health = getSectorHealth(sectors[s]);
    var risk = calculateSectorRisk(sectors[s]);
    var maxPop = 0;
    var crossDeps = 0;
    for (var n = 0; n < nodes.length; n++) {
      if (nodes[n].population > maxPop) maxPop = nodes[n].population;
      for (var d = 0; d < nodes[n].deps.length; d++) {
        var depNode = getNodeById(nodes[n].deps[d]);
        if (depNode && depNode.sector !== sectors[s]) crossDeps++;
      }
    }
    var activeThreats = 0;
    for (var t = 0; t < THREAT_PREDICTIONS.length; t++) {
      if (THREAT_PREDICTIONS[t].status === 'active') {
        for (var tgt = 0; tgt < THREAT_PREDICTIONS[t].targets.length; tgt++) {
          var tgtNode = getNodeById(THREAT_PREDICTIONS[t].targets[tgt]);
          if (tgtNode && tgtNode.sector === sectors[s]) { activeThreats++; break; }
        }
      }
    }

    var healthColor = health >= 90 ? 'pm-text-green' : (health >= 60 ? 'pm-text-yellow' : 'pm-text-red');
    var riskColor = risk >= 80 ? 'pm-text-red' : (risk >= 50 ? 'pm-text-yellow' : 'pm-text-green');
    html += '<tr>' +
      '<td class="pm-text-sm">' + esc(shortNames[s]) + '</td>' +
      '<td>' + esc(String(nodes.length)) + '</td>' +
      '<td class="' + healthColor + '">' + esc(String(health)) + '%</td>' +
      '<td class="' + riskColor + '">' + esc(String(risk)) + '</td>' +
      '<td>' + esc(String(crossDeps)) + '</td>' +
      '<td>' + esc(formatNumber(maxPop)) + '</td>' +
      '<td>' + (activeThreats > 0 ? '<span class="pm-badge pm-badge-critical">' + esc(String(activeThreats)) + '</span>' : '<span class="pm-text-green">0</span>') + '</td>' +
    '</tr>';
  }
  html += '</table></div></div>';
  return html;
}

function renderOperationalTimeline() {
  var html = '<div class="pm-section-title">Operational Timeline (Last 24 Hours)</div>' +
    '<div class="pm-card"><div class="pm-timeline pm-scroll-y" style="max-height:500px;">';

  for (var i = 0; i < GLOBAL_ALERTS_EXTENDED.length; i++) {
    var alert = GLOBAL_ALERTS_EXTENDED[i];
    var tlClass = alert.severity === 'CRITICAL' ? 'pm-timeline-red' : (alert.severity === 'HIGH' ? 'pm-timeline-blue' : '');
    html += '<div class="pm-timeline-item ' + tlClass + '">' +
      '<div class="pm-flex-between">' +
        '<div class="pm-timeline-time">' + esc(fmtTime(alert.time)) + ' | ' + esc(alert.source) + '</div>' +
        '<span class="pm-badge pm-badge-' + alert.severity.toLowerCase() + '">' + esc(alert.severity) + '</span>' +
      '</div>' +
      '<div class="pm-text-sm">' + esc(alert.message) + '</div>' +
      '<div class="pm-text-xs pm-text-muted">Sector: ' + esc(alert.sector) + (alert.actionRequired ? ' | <span class="pm-text-red">ACTION REQUIRED</span>' : '') + '</div>' +
    '</div>';
  }
  html += '</div></div>';
  return html;
}

function renderKillChainAnalysis() {
  var html = '<div class="pm-section-title">Cyber Kill Chain Analysis</div><div class="pm-card pm-mb-16">';
  for (var k = 0; k < KILL_CHAIN_STAGES.length; k++) {
    var stage = KILL_CHAIN_STAGES[k];
    var stageColor = k < 3 ? '#00aaff' : (k < 5 ? '#ffaa00' : '#ff0040');
    html += '<div class="pm-roe-item" style="border-left:3px solid ' + stageColor + ';">' +
      '<div style="flex:1;">' +
        '<div class="pm-flex-between">' +
          '<span class="pm-text-sm pm-text-bold" style="color:' + stageColor + ';">Stage ' + esc(String(stage.stage)) + ': ' + esc(stage.name) + '</span>' +
          '<div class="pm-flex-wrap">';
    for (var m = 0; m < Math.min(3, stage.mitre.length); m++) {
      html += '<span class="pm-tag">' + esc(stage.mitre[m]) + '</span>';
    }
    html += '</div></div>' +
        '<div class="pm-text-xs pm-text-muted pm-mb-8">' + esc(stage.description) + '</div>' +
        '<div class="pm-grid-2" style="gap:8px;">' +
          '<div><div class="pm-label">Indicators</div><div class="pm-text-xs">' + esc(stage.indicators.join(' | ')) + '</div></div>' +
          '<div><div class="pm-label">Defenses</div><div class="pm-text-xs pm-text-green">' + esc(stage.defenses.join(' | ')) + '</div></div>' +
        '</div>' +
      '</div>' +
    '</div>';
  }
  html += '</div>';
  return html;
}

function renderTIStandards() {
  var html = '<div class="pm-section-title">Threat Intelligence Standards</div>' +
    '<div class="pm-table-wrap pm-mb-16"><table class="pm-table pm-compact">' +
    '<tr><th>Standard</th><th>Description</th><th>Use Case</th><th>Format</th><th>Adoption</th></tr>';
  for (var t = 0; t < TI_STANDARDS.length; t++) {
    var std = TI_STANDARDS[t];
    html += '<tr>' +
      '<td class="pm-text-sm pm-text-bold pm-text-green">' + esc(std.name) + '</td>' +
      '<td class="pm-text-xs">' + esc(std.description) + '</td>' +
      '<td class="pm-text-xs">' + esc(std.useCase) + '</td>' +
      '<td class="pm-text-xs"><span class="pm-tag">' + esc(std.format) + '</span></td>' +
      '<td class="pm-text-xs">' + esc(std.adoption) + '</td>' +
    '</tr>';
  }
  html += '</table></div>';
  return html;
}

function renderAlertDefinitions() {
  var html = '<div class="pm-section-title">Alert Severity Definitions</div><div class="pm-grid-5 pm-mb-16">';
  var sevKeys = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  for (var s = 0; s < sevKeys.length; s++) {
    var def = ALERT_DEFINITIONS[sevKeys[s]];
    html += '<div class="pm-card" style="border-top:3px solid ' + def.color + ';">' +
      '<div class="pm-text-sm pm-text-bold" style="color:' + def.color + ';">' + esc(sevKeys[s]) + '</div>' +
      '<div class="pm-text-xs pm-text-muted pm-mb-8">SLA: ' + esc(def.sla) + '</div>' +
      '<div class="pm-text-xs pm-mb-8">Response: ' + esc(def.response) + '</div>' +
      '<div class="pm-text-xs pm-mb-8">Notify: ' + esc(def.notification) + '</div>' +
      '<div class="pm-text-xs pm-mb-8">Escalation: ' + esc(def.escalation) + '</div>' +
      '<div class="pm-label pm-mb-8">Examples</div>';
    for (var e = 0; e < def.examples.length; e++) {
      html += '<div class="pm-text-xs pm-text-muted">&#8226; ' + esc(def.examples[e]) + '</div>';
    }
    html += '</div>';
  }
  html += '</div>';
  return html;
}


// ============================================================================
// INTELLIGENCE ANALYSIS METHODOLOGIES
// ============================================================================
var ANALYSIS_METHODS = [
  {name:'Analysis of Competing Hypotheses (ACH)',description:'Evaluate evidence against multiple hypotheses to identify the most likely explanation',steps:['Generate hypotheses','List evidence/arguments for each','Create matrix of evidence vs hypotheses','Refine matrix','Draw tentative conclusions','Identify milestones for future analysis'],applicability:'Complex attribution problems with multiple possible explanations',currentUse:'Used for APT attribution and geopolitical trigger assessment'},
  {name:'Structured Analytic Techniques (SATs)',description:'Formalized analytical methods to mitigate cognitive biases',steps:['Define the problem','Challenge assumptions','Evaluate evidence quality','Consider alternative scenarios','Identify information gaps','Present findings with confidence levels'],applicability:'All intelligence analysis to reduce bias',currentUse:'Standard methodology across all PROMETHEUS intelligence products'},
  {name:'Diamond Model',description:'Intrusion analysis framework examining adversary, capability, infrastructure, and victim relationships',steps:['Identify the adversary','Characterize capabilities used','Map infrastructure employed','Profile the victim','Establish relationships between elements','Track changes over time'],applicability:'Detailed intrusion analysis and campaign tracking',currentUse:'Applied to all confirmed APT campaigns in PROMETHEUS'},
  {name:'MITRE ATT&CK Mapping',description:'Map observed adversary behaviors to the ATT&CK framework for standardized classification',steps:['Observe adversary actions','Identify matching techniques','Map to tactics and procedures','Compare with known group profiles','Identify gaps in detection','Prioritize defenses'],applicability:'Standardized adversary behavior classification',currentUse:'All threat intelligence and detection rule development'},
  {name:'Kill Chain Analysis',description:'Map adversary operations to the Cyber Kill Chain to identify disruption opportunities',steps:['Identify reconnaissance indicators','Detect weaponization signatures','Block delivery mechanisms','Prevent exploitation','Detect installation/persistence','Disrupt C2 channels','Deny actions on objectives'],applicability:'Defensive planning and incident response',currentUse:'Applied to all active threat assessments'}
];

// ============================================================================
// COMMUNICATION CHANNELS STATUS
// ============================================================================
var COMMS_CHANNELS = [
  {name:'SIPRNet',type:'Classified Network',status:'operational',latency:'12ms',bandwidth:'10 Gbps',encryption:'Type 1',uptime:99.99,lastIncident:'Never',backup:'Alternate SIPRNet node'},
  {name:'JWICS',type:'Top Secret Network',status:'operational',latency:'8ms',bandwidth:'40 Gbps',encryption:'Type 1',uptime:99.99,lastIncident:'Never',backup:'Mobile JWICS terminal'},
  {name:'NIPRNet',type:'Unclassified Network',status:'operational',latency:'5ms',bandwidth:'100 Gbps',encryption:'TLS 1.3',uptime:99.95,lastIncident:'2026-08-15',backup:'Commercial internet'},
  {name:'SATCOM Primary',type:'Satellite',status:'operational',latency:'540ms',bandwidth:'50 Mbps',encryption:'Suite B',uptime:99.90,lastIncident:'2026-07-20',backup:'SATCOM Secondary'},
  {name:'SATCOM Secondary',type:'Satellite',status:'standby',latency:'580ms',bandwidth:'25 Mbps',encryption:'Suite B',uptime:99.85,lastIncident:'2026-06-10',backup:'HF Radio'},
  {name:'HF Radio',type:'Radio',status:'standby',latency:'N/A',bandwidth:'9.6 kbps',encryption:'KY-99',uptime:99.99,lastIncident:'Never',backup:'Courier'},
  {name:'Secure Video',type:'VTC',status:'operational',latency:'45ms',bandwidth:'20 Mbps',encryption:'Type 1',uptime:99.90,lastIncident:'2026-08-02',backup:'Secure Voice'},
  {name:'Secure Voice',type:'SVOIP',status:'operational',latency:'25ms',bandwidth:'256 kbps',encryption:'Type 1',uptime:99.95,lastIncident:'2026-05-15',backup:'STU-III'},
  {name:'ISAC Sharing',type:'Information Sharing',status:'operational',latency:'< 1s',bandwidth:'N/A',encryption:'TLS 1.3 + PGP',uptime:99.80,lastIncident:'2026-07-01',backup:'Email + phone tree'},
  {name:'Emergency Alert System',type:'Public Warning',status:'operational',latency:'30s',bandwidth:'N/A',encryption:'Authenticated',uptime:99.99,lastIncident:'Never',backup:'IPAWS'}
];

function renderCommsStatus() {
  var html = '<div class="pm-section-title">Communication Channels Status</div>' +
    '<div class="pm-table-wrap pm-mb-16"><table class="pm-table pm-compact">' +
    '<tr><th>Channel</th><th>Type</th><th>Status</th><th>Latency</th><th>Bandwidth</th><th>Encryption</th><th>Uptime</th><th>Last Incident</th><th>Backup</th></tr>';
  for (var c = 0; c < COMMS_CHANNELS.length; c++) {
    var ch = COMMS_CHANNELS[c];
    var statusBadge = ch.status === 'operational' ? 'pm-badge-info' : (ch.status === 'standby' ? 'pm-badge-medium' : 'pm-badge-critical');
    html += '<tr>' +
      '<td class="pm-text-sm">' + esc(ch.name) + '</td>' +
      '<td class="pm-text-xs">' + esc(ch.type) + '</td>' +
      '<td><span class="pm-badge ' + statusBadge + '">' + esc(ch.status) + '</span></td>' +
      '<td class="pm-text-xs">' + esc(ch.latency) + '</td>' +
      '<td class="pm-text-xs">' + esc(ch.bandwidth) + '</td>' +
      '<td class="pm-text-xs">' + esc(ch.encryption) + '</td>' +
      '<td class="pm-text-xs pm-text-green">' + esc(String(ch.uptime)) + '%</td>' +
      '<td class="pm-text-xs pm-text-muted">' + esc(ch.lastIncident) + '</td>' +
      '<td class="pm-text-xs">' + esc(ch.backup) + '</td>' +
    '</tr>';
  }
  html += '</table></div>';
  return html;
}

// ============================================================================
// EXTENDED REPORTING FUNCTIONS
// ============================================================================
function generateFullSituationReport() {
  var sitrep = generateSituationReport();
  var landscape = analyzeThreatLandscape();
  var supplyRisk = analyzeSupplyChainRisk();
  var geoRisk = analyzeGeoRisk();
  var surface = analyzeAttackSurface();

  var html = '<div class="pm-card" style="background:#080c14;">' +
    '<div class="pm-text-green pm-text-bold pm-mb-8">COMPREHENSIVE SITUATION REPORT</div>' +
    '<div class="pm-text-xs pm-text-muted pm-mb-8">DTG: ' + esc(sitrep.timestamp) + '</div>' +
    '<div class="pm-text-xs pm-text-muted pm-mb-12">CLASSIFICATION: TOP SECRET//SCI//NOFORN//PROMETHEUS</div>' +
    '<hr class="pm-separator">' +

    '<div class="pm-text-sm pm-text-bold pm-mb-8">1. OVERALL POSTURE</div>' +
    '<div class="pm-grid-4 pm-mb-12">' +
      '<div class="pm-kpi"><div class="pm-kpi-value pm-defcon-' + sitrep.defcon + '">' + esc(String(sitrep.defcon)) + '</div><div class="pm-kpi-label">DEFCON Level</div></div>' +
      '<div class="pm-kpi"><div class="pm-kpi-value">' + esc(String(sitrep.threatScore)) + '</div><div class="pm-kpi-label">Threat Score</div></div>' +
      '<div class="pm-kpi"><div class="pm-kpi-value pm-text-red">' + esc(String(sitrep.activeThreats)) + '</div><div class="pm-kpi-label">Active Threats</div></div>' +
      '<div class="pm-kpi"><div class="pm-kpi-value">' + esc(String(sitrep.recentIntel)) + '</div><div class="pm-kpi-label">Intel (24h)</div></div>' +
    '</div>' +

    '<div class="pm-text-sm pm-text-bold pm-mb-8">2. THREAT LANDSCAPE</div>' +
    '<div class="pm-text-sm pm-mb-8">Active APT Groups: ' + esc(String(landscape.activeAPTs)) + ' of ' + esc(String(landscape.totalAPTs)) + '</div>' +
    '<div class="pm-text-sm pm-mb-8">Active Campaigns: ' + esc(String(landscape.recentCampaigns)) + '</div>' +
    '<div class="pm-text-sm pm-mb-12">Top Threat Level: ' + esc(String(landscape.topThreatLevel)) + '/10</div>' +

    '<div class="pm-text-sm pm-text-bold pm-mb-8">3. ATTACK SURFACE</div>' +
    '<div class="pm-text-sm pm-mb-8">External-facing nodes: ' + esc(String(surface.externalFacing)) + '</div>' +
    '<div class="pm-text-sm pm-mb-8">Critical nodes exposed: ' + esc(String(surface.criticalExposed)) + '</div>' +
    '<div class="pm-text-sm pm-mb-8">SCADA systems exposed: ' + esc(String(surface.scadaExposed)) + '</div>' +
    '<div class="pm-text-sm pm-mb-12">Total vulnerabilities: ' + esc(String(surface.totalVulns)) + '</div>' +

    '<div class="pm-text-sm pm-text-bold pm-mb-8">4. SUPPLY CHAIN RISK</div>' +
    '<div class="pm-text-sm pm-mb-8">Components tracked: ' + esc(String(supplyRisk.totalComponents)) + '</div>' +
    '<div class="pm-text-sm pm-mb-8">Critical risk: ' + esc(String(supplyRisk.criticalRisk)) + ' | High risk: ' + esc(String(supplyRisk.highRisk)) + '</div>' +
    '<div class="pm-text-sm pm-mb-12">Average risk score: ' + esc(String(supplyRisk.avgRiskScore)) + '/100</div>' +

    '<div class="pm-text-sm pm-text-bold pm-mb-8">5. GEOPOLITICAL ASSESSMENT</div>' +
    '<div class="pm-text-sm pm-mb-8">Critical regions: ' + esc(String(geoRisk.criticalRegions.length)) + '</div>' +
    '<div class="pm-text-sm pm-mb-8">High probability events: ' + esc(String(geoRisk.highProbEvents.length)) + '</div>' +
    '<div class="pm-text-sm pm-mb-12">Correlated triggers: ' + esc(String(geoRisk.correlatedTriggers.length)) + ' pairs</div>' +

    '<div class="pm-text-sm pm-text-bold pm-mb-8">6. RECOMMENDATIONS</div>' +
    '<div class="pm-text-sm pm-mb-8">&#8226; Maintain DEFCON ' + esc(String(sitrep.defcon)) + ' posture across all sectors</div>' +
    '<div class="pm-text-sm pm-mb-8">&#8226; Priority patching: PAN-OS, FortiOS, Schneider Electric PLCs</div>' +
    '<div class="pm-text-sm pm-mb-8">&#8226; Enhanced monitoring on SCADA/ICS systems in energy and water sectors</div>' +
    '<div class="pm-text-sm pm-mb-8">&#8226; Credential rotation for all critical infrastructure service accounts</div>' +
    '<div class="pm-text-sm pm-mb-8">&#8226; Coordinate with Five Eyes partners on Volt Typhoon indicators</div>' +
    '<div class="pm-text-sm">&#8226; Brief sector ISACs on Sandworm SCADA malware variant</div>' +
  '</div>';

  return html;
}

function generateThreatMatrix() {
  var html = '<div class="pm-section-title">Threat Actor vs Sector Matrix</div>' +
    '<div class="pm-card pm-mb-16"><div class="pm-table-wrap"><table class="pm-table pm-compact">' +
    '<tr><th>Actor</th><th>Nation</th><th>Level</th>';
  var sectorShort = ['PWR', 'WTR', 'TEL', 'TRN', 'FIN', 'HLT', 'GOV', 'ENG'];
  var sectorFull = ['energy', 'water', 'telecom', 'transport', 'financial', 'healthcare', 'government', 'energy'];
  for (var h = 0; h < sectorShort.length; h++) {
    html += '<th class="pm-text-center">' + esc(sectorShort[h]) + '</th>';
  }
  html += '</tr>';

  for (var a = 0; a < Math.min(20, APT_GROUPS.length); a++) {
    var apt = APT_GROUPS[a];
    if (!apt.active) continue;
    html += '<tr>' +
      '<td class="pm-text-xs pm-text-bold">' + esc(apt.name) + '</td>' +
      '<td class="pm-text-xs">' + esc(apt.nation) + '</td>' +
      '<td class="pm-text-xs pm-text-' + (apt.threatLevel >= 9 ? 'red' : (apt.threatLevel >= 7 ? 'yellow' : 'blue')) + '">' + esc(String(apt.threatLevel)) + '</td>';
    for (var s = 0; s < sectorFull.length; s++) {
      var targets = apt.targets.join(',').toLowerCase();
      var hits = targets.indexOf(sectorFull[s]) !== -1 ||
                 (sectorFull[s] === 'energy' && targets.indexOf('critical_infrastructure') !== -1) ||
                 (sectorFull[s] === 'telecom' && targets.indexOf('technology') !== -1) ||
                 (sectorFull[s] === 'government' && targets.indexOf('military') !== -1);
      html += '<td class="pm-text-center ' + (hits ? 'pm-mitre-used' : 'pm-mitre-unused') + '">' + (hits ? '&#9679;' : '') + '</td>';
    }
    html += '</tr>';
  }
  html += '</table></div></div>';
  return html;
}

function renderAssessmentRubrics() {
  var html = '<div class="pm-section-title">Exercise Assessment Rubrics</div>';
  for (var r = 0; r < ASSESSMENT_RUBRICS.length; r++) {
    var rubric = ASSESSMENT_RUBRICS[r];
    html += '<div class="pm-card pm-mb-12">' +
      '<div class="pm-flex-between pm-mb-8">' +
        '<span class="pm-text-sm pm-text-bold pm-text-green">' + esc(rubric.category) + '</span>' +
        '<span class="pm-text-xs pm-text-muted">Weight: ' + esc(String(rubric.weight)) + '%</span>' +
      '</div>' +
      '<div class="pm-table-wrap"><table class="pm-table pm-compact">' +
      '<tr><th>Criterion</th><th style="color:#00ff88;">Excellent</th><th style="color:#00aaff;">Good</th><th style="color:#ffaa00;">Acceptable</th><th style="color:#ff0040;">Poor</th></tr>';
    for (var c = 0; c < rubric.criteria.length; c++) {
      var crit = rubric.criteria[c];
      html += '<tr>' +
        '<td class="pm-text-xs pm-text-bold">' + esc(crit.item) + '</td>' +
        '<td class="pm-text-xs pm-text-green">' + esc(crit.excellent) + '</td>' +
        '<td class="pm-text-xs pm-text-blue">' + esc(crit.good) + '</td>' +
        '<td class="pm-text-xs pm-text-yellow">' + esc(crit.acceptable) + '</td>' +
        '<td class="pm-text-xs pm-text-red">' + esc(crit.poor) + '</td>' +
      '</tr>';
    }
    html += '</table></div></div>';
  }
  return html;
}

function renderAnalysisMethods() {
  var html = '<div class="pm-section-title">Intelligence Analysis Methodologies</div>';
  for (var m = 0; m < ANALYSIS_METHODS.length; m++) {
    var method = ANALYSIS_METHODS[m];
    html += '<div class="pm-card pm-mb-12">' +
      '<div class="pm-text-sm pm-text-bold pm-text-green pm-mb-8">' + esc(method.name) + '</div>' +
      '<div class="pm-text-xs pm-text-muted pm-mb-8">' + esc(method.description) + '</div>' +
      '<div class="pm-label pm-mb-8">Steps</div>';
    for (var s = 0; s < method.steps.length; s++) {
      html += '<div class="pm-text-xs pm-mb-8">' + esc(String(s + 1)) + '. ' + esc(method.steps[s]) + '</div>';
    }
    html += '<div class="pm-text-xs pm-text-muted"><b>Applicability:</b> ' + esc(method.applicability) + '</div>' +
      '<div class="pm-text-xs pm-text-green"><b>Current Use:</b> ' + esc(method.currentUse) + '</div>' +
    '</div>';
  }
  return html;
}

// ============================================================================
// FINAL SYSTEM STATS
// ============================================================================
function renderSystemStats() {
  var totalNodes = INFRA_NODES.length;
  var totalAPTs = APT_GROUPS.length;
  var totalCampaigns = APT_CAMPAIGNS.length;
  var totalIntel = INTEL_FEEDS.length;
  var totalPredictions = THREAT_PREDICTIONS.length;
  var totalSupplyChain = SUPPLY_CHAIN.length;
  var totalGeoTriggers = GEO_TRIGGERS.length;
  var totalScenarios = WARGAME_SCENARIOS.length;
  var totalVulns = VULN_DATABASE.length;
  var totalIOCs = IOC_DATABASE.length;
  var totalDetections = DETECTION_RULES.length;
  var totalHunts = HUNT_QUERIES.length;
  var totalPlaybooks = IR_PLAYBOOKS.length;
  var totalDeceptions = DECEPTION_OPS.length;

  var html = '<div class="pm-section-title">PROMETHEUS System Statistics</div>' +
    '<div class="pm-grid-4 pm-mb-16">' +
      '<div class="pm-kpi"><div class="pm-kpi-value pm-text-green">' + esc(String(totalNodes)) + '</div><div class="pm-kpi-label">Infrastructure Nodes</div></div>' +
      '<div class="pm-kpi"><div class="pm-kpi-value pm-text-red">' + esc(String(totalAPTs)) + '</div><div class="pm-kpi-label">Threat Actors</div></div>' +
      '<div class="pm-kpi"><div class="pm-kpi-value pm-text-yellow">' + esc(String(totalCampaigns)) + '</div><div class="pm-kpi-label">Active Campaigns</div></div>' +
      '<div class="pm-kpi"><div class="pm-kpi-value pm-text-blue">' + esc(String(totalIntel)) + '</div><div class="pm-kpi-label">Intel Reports</div></div>' +
    '</div>' +
    '<div class="pm-grid-4 pm-mb-16">' +
      '<div class="pm-kpi"><div class="pm-kpi-value">' + esc(String(totalPredictions)) + '</div><div class="pm-kpi-label">Threat Predictions</div></div>' +
      '<div class="pm-kpi"><div class="pm-kpi-value">' + esc(String(totalSupplyChain)) + '</div><div class="pm-kpi-label">Supply Chain Components</div></div>' +
      '<div class="pm-kpi"><div class="pm-kpi-value">' + esc(String(totalGeoTriggers)) + '</div><div class="pm-kpi-label">Geopolitical Triggers</div></div>' +
      '<div class="pm-kpi"><div class="pm-kpi-value">' + esc(String(totalScenarios)) + '</div><div class="pm-kpi-label">Wargame Scenarios</div></div>' +
    '</div>' +
    '<div class="pm-grid-4 pm-mb-16">' +
      '<div class="pm-kpi"><div class="pm-kpi-value pm-text-red">' + esc(String(totalVulns)) + '</div><div class="pm-kpi-label">Tracked CVEs</div></div>' +
      '<div class="pm-kpi"><div class="pm-kpi-value pm-text-yellow">' + esc(String(totalIOCs)) + '</div><div class="pm-kpi-label">Active IOCs</div></div>' +
      '<div class="pm-kpi"><div class="pm-kpi-value pm-text-green">' + esc(String(totalDetections)) + '</div><div class="pm-kpi-label">Detection Rules</div></div>' +
      '<div class="pm-kpi"><div class="pm-kpi-value pm-text-blue">' + esc(String(totalHunts)) + '</div><div class="pm-kpi-label">Hunt Queries</div></div>' +
    '</div>' +
    '<div class="pm-grid-4">' +
      '<div class="pm-kpi"><div class="pm-kpi-value">' + esc(String(totalPlaybooks)) + '</div><div class="pm-kpi-label">IR Playbooks</div></div>' +
      '<div class="pm-kpi"><div class="pm-kpi-value">' + esc(String(totalDeceptions)) + '</div><div class="pm-kpi-label">Deception Ops</div></div>' +
      '<div class="pm-kpi"><div class="pm-kpi-value">' + esc(String(NATION_PROFILES.length)) + '</div><div class="pm-kpi-label">Nation Profiles</div></div>' +
      '<div class="pm-kpi"><div class="pm-kpi-value">' + esc(String(COMMS_CHANNELS.length)) + '</div><div class="pm-kpi-label">Comms Channels</div></div>' +
    '</div>';
  return html;
}


// ============================================================================
// ADDITIONAL IOC ANALYSIS AND ENRICHMENT
// ============================================================================
function enrichIOC(ioc) {
  var enriched = {
    ioc: ioc,
    relatedIOCs: [],
    relatedAPTs: [],
    affectedNodes: [],
    detectionRules: [],
    riskScore: 0
  };

  for (var i = 0; i < IOC_DATABASE.length; i++) {
    if (IOC_DATABASE[i].value !== ioc.value && IOC_DATABASE[i].threat === ioc.threat) {
      enriched.relatedIOCs.push(IOC_DATABASE[i]);
    }
  }

  for (var a = 0; a < APT_GROUPS.length; a++) {
    if (APT_GROUPS[a].name === ioc.threat || APT_GROUPS[a].id === ioc.threat) {
      enriched.relatedAPTs.push(APT_GROUPS[a]);
    }
    for (var al = 0; al < APT_GROUPS[a].aliases.length; al++) {
      if (APT_GROUPS[a].aliases[al] === ioc.threat) {
        enriched.relatedAPTs.push(APT_GROUPS[a]);
        break;
      }
    }
  }

  for (var d = 0; d < DETECTION_RULES.length; d++) {
    if (ioc.tags) {
      for (var t = 0; t < ioc.tags.length; t++) {
        if (DETECTION_RULES[d].description.toLowerCase().indexOf(ioc.tags[t].toLowerCase()) !== -1) {
          enriched.detectionRules.push(DETECTION_RULES[d]);
          break;
        }
      }
    }
  }

  enriched.riskScore = (ioc.confidence === 'high' ? 80 : (ioc.confidence === 'medium' ? 50 : 20));
  if (enriched.relatedAPTs.length > 0) {
    enriched.riskScore = Math.min(100, enriched.riskScore + enriched.relatedAPTs[0].threatLevel * 2);
  }

  return enriched;
}

function renderIOCTable() {
  var html = '<div class="pm-section-title">Indicator of Compromise Database (' + esc(String(IOC_DATABASE.length)) + ' IOCs)</div>' +
    '<div class="pm-table-wrap pm-mb-16"><table class="pm-table pm-compact pm-striped">' +
    '<tr><th>Type</th><th>Value</th><th>Threat Actor</th><th>Confidence</th><th>First Seen</th><th>Last Seen</th><th>Source</th><th>Tags</th></tr>';
  for (var i = 0; i < IOC_DATABASE.length; i++) {
    var ioc = IOC_DATABASE[i];
    var confColor = ioc.confidence === 'high' ? 'pm-text-red' : (ioc.confidence === 'medium' ? 'pm-text-yellow' : 'pm-text-blue');
    var displayVal = ioc.value.length > 50 ? ioc.value.substring(0, 47) + '...' : ioc.value;
    html += '<tr>' +
      '<td><span class="pm-tag">' + esc(ioc.type) + '</span></td>' +
      '<td class="pm-text-xs" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;" title="' + esc(ioc.value) + '">' + esc(displayVal) + '</td>' +
      '<td class="pm-text-xs pm-text-bold">' + esc(ioc.threat) + '</td>' +
      '<td class="' + confColor + '">' + esc(ioc.confidence) + '</td>' +
      '<td class="pm-text-xs pm-text-muted">' + esc(ioc.firstSeen) + '</td>' +
      '<td class="pm-text-xs pm-text-muted">' + esc(ioc.lastSeen) + '</td>' +
      '<td class="pm-text-xs">' + esc(ioc.source) + '</td>' +
      '<td class="pm-text-xs">';
    for (var t = 0; t < ioc.tags.length; t++) {
      html += '<span class="pm-tag">' + esc(ioc.tags[t]) + '</span>';
    }
    html += '</td></tr>';
  }
  html += '</table></div>';
  return html;
}

// ============================================================================
// OPERATIONAL READINESS ASSESSMENTS
// ============================================================================
var READINESS_ASSESSMENTS = [
  {area:'SOC Operations',readiness:92,personnel:{authorized:45,onDuty:12,available:38},gaps:['Night shift understaffed','Senior analyst vacancy'],lastDrill:'2026-09-10',nextDrill:'2026-09-17'},
  {area:'Incident Response',readiness:87,personnel:{authorized:20,onDuty:5,available:16},gaps:['ICS forensics capability limited','Cloud IR experience needed'],lastDrill:'2026-09-05',nextDrill:'2026-09-19'},
  {area:'Threat Intelligence',readiness:95,personnel:{authorized:15,onDuty:4,available:13},gaps:['Language capability for Farsi limited'],lastDrill:'2026-09-08',nextDrill:'2026-09-22'},
  {area:'Vulnerability Management',readiness:78,personnel:{authorized:10,onDuty:3,available:8},gaps:['OT patching cadence behind schedule','Third-party coordination slow'],lastDrill:'2026-08-28',nextDrill:'2026-09-25'},
  {area:'OT/ICS Security',readiness:72,personnel:{authorized:8,onDuty:2,available:6},gaps:['Limited PLC forensics tools','Cross-sector coordination needed','Backup control procedures incomplete'],lastDrill:'2026-08-15',nextDrill:'2026-09-20'},
  {area:'Digital Forensics',readiness:88,personnel:{authorized:12,onDuty:3,available:10},gaps:['Mobile forensics backlog','Cloud evidence collection process'],lastDrill:'2026-09-02',nextDrill:'2026-09-16'},
  {area:'Red Team Operations',readiness:91,personnel:{authorized:8,onDuty:2,available:7},gaps:['ICS-specific tooling needed'],lastDrill:'2026-09-07',nextDrill:'2026-09-21'},
  {area:'Crisis Communications',readiness:83,personnel:{authorized:6,onDuty:2,available:5},gaps:['Media training for technical staff','Template updates needed'],lastDrill:'2026-08-20',nextDrill:'2026-09-18'},
  {area:'Legal & Compliance',readiness:86,personnel:{authorized:5,onDuty:1,available:4},gaps:['International law expertise for cyber ops','GDPR notification process'],lastDrill:'2026-08-25',nextDrill:'2026-09-23'},
  {area:'Recovery Operations',readiness:79,personnel:{authorized:15,onDuty:4,available:12},gaps:['Air-gapped backup testing overdue','DR site network config outdated','Recovery time objectives not validated'],lastDrill:'2026-08-10',nextDrill:'2026-09-15'}
];

function renderReadinessAssessment() {
  var html = '<div class="pm-section-title">Operational Readiness Assessment</div>';
  var avgReadiness = 0;
  for (var r = 0; r < READINESS_ASSESSMENTS.length; r++) {
    avgReadiness += READINESS_ASSESSMENTS[r].readiness;
  }
  avgReadiness = Math.round(avgReadiness / READINESS_ASSESSMENTS.length);

  html += '<div class="pm-grid-3 pm-mb-16">' +
    '<div class="pm-kpi"><div class="pm-kpi-value pm-text-' + (avgReadiness >= 85 ? 'green' : (avgReadiness >= 70 ? 'yellow' : 'red')) + '">' + esc(String(avgReadiness)) + '%</div><div class="pm-kpi-label">Overall Readiness</div></div>' +
    '<div class="pm-kpi"><div class="pm-kpi-value">' + esc(String(READINESS_ASSESSMENTS.length)) + '</div><div class="pm-kpi-label">Assessment Areas</div></div>' +
    '<div class="pm-kpi"><div class="pm-kpi-value pm-text-yellow">';
  var gapCount = 0;
  for (var g = 0; g < READINESS_ASSESSMENTS.length; g++) { gapCount += READINESS_ASSESSMENTS[g].gaps.length; }
  html += esc(String(gapCount)) + '</div><div class="pm-kpi-label">Identified Gaps</div></div></div>';

  html += '<div class="pm-grid-2">';
  for (var a = 0; a < READINESS_ASSESSMENTS.length; a++) {
    var assess = READINESS_ASSESSMENTS[a];
    var readColor = assess.readiness >= 90 ? '#00ff88' : (assess.readiness >= 80 ? '#00aaff' : (assess.readiness >= 70 ? '#ffaa00' : '#ff0040'));
    html += '<div class="pm-card">' +
      '<div class="pm-flex-between pm-mb-8">' +
        '<span class="pm-text-sm pm-text-bold">' + esc(assess.area) + '</span>' +
        '<span style="color:' + readColor + ';font-weight:bold;font-size:18px;">' + esc(String(assess.readiness)) + '%</span>' +
      '</div>' +
      '<div class="pm-progress pm-mb-12"><div class="pm-progress-bar" style="width:' + assess.readiness + '%;background:' + readColor + ';"></div></div>' +
      '<div class="pm-grid-3" style="gap:8px;">' +
        '<div class="pm-text-xs"><b>Authorized:</b> ' + esc(String(assess.personnel.authorized)) + '</div>' +
        '<div class="pm-text-xs"><b>On Duty:</b> ' + esc(String(assess.personnel.onDuty)) + '</div>' +
        '<div class="pm-text-xs"><b>Available:</b> ' + esc(String(assess.personnel.available)) + '</div>' +
      '</div>';
    if (assess.gaps.length > 0) {
      html += '<div class="pm-label pm-mb-8 pm-mt-12">Gaps</div>';
      for (var gp = 0; gp < assess.gaps.length; gp++) {
        html += '<div class="pm-text-xs pm-text-yellow pm-mb-8">&#9888; ' + esc(assess.gaps[gp]) + '</div>';
      }
    }
    html += '<div class="pm-text-xs pm-text-muted pm-mt-12">Last Drill: ' + esc(assess.lastDrill) + ' | Next: ' + esc(assess.nextDrill) + '</div>' +
    '</div>';
  }
  html += '</div>';
  return html;
}

// ============================================================================
// THREAT TREND ANALYSIS
// ============================================================================
var THREAT_TRENDS = [
  {period:'2026-Q1',incidents:847,criticalIncidents:23,avgResponseTime:42,avgDetectionTime:18,topThreat:'Ransomware',topAPT:'LockBit',topSector:'Healthcare'},
  {period:'2026-Q2',incidents:912,criticalIncidents:31,avgResponseTime:38,avgDetectionTime:15,topThreat:'Supply Chain',topAPT:'APT29',topSector:'Government'},
  {period:'2026-Q3',incidents:1087,criticalIncidents:45,avgResponseTime:35,avgDetectionTime:12,topThreat:'SCADA Targeting',topAPT:'Sandworm',topSector:'Energy'},
  {period:'2025-Q4',incidents:723,criticalIncidents:18,avgResponseTime:48,avgDetectionTime:22,topThreat:'Ransomware',topAPT:'BlackCat',topSector:'Financial'},
  {period:'2025-Q3',incidents:681,criticalIncidents:15,avgResponseTime:52,avgDetectionTime:25,topThreat:'Espionage',topAPT:'Volt Typhoon',topSector:'Telecom'},
  {period:'2025-Q2',incidents:598,criticalIncidents:12,avgResponseTime:55,avgDetectionTime:28,topThreat:'Phishing',topAPT:'APT28',topSector:'Government'},
  {period:'2025-Q1',incidents:534,criticalIncidents:10,avgResponseTime:58,avgDetectionTime:30,topThreat:'Ransomware',topAPT:'LockBit',topSector:'Healthcare'},
  {period:'2024-Q4',incidents:489,criticalIncidents:8,avgResponseTime:62,avgDetectionTime:35,topThreat:'Zero-day Exploitation',topAPT:'APT41',topSector:'Technology'}
];

function renderThreatTrends() {
  var html = '<div class="pm-section-title">Threat Trend Analysis (Quarterly)</div>' +
    '<div class="pm-table-wrap pm-mb-16"><table class="pm-table">' +
    '<tr><th>Period</th><th>Total Incidents</th><th>Critical</th><th>Avg Detection (min)</th><th>Avg Response (min)</th><th>Top Threat</th><th>Top APT</th><th>Top Sector</th></tr>';
  for (var t = 0; t < THREAT_TRENDS.length; t++) {
    var trend = THREAT_TRENDS[t];
    html += '<tr>' +
      '<td class="pm-text-sm pm-text-bold">' + esc(trend.period) + '</td>' +
      '<td>' + esc(String(trend.incidents)) + '</td>' +
      '<td class="pm-text-red">' + esc(String(trend.criticalIncidents)) + '</td>' +
      '<td class="' + (trend.avgDetectionTime <= 15 ? 'pm-text-green' : (trend.avgDetectionTime <= 25 ? 'pm-text-yellow' : 'pm-text-red')) + '">' + esc(String(trend.avgDetectionTime)) + '</td>' +
      '<td class="' + (trend.avgResponseTime <= 40 ? 'pm-text-green' : (trend.avgResponseTime <= 55 ? 'pm-text-yellow' : 'pm-text-red')) + '">' + esc(String(trend.avgResponseTime)) + '</td>' +
      '<td class="pm-text-xs">' + esc(trend.topThreat) + '</td>' +
      '<td class="pm-text-xs pm-text-bold">' + esc(trend.topAPT) + '</td>' +
      '<td class="pm-text-xs">' + esc(trend.topSector) + '</td>' +
    '</tr>';
  }
  html += '</table></div>';

  html += '<div class="pm-grid-4 pm-mb-16">';
  var latest = THREAT_TRENDS[0];
  var previous = THREAT_TRENDS[1];
  var incidentChange = Math.round(((latest.incidents - previous.incidents) / previous.incidents) * 100);
  var critChange = Math.round(((latest.criticalIncidents - previous.criticalIncidents) / previous.criticalIncidents) * 100);
  var detChange = latest.avgDetectionTime - previous.avgDetectionTime;
  var respChange = latest.avgResponseTime - previous.avgResponseTime;
  html += '<div class="pm-kpi"><div class="pm-kpi-value ' + (incidentChange > 0 ? 'pm-text-red' : 'pm-text-green') + '">' + (incidentChange > 0 ? '+' : '') + esc(String(incidentChange)) + '%</div><div class="pm-kpi-label">Incident Change</div></div>' +
    '<div class="pm-kpi"><div class="pm-kpi-value ' + (critChange > 0 ? 'pm-text-red' : 'pm-text-green') + '">' + (critChange > 0 ? '+' : '') + esc(String(critChange)) + '%</div><div class="pm-kpi-label">Critical Change</div></div>' +
    '<div class="pm-kpi"><div class="pm-kpi-value ' + (detChange > 0 ? 'pm-text-red' : 'pm-text-green') + '">' + (detChange > 0 ? '+' : '') + esc(String(detChange)) + ' min</div><div class="pm-kpi-label">Detection Time</div></div>' +
    '<div class="pm-kpi"><div class="pm-kpi-value ' + (respChange > 0 ? 'pm-text-red' : 'pm-text-green') + '">' + (respChange > 0 ? '+' : '') + esc(String(respChange)) + ' min</div><div class="pm-kpi-label">Response Time</div></div>' +
  '</div>';
  return html;
}

// ============================================================================
// RESOURCE ALLOCATION TRACKING
// ============================================================================
var RESOURCE_ALLOCATION = {
  personnel: {
    total: 200,
    deployed: {soc: 45, ir: 20, ti: 15, vm: 10, ics: 8, forensics: 12, redteam: 8, comms: 6, legal: 5, recovery: 15, management: 10, reserve: 46},
    shifts: {day: {start: '06:00', end: '14:00', staff: 85}, swing: {start: '14:00', end: '22:00', staff: 65}, night: {start: '22:00', end: '06:00', staff: 50}}
  },
  systems: {
    siem: {name: 'Splunk Enterprise', status: 'operational', eps: 125000, storage: '80 TB', retention: '365 days', lastMaintenance: '2026-09-01'},
    edr: {name: 'CrowdStrike Falcon', status: 'operational', endpoints: 15000, coverage: '98%', lastUpdate: '2026-09-12'},
    ids: {name: 'Suricata + Zeek', status: 'operational', sensors: 45, signatures: 85000, lastUpdate: '2026-09-13'},
    soar: {name: 'Palo Alto XSOAR', status: 'operational', playbooks: 89, automations: 234, avgResponseTime: '2.3 min'},
    ti: {name: 'MISP + Custom', status: 'operational', feeds: 35, iocs: IOC_DATABASE.length, lastSync: '2026-09-13T02:00:00Z'},
    vuln: {name: 'Tenable.io + Qualys', status: 'operational', scannedAssets: 12000, lastScan: '2026-09-12', criticalFindings: 47},
    ot: {name: 'Dragos + Claroty', status: 'operational', monitoredDevices: 3500, protocols: 15, lastBaseline: '2026-09-01'}
  }
};

function renderResourceAllocation() {
  var html = '<div class="pm-section-title">Resource Allocation</div>' +
    '<div class="pm-grid-2 pm-mb-16">' +
      '<div class="pm-card">' +
        '<div class="pm-card-title">Personnel Deployment</div>' +
        '<div class="pm-text-sm pm-mb-12">Total: ' + esc(String(RESOURCE_ALLOCATION.personnel.total)) + ' | Reserve: ' + esc(String(RESOURCE_ALLOCATION.personnel.deployed.reserve)) + '</div>';
  var deptKeys = Object.keys(RESOURCE_ALLOCATION.personnel.deployed);
  for (var dk = 0; dk < deptKeys.length; dk++) {
    if (deptKeys[dk] === 'reserve' || deptKeys[dk] === 'management') continue;
    var count = RESOURCE_ALLOCATION.personnel.deployed[deptKeys[dk]];
    var pct = Math.round((count / RESOURCE_ALLOCATION.personnel.total) * 100);
    html += '<div class="pm-flex-between pm-mb-8"><span class="pm-text-xs">' + esc(deptKeys[dk].toUpperCase()) + '</span><span class="pm-text-xs">' + esc(String(count)) + ' (' + pct + '%)</span></div>' +
      '<div class="pm-progress pm-mb-8"><div class="pm-progress-bar pm-progress-green" style="width:' + pct + '%;"></div></div>';
  }
  html += '</div>';

  html += '<div class="pm-card">' +
    '<div class="pm-card-title">Security Systems Status</div>';
  var sysKeys = Object.keys(RESOURCE_ALLOCATION.systems);
  for (var sk = 0; sk < sysKeys.length; sk++) {
    var sys = RESOURCE_ALLOCATION.systems[sysKeys[sk]];
    html += '<div class="pm-roe-item">' +
      '<span class="pm-status-dot pm-dot-' + (sys.status === 'operational' ? 'green' : 'red') + '"></span>' +
      '<div style="flex:1;">' +
        '<div class="pm-text-sm pm-text-bold">' + esc(sys.name) + '</div>' +
        '<div class="pm-text-xs pm-text-muted">' + esc(sysKeys[sk].toUpperCase()) + ' | Status: ' + esc(sys.status) + '</div>' +
      '</div>' +
    '</div>';
  }
  html += '</div></div>';
  return html;
}

// ============================================================================
// MISSION BRIEFING GENERATOR
// ============================================================================
function generateMissionBriefing(scenario) {
  var html = '<div class="pm-card" style="background:#080c14;border:1px solid #ff0040;">' +
    '<div class="pm-class-banner" style="margin:-14px -14px 14px -14px;">TOP SECRET // SCI // NOFORN</div>' +
    '<div class="pm-text-green pm-text-bold pm-mb-8" style="font-size:16px;">MISSION BRIEFING</div>' +
    '<div class="pm-text-xs pm-text-muted pm-mb-12">DTG: ' + esc(new Date().toISOString()) + '</div>' +
    '<hr class="pm-separator">' +
    '<div class="pm-grid-2 pm-mb-12">' +
      '<div><div class="pm-label">Operation</div><div class="pm-text-sm pm-text-green">' + esc(scenario.name || 'UNNAMED') + '</div></div>' +
      '<div><div class="pm-label">Classification</div><div class="pm-text-sm pm-text-red">TOP SECRET//SCI//NOFORN</div></div>' +
      '<div><div class="pm-label">Duration</div><div class="pm-text-sm">' + esc(scenario.duration || 'TBD') + '</div></div>' +
      '<div><div class="pm-label">Difficulty</div><div class="pm-text-sm">' + esc(scenario.difficulty || 'TBD') + '</div></div>' +
    '</div>' +
    '<div class="pm-label pm-mb-8">Situation</div>' +
    '<div class="pm-text-sm pm-mb-12">' + esc(scenario.description || 'Briefing pending') + '</div>' +
    '<div class="pm-label pm-mb-8">Objectives</div>';
  if (scenario.objectives) {
    for (var o = 0; o < scenario.objectives.length; o++) {
      html += '<div class="pm-text-sm pm-mb-8">&#8226; ' + esc(scenario.objectives[o]) + '</div>';
    }
  }
  html += '<div class="pm-label pm-mb-8 pm-mt-12">Teams</div>' +
    '<div class="pm-flex pm-mb-12">';
  if (scenario.teams) {
    for (var t = 0; t < scenario.teams.length; t++) {
      var teamColor = scenario.teams[t] === 'Red' ? 'pm-btn-danger' : (scenario.teams[t] === 'Blue' ? 'pm-btn-blue' : '');
      html += '<span class="pm-btn pm-btn-sm ' + teamColor + '">' + esc(scenario.teams[t]) + '</span>';
    }
  }
  html += '</div>' +
    '<div class="pm-label pm-mb-8">Rules of Engagement</div>' +
    '<div class="pm-text-sm pm-mb-8">&#8226; No destructive actions against production systems</div>' +
    '<div class="pm-text-sm pm-mb-8">&#8226; All actions must be logged and attributable</div>' +
    '<div class="pm-text-sm pm-mb-8">&#8226; White cell has final authority on all disputes</div>' +
    '<div class="pm-text-sm pm-mb-8">&#8226; Exercise will be paused for any real-world incident</div>' +
    '<div class="pm-text-sm pm-mb-12">&#8226; Code word ENDEX terminates the exercise immediately</div>' +
    '<div class="pm-class-banner" style="margin:14px -14px -14px -14px;">TOP SECRET // SCI // NOFORN</div>' +
  '</div>';
  return html;
}

// ============================================================================
// RISK SCORE AGGREGATION
// ============================================================================
function calculateOverallRiskScore() {
  var threatScore = calculateThreatScore();
  var activeThreats = getActiveThreats().length;
  var criticalGeoTriggers = 0;
  for (var g = 0; g < GEO_TRIGGERS.length; g++) {
    if (GEO_TRIGGERS[g].escalationRisk === 'critical') criticalGeoTriggers++;
  }
  var highRiskComponents = getHighRiskComponents().length;
  var surface = analyzeAttackSurface();

  var overallScore = 0;
  overallScore += Math.min(250, threatScore / 4);
  overallScore += activeThreats * 15;
  overallScore += criticalGeoTriggers * 30;
  overallScore += highRiskComponents * 5;
  overallScore += surface.riskScore;

  return {
    overall: Math.min(1000, Math.round(overallScore)),
    components: {
      threatIntel: Math.min(250, Math.round(threatScore / 4)),
      activeThreats: activeThreats * 15,
      geopolitical: criticalGeoTriggers * 30,
      supplyChain: highRiskComponents * 5,
      attackSurface: surface.riskScore
    },
    level: overallScore >= 700 ? 'CRITICAL' : (overallScore >= 500 ? 'HIGH' : (overallScore >= 300 ? 'ELEVATED' : (overallScore >= 100 ? 'GUARDED' : 'LOW'))),
    color: overallScore >= 700 ? '#ff0040' : (overallScore >= 500 ? '#ff6600' : (overallScore >= 300 ? '#ffaa00' : (overallScore >= 100 ? '#00aaff' : '#00ff88')))
  };
}

function renderOverallRisk() {
  var risk = calculateOverallRiskScore();
  var html = '<div class="pm-card pm-card-glow" style="border-color:' + risk.color + ';">' +
    '<div class="pm-flex-between pm-mb-12">' +
      '<div>' +
        '<div class="pm-label">Overall Risk Level</div>' +
        '<div class="pm-metric" style="color:' + risk.color + ';">' + esc(risk.level) + '</div>' +
      '</div>' +
      '<div style="text-align:right;">' +
        '<div class="pm-label">Risk Score</div>' +
        '<div class="pm-metric" style="color:' + risk.color + ';">' + esc(String(risk.overall)) + '<span class="pm-text-muted pm-text-sm">/1000</span></div>' +
      '</div>' +
    '</div>' +
    '<div class="pm-progress pm-mb-12"><div class="pm-progress-bar" style="width:' + (risk.overall / 10) + '%;background:' + risk.color + ';"></div></div>' +
    '<div class="pm-grid-5">' +
      '<div class="pm-text-center"><div class="pm-text-xs pm-text-muted">Threat Intel</div><div class="pm-text-sm pm-text-bold">' + esc(String(risk.components.threatIntel)) + '</div></div>' +
      '<div class="pm-text-center"><div class="pm-text-xs pm-text-muted">Active Threats</div><div class="pm-text-sm pm-text-bold">' + esc(String(risk.components.activeThreats)) + '</div></div>' +
      '<div class="pm-text-center"><div class="pm-text-xs pm-text-muted">Geopolitical</div><div class="pm-text-sm pm-text-bold">' + esc(String(risk.components.geopolitical)) + '</div></div>' +
      '<div class="pm-text-center"><div class="pm-text-xs pm-text-muted">Supply Chain</div><div class="pm-text-sm pm-text-bold">' + esc(String(risk.components.supplyChain)) + '</div></div>' +
      '<div class="pm-text-center"><div class="pm-text-xs pm-text-muted">Attack Surface</div><div class="pm-text-sm pm-text-bold">' + esc(String(risk.components.attackSurface)) + '</div></div>' +
    '</div>' +
  '</div>';
  return html;
}


// ============================================================================
// INCIDENT CLASSIFICATION TAXONOMY
// ============================================================================
var INCIDENT_TAXONOMY = [
  {category:'CAT 1 - Unauthorized Access',description:'Unauthorized logical or physical access to systems or data',examples:['Compromised credentials','Exploited vulnerability','Insider misuse','Physical access violation'],severity:'High',sla:'1 hour',notification:['SOC Manager','CISO','Legal']},
  {category:'CAT 2 - Denial of Service',description:'Actions that impair the normal operation of networks or systems',examples:['Volumetric DDoS','Application layer DoS','Resource exhaustion','Amplification attack'],severity:'High',sla:'30 minutes',notification:['SOC Manager','Network Ops','ISP']},
  {category:'CAT 3 - Malicious Code',description:'Installation of malware including viruses, worms, trojans, ransomware',examples:['Ransomware deployment','Trojan installation','Worm propagation','Rootkit detection'],severity:'Critical',sla:'15 minutes',notification:['SOC Manager','CISO','IR Team','Legal']},
  {category:'CAT 4 - Improper Usage',description:'Violation of acceptable use policies',examples:['Policy violation','Shadow IT','Unauthorized software','Data handling violation'],severity:'Medium',sla:'4 hours',notification:['SOC Analyst','HR']},
  {category:'CAT 5 - Scans/Probes',description:'Reconnaissance or suspicious activity targeting networks or systems',examples:['Port scanning','Vulnerability scanning','Web application probing','Social engineering attempts'],severity:'Low',sla:'24 hours',notification:['SOC Analyst']},
  {category:'CAT 6 - Investigation',description:'Unconfirmed incidents requiring further analysis',examples:['Anomalous behavior','Suspicious traffic','Unusual login patterns','Potential data leak'],severity:'Medium',sla:'4 hours',notification:['SOC Analyst','Team Lead']},
  {category:'CAT 7 - Destructive Attack',description:'Actions that destroy or irreversibly damage systems or data',examples:['Wiper malware','Physical destruction','Data corruption','Firmware manipulation'],severity:'Critical',sla:'Immediate',notification:['CISO','CEO','Legal','Law Enforcement','CISA']},
  {category:'CAT 8 - Espionage',description:'Unauthorized intelligence collection by nation-state or advanced actors',examples:['APT campaign','Data exfiltration','Credential harvesting for intel','Long-term access maintenance'],severity:'Critical',sla:'1 hour',notification:['CISO','CI','FBI','Intelligence Community']}
];

function renderIncidentTaxonomy() {
  var html = '<div class="pm-section-title">Incident Classification Taxonomy</div>' +
    '<div class="pm-table-wrap pm-mb-16"><table class="pm-table">' +
    '<tr><th>Category</th><th>Description</th><th>Severity</th><th>SLA</th><th>Notification</th></tr>';
  for (var i = 0; i < INCIDENT_TAXONOMY.length; i++) {
    var cat = INCIDENT_TAXONOMY[i];
    var sevBadge = cat.severity === 'Critical' ? 'pm-badge-critical' : (cat.severity === 'High' ? 'pm-badge-high' : (cat.severity === 'Medium' ? 'pm-badge-medium' : 'pm-badge-low'));
    html += '<tr>' +
      '<td class="pm-text-sm pm-text-bold">' + esc(cat.category) + '</td>' +
      '<td class="pm-text-xs">' + esc(cat.description) + '</td>' +
      '<td><span class="pm-badge ' + sevBadge + '">' + esc(cat.severity) + '</span></td>' +
      '<td class="pm-text-xs">' + esc(cat.sla) + '</td>' +
      '<td class="pm-text-xs">' + esc(cat.notification.join(', ')) + '</td>' +
    '</tr>';
  }
  html += '</table></div>';
  return html;
}

// ============================================================================
// CRITICAL ASSET PRIORITIZATION
// ============================================================================
function prioritizeCriticalAssets() {
  var assets = [];
  for (var i = 0; i < INFRA_NODES.length; i++) {
    var node = INFRA_NODES[i];
    var dependents = getDependents(node.id);
    var vulns = getVulnsForNode(node.id);
    var crossSectorDeps = 0;
    for (var d = 0; d < node.deps.length; d++) {
      var depNode = getNodeById(node.deps[d]);
      if (depNode && depNode.sector !== node.sector) crossSectorDeps++;
    }

    var priority = 0;
    priority += node.criticality * 10;
    priority += dependents.length * 8;
    priority += node.population / 100000;
    priority += vulns.length * 15;
    priority += crossSectorDeps * 5;
    if (node.type === 'scada' || node.type === 'control' || node.type === 'nuclear' || node.type === 'nuclear_cmd') {
      priority *= 1.5;
    }

    assets.push({
      id: node.id,
      name: node.name,
      sector: node.sector,
      type: node.type,
      criticality: node.criticality,
      dependents: dependents.length,
      population: node.population,
      vulns: vulns.length,
      crossSectorDeps: crossSectorDeps,
      priority: Math.round(priority)
    });
  }

  assets.sort(function(a, b) { return b.priority - a.priority; });
  return assets;
}

function renderCriticalAssets() {
  var assets = prioritizeCriticalAssets();
  var html = '<div class="pm-section-title">Critical Asset Prioritization (Top 25)</div>' +
    '<div class="pm-table-wrap pm-mb-16"><table class="pm-table pm-compact pm-striped">' +
    '<tr><th>#</th><th>ID</th><th>Asset</th><th>Sector</th><th>Type</th><th>Criticality</th><th>Dependents</th><th>Population</th><th>Vulns</th><th>Cross-Sector</th><th>Priority</th></tr>';
  for (var i = 0; i < Math.min(25, assets.length); i++) {
    var asset = assets[i];
    var prioColor = asset.priority >= 200 ? 'pm-text-red' : (asset.priority >= 100 ? 'pm-text-yellow' : 'pm-text-green');
    html += '<tr>' +
      '<td class="pm-text-xs pm-text-muted">' + esc(String(i + 1)) + '</td>' +
      '<td class="pm-text-xs">' + esc(asset.id) + '</td>' +
      '<td class="pm-text-sm">' + esc(asset.name) + '</td>' +
      '<td class="pm-text-xs">' + esc(asset.sector) + '</td>' +
      '<td class="pm-text-xs">' + esc(asset.type) + '</td>' +
      '<td class="pm-text-bold">' + esc(String(asset.criticality)) + '/10</td>' +
      '<td>' + esc(String(asset.dependents)) + '</td>' +
      '<td>' + esc(formatNumber(asset.population)) + '</td>' +
      '<td>' + (asset.vulns > 0 ? '<span class="pm-text-red">' + esc(String(asset.vulns)) + '</span>' : '0') + '</td>' +
      '<td>' + esc(String(asset.crossSectorDeps)) + '</td>' +
      '<td class="pm-text-bold ' + prioColor + '">' + esc(String(asset.priority)) + '</td>' +
    '</tr>';
  }
  html += '</table></div>';
  return html;
}

// ============================================================================
// SECTOR ISAC COORDINATION
// ============================================================================
var ISAC_STATUS = [
  {name:'E-ISAC (Electricity)',sector:'POWER_GRID',status:'active',lastComm:'5 min ago',threatLevel:'elevated',members:3200,activeAlerts:8,contactMethod:'Secure portal + encrypted email'},
  {name:'WaterISAC',sector:'WATER',status:'active',lastComm:'15 min ago',threatLevel:'elevated',members:5500,activeAlerts:5,contactMethod:'Secure portal + phone bridge'},
  {name:'IT-ISAC',sector:'TELECOM',status:'active',lastComm:'2 min ago',threatLevel:'high',members:4800,activeAlerts:12,contactMethod:'Secure portal + Slack'},
  {name:'A-ISAC (Aviation)',sector:'TRANSPORT',status:'active',lastComm:'30 min ago',threatLevel:'guarded',members:2100,activeAlerts:3,contactMethod:'Secure portal'},
  {name:'FS-ISAC (Financial)',sector:'FINANCIAL',status:'active',lastComm:'1 min ago',threatLevel:'high',members:7000,activeAlerts:15,contactMethod:'Secure portal + SWIFT network'},
  {name:'H-ISAC (Health)',sector:'HEALTHCARE',status:'active',lastComm:'10 min ago',threatLevel:'elevated',members:8500,activeAlerts:9,contactMethod:'Secure portal + HHS coordination'},
  {name:'MS-ISAC (Multi-State)',sector:'GOVERNMENT',status:'active',lastComm:'8 min ago',threatLevel:'high',members:14000,activeAlerts:11,contactMethod:'Secure portal + CISA integration'},
  {name:'ONG-ISAC (Oil & Natural Gas)',sector:'ENERGY',status:'active',lastComm:'20 min ago',threatLevel:'elevated',members:2800,activeAlerts:6,contactMethod:'Secure portal + API integration'}
];

function renderISACStatus() {
  var html = '<div class="pm-section-title">Sector ISAC Coordination Status</div>' +
    '<div class="pm-table-wrap pm-mb-16"><table class="pm-table">' +
    '<tr><th>ISAC</th><th>Status</th><th>Threat Level</th><th>Members</th><th>Active Alerts</th><th>Last Communication</th><th>Contact Method</th></tr>';
  for (var i = 0; i < ISAC_STATUS.length; i++) {
    var isac = ISAC_STATUS[i];
    var tlColor = isac.threatLevel === 'high' ? 'pm-badge-high' : (isac.threatLevel === 'elevated' ? 'pm-badge-medium' : 'pm-badge-low');
    html += '<tr>' +
      '<td class="pm-text-sm pm-text-bold">' + esc(isac.name) + '</td>' +
      '<td><span class="pm-badge pm-badge-info">' + esc(isac.status) + '</span></td>' +
      '<td><span class="pm-badge ' + tlColor + '">' + esc(isac.threatLevel) + '</span></td>' +
      '<td>' + esc(formatNumber(isac.members)) + '</td>' +
      '<td class="pm-text-yellow">' + esc(String(isac.activeAlerts)) + '</td>' +
      '<td class="pm-text-xs pm-text-muted">' + esc(isac.lastComm) + '</td>' +
      '<td class="pm-text-xs">' + esc(isac.contactMethod) + '</td>' +
    '</tr>';
  }
  html += '</table></div>';
  return html;
}

// ============================================================================
// FINAL PROMETHEUS SYSTEM METRICS
// ============================================================================
function renderPrometheusMetrics() {
  var totalDataPoints = INFRA_NODES.length + APT_GROUPS.length + APT_CAMPAIGNS.length +
    INTEL_FEEDS.length + THREAT_PREDICTIONS.length + SUPPLY_CHAIN.length +
    GEO_TRIGGERS.length + WARGAME_SCENARIOS.length + VULN_DATABASE.length +
    IOC_DATABASE.length + DETECTION_RULES.length + HUNT_QUERIES.length +
    IR_PLAYBOOKS.length + DECEPTION_OPS.length + NETWORK_FLOWS.length +
    NETWORK_SEGMENTS.length + COMMS_CHANNELS.length + NATION_PROFILES.length +
    READINESS_ASSESSMENTS.length + THREAT_TRENDS.length + INCIDENT_TAXONOMY.length +
    ISAC_STATUS.length + COMPLIANCE_STATUS.length;

  var html = '<div class="pm-card" style="border-color:#00ff88;margin-top:16px;">' +
    '<div class="pm-flex-between">' +
      '<div>' +
        '<div class="pm-text-green pm-text-bold" style="font-size:14px;">PROMETHEUS v2.0 — TRAINING MODE</div>' +
        '<div class="pm-text-xs pm-text-muted">Predictive Real-time Omniscient Monitoring, Emulation, Threat Hunting & Engagement Unified System</div>' +
      '</div>' +
      '<div class="pm-text-right">' +
        '<div class="pm-text-green pm-text-bold" style="font-size:18px;">' + esc(String(totalDataPoints)) + '</div>' +
        '<div class="pm-text-xs pm-text-muted">Total Data Points</div>' +
      '</div>' +
    '</div>' +
  '</div>';
  return html;
}


// ============================================================================
// HISTORICAL INCIDENT DATABASE
// ============================================================================
var HISTORICAL_INCIDENTS = [
  {id:'HI01',date:'2026-09-10',name:'Operation Fancy Storm Detection',category:'CAT 8',severity:'critical',apt:'APT28',sector:'GOVERNMENT',nodesAffected:['GV03','GV13'],detectionTime:12,containmentTime:45,recoveryTime:180,dataLoss:false,status:'resolved',lessonsLearned:'Enhanced email filtering detected phishing attempt. Need to improve lateral movement detection.'},
  {id:'HI02',date:'2026-09-05',name:'SCADA Anomaly Alert',category:'CAT 1',severity:'high',apt:'Unknown',sector:'WATER',nodesAffected:['WT11'],detectionTime:3,containmentTime:15,recoveryTime:60,dataLoss:false,status:'resolved',lessonsLearned:'OT monitoring sensors detected Modbus anomaly. False positive rate needs tuning.'},
  {id:'HI03',date:'2026-08-28',name:'Credential Stuffing Campaign',category:'CAT 1',severity:'medium',apt:'Unknown',sector:'FINANCIAL',nodesAffected:['FN07','FN09'],detectionTime:8,containmentTime:20,recoveryTime:120,dataLoss:false,status:'resolved',lessonsLearned:'Rate limiting and MFA prevented account compromise. Need to deploy credential monitoring.'},
  {id:'HI04',date:'2026-08-20',name:'Healthcare Ransomware Attempt',category:'CAT 3',severity:'critical',apt:'Rhysida',sector:'HEALTHCARE',nodesAffected:['HC03'],detectionTime:5,containmentTime:30,recoveryTime:240,dataLoss:false,status:'resolved',lessonsLearned:'EDR quarantined ransomware before encryption. Backup restoration tested successfully.'},
  {id:'HI05',date:'2026-08-15',name:'Supply Chain Alert',category:'CAT 6',severity:'medium',apt:'Unknown',sector:'GOVERNMENT',nodesAffected:[],detectionTime:60,containmentTime:120,recoveryTime:0,dataLoss:false,status:'false_positive',lessonsLearned:'npm package update triggered alert. Need to improve SBOM analysis automation.'},
  {id:'HI06',date:'2026-08-10',name:'DDoS Mitigation Event',category:'CAT 2',severity:'high',apt:'Hacktivists',sector:'FINANCIAL',nodesAffected:['FN01'],detectionTime:2,containmentTime:8,recoveryTime:30,dataLoss:false,status:'resolved',lessonsLearned:'CDN and DDoS mitigation absorbed 95% of traffic. Need to increase capacity for application-layer attacks.'},
  {id:'HI07',date:'2026-08-05',name:'Insider Investigation',category:'CAT 4',severity:'medium',apt:'Insider',sector:'GOVERNMENT',nodesAffected:['GV08'],detectionTime:480,containmentTime:60,recoveryTime:24,dataLoss:true,status:'resolved',lessonsLearned:'UEBA detected after-hours access pattern. Need to improve DLP coverage on classified systems.'},
  {id:'HI08',date:'2026-07-25',name:'Pipeline SCADA Probe',category:'CAT 5',severity:'low',apt:'Unknown',sector:'ENERGY',nodesAffected:['EN19'],detectionTime:15,containmentTime:30,recoveryTime:0,dataLoss:false,status:'resolved',lessonsLearned:'Perimeter firewall blocked Modbus scanning from external IP. Added IP to blocklist.'},
  {id:'HI09',date:'2026-07-15',name:'Volt Typhoon Activity',category:'CAT 8',severity:'critical',apt:'Volt Typhoon',sector:'TELECOM',nodesAffected:['TC08','TC14'],detectionTime:720,containmentTime:240,recoveryTime:480,dataLoss:false,status:'resolved',lessonsLearned:'LOTL technique evaded EDR for extended period. Need enhanced behavioral analytics.'},
  {id:'HI10',date:'2026-07-01',name:'Zero-Day Exploitation',category:'CAT 1',severity:'critical',apt:'APT41',sector:'HEALTHCARE',nodesAffected:['HC04','HC10'],detectionTime:45,containmentTime:90,recoveryTime:360,dataLoss:true,status:'resolved',lessonsLearned:'Zero-day in healthcare application exploited. Need virtual patching capability.'},
  {id:'HI11',date:'2026-06-20',name:'DNS Infrastructure Attack',category:'CAT 2',severity:'high',apt:'Unknown',sector:'TELECOM',nodesAffected:['TC10','TC11'],detectionTime:5,containmentTime:15,recoveryTime:45,dataLoss:false,status:'resolved',lessonsLearned:'DNS amplification attack mitigated. Need to deploy DNS response rate limiting.'},
  {id:'HI12',date:'2026-06-10',name:'Satellite Comm Disruption',category:'CAT 2',severity:'high',apt:'Sandworm',sector:'TELECOM',nodesAffected:['TC06'],detectionTime:10,containmentTime:30,recoveryTime:120,dataLoss:false,status:'resolved',lessonsLearned:'Satellite modem firmware targeted. Need firmware integrity monitoring.'},
  {id:'HI13',date:'2026-05-28',name:'Election System Probe',category:'CAT 5',severity:'medium',apt:'Multiple',sector:'GOVERNMENT',nodesAffected:['GV04'],detectionTime:20,containmentTime:40,recoveryTime:0,dataLoss:false,status:'resolved',lessonsLearned:'Multiple APTs probing election infrastructure ahead of cycle. Hardened perimeter and deployed additional monitoring.'},
  {id:'HI14',date:'2026-05-15',name:'Crypto Exchange Heist Attempt',category:'CAT 1',severity:'critical',apt:'Lazarus',sector:'FINANCIAL',nodesAffected:['FN11'],detectionTime:30,containmentTime:60,recoveryTime:180,dataLoss:false,status:'resolved',lessonsLearned:'Smart contract exploit attempt detected. Froze affected wallets. Need real-time DeFi monitoring.'},
  {id:'HI15',date:'2026-05-01',name:'Nuclear Facility Scan',category:'CAT 5',severity:'high',apt:'Unknown',sector:'POWER_GRID',nodesAffected:['PG01'],detectionTime:2,containmentTime:5,recoveryTime:0,dataLoss:false,status:'resolved',lessonsLearned:'Air-gapped systems not affected. External perimeter scan blocked. Reported to NRC.'}
];

function renderIncidentHistory() {
  var html = '<div class="pm-section-title">Historical Incident Database (' + esc(String(HISTORICAL_INCIDENTS.length)) + ' incidents)</div>' +
    '<div class="pm-grid-4 pm-mb-16">';
  var totalIncidents = HISTORICAL_INCIDENTS.length;
  var criticalCount = 0, resolvedCount = 0, avgDetection = 0, avgContainment = 0;
  for (var i = 0; i < totalIncidents; i++) {
    if (HISTORICAL_INCIDENTS[i].severity === 'critical') criticalCount++;
    if (HISTORICAL_INCIDENTS[i].status === 'resolved') resolvedCount++;
    avgDetection += HISTORICAL_INCIDENTS[i].detectionTime;
    avgContainment += HISTORICAL_INCIDENTS[i].containmentTime;
  }
  avgDetection = Math.round(avgDetection / totalIncidents);
  avgContainment = Math.round(avgContainment / totalIncidents);

  html += '<div class="pm-kpi"><div class="pm-kpi-value">' + esc(String(totalIncidents)) + '</div><div class="pm-kpi-label">Total Incidents</div></div>' +
    '<div class="pm-kpi"><div class="pm-kpi-value pm-text-red">' + esc(String(criticalCount)) + '</div><div class="pm-kpi-label">Critical</div></div>' +
    '<div class="pm-kpi"><div class="pm-kpi-value pm-text-yellow">' + esc(String(avgDetection)) + ' min</div><div class="pm-kpi-label">Avg Detection</div></div>' +
    '<div class="pm-kpi"><div class="pm-kpi-value pm-text-blue">' + esc(String(avgContainment)) + ' min</div><div class="pm-kpi-label">Avg Containment</div></div>' +
  '</div>';

  html += '<div class="pm-table-wrap pm-mb-16"><table class="pm-table pm-compact pm-striped">' +
    '<tr><th>Date</th><th>Incident</th><th>Category</th><th>Severity</th><th>APT</th><th>Sector</th><th>Detection</th><th>Containment</th><th>Recovery</th><th>Data Loss</th><th>Status</th></tr>';
  for (var h = 0; h < HISTORICAL_INCIDENTS.length; h++) {
    var inc = HISTORICAL_INCIDENTS[h];
    var sevBadge = inc.severity === 'critical' ? 'pm-badge-critical' : (inc.severity === 'high' ? 'pm-badge-high' : (inc.severity === 'medium' ? 'pm-badge-medium' : 'pm-badge-low'));
    html += '<tr>' +
      '<td class="pm-text-xs pm-text-muted">' + esc(inc.date) + '</td>' +
      '<td class="pm-text-xs pm-text-bold">' + esc(inc.name) + '</td>' +
      '<td class="pm-text-xs">' + esc(inc.category) + '</td>' +
      '<td><span class="pm-badge ' + sevBadge + '">' + esc(inc.severity) + '</span></td>' +
      '<td class="pm-text-xs">' + esc(inc.apt) + '</td>' +
      '<td class="pm-text-xs">' + esc(inc.sector) + '</td>' +
      '<td class="pm-text-xs">' + esc(String(inc.detectionTime)) + ' min</td>' +
      '<td class="pm-text-xs">' + esc(String(inc.containmentTime)) + ' min</td>' +
      '<td class="pm-text-xs">' + esc(String(inc.recoveryTime)) + ' min</td>' +
      '<td>' + (inc.dataLoss ? '<span class="pm-text-red">YES</span>' : '<span class="pm-text-green">NO</span>') + '</td>' +
      '<td><span class="pm-badge ' + (inc.status === 'resolved' ? 'pm-badge-info' : (inc.status === 'false_positive' ? 'pm-badge-low' : 'pm-badge-medium')) + '">' + esc(inc.status) + '</span></td>' +
    '</tr>';
  }
  html += '</table></div>';

  html += '<div class="pm-section-title">Lessons Learned Summary</div><div class="pm-card"><div class="pm-scroll-y">';
  for (var l = 0; l < HISTORICAL_INCIDENTS.length; l++) {
    var lesson = HISTORICAL_INCIDENTS[l];
    if (lesson.lessonsLearned) {
      html += '<div class="pm-evidence-item">' +
        '<div class="pm-text-xs pm-text-muted">' + esc(lesson.date) + ' - ' + esc(lesson.name) + '</div>' +
        '<div class="pm-text-sm">' + esc(lesson.lessonsLearned) + '</div>' +
      '</div>';
    }
  }
  html += '</div></div>';
  return html;
}

// ============================================================================
// PERFORMANCE METRICS
// ============================================================================
var PERFORMANCE_METRICS = {
  mttr: {current: 35, target: 30, trend: 'improving', history: [58, 52, 48, 42, 38, 35]},
  mttd: {current: 12, target: 10, trend: 'improving', history: [35, 28, 22, 18, 15, 12]},
  falsePositiveRate: {current: 8.2, target: 5.0, trend: 'stable', history: [15.5, 12.8, 10.5, 9.1, 8.5, 8.2]},
  patchCompliance: {current: 94, target: 99, trend: 'improving', history: [78, 82, 86, 89, 92, 94]},
  mfaAdoption: {current: 97, target: 100, trend: 'improving', history: [75, 82, 88, 92, 95, 97]},
  edpCoverage: {current: 98, target: 100, trend: 'stable', history: [90, 93, 95, 96, 97, 98]},
  vulnerabilitySLA: {critical: {sla: '24h', compliance: 92}, high: {sla: '7d', compliance: 87}, medium: {sla: '30d', compliance: 78}, low: {sla: '90d', compliance: 95}},
  incidentVolume: {current: 1087, previousQuarter: 912, change: 19.2}
};

function renderPerformanceMetrics() {
  var html = '<div class="pm-section-title">Security Operations Performance Metrics</div>' +
    '<div class="pm-grid-3 pm-mb-16">' +
      '<div class="pm-kpi">' +
        '<div class="pm-kpi-value pm-text-' + (PERFORMANCE_METRICS.mttd.current <= PERFORMANCE_METRICS.mttd.target ? 'green' : 'yellow') + '">' + esc(String(PERFORMANCE_METRICS.mttd.current)) + ' min</div>' +
        '<div class="pm-kpi-label">Mean Time to Detect</div>' +
        '<div class="pm-text-xs pm-text-muted">Target: ' + esc(String(PERFORMANCE_METRICS.mttd.target)) + ' min | ' + esc(PERFORMANCE_METRICS.mttd.trend) + '</div>' +
      '</div>' +
      '<div class="pm-kpi">' +
        '<div class="pm-kpi-value pm-text-' + (PERFORMANCE_METRICS.mttr.current <= PERFORMANCE_METRICS.mttr.target ? 'green' : 'yellow') + '">' + esc(String(PERFORMANCE_METRICS.mttr.current)) + ' min</div>' +
        '<div class="pm-kpi-label">Mean Time to Respond</div>' +
        '<div class="pm-text-xs pm-text-muted">Target: ' + esc(String(PERFORMANCE_METRICS.mttr.target)) + ' min | ' + esc(PERFORMANCE_METRICS.mttr.trend) + '</div>' +
      '</div>' +
      '<div class="pm-kpi">' +
        '<div class="pm-kpi-value pm-text-' + (PERFORMANCE_METRICS.falsePositiveRate.current <= PERFORMANCE_METRICS.falsePositiveRate.target ? 'green' : 'yellow') + '">' + esc(String(PERFORMANCE_METRICS.falsePositiveRate.current)) + '%</div>' +
        '<div class="pm-kpi-label">False Positive Rate</div>' +
        '<div class="pm-text-xs pm-text-muted">Target: ' + esc(String(PERFORMANCE_METRICS.falsePositiveRate.target)) + '% | ' + esc(PERFORMANCE_METRICS.falsePositiveRate.trend) + '</div>' +
      '</div>' +
    '</div>' +
    '<div class="pm-grid-3 pm-mb-16">' +
      '<div class="pm-kpi">' +
        '<div class="pm-kpi-value pm-text-green">' + esc(String(PERFORMANCE_METRICS.patchCompliance.current)) + '%</div>' +
        '<div class="pm-kpi-label">Patch Compliance</div>' +
      '</div>' +
      '<div class="pm-kpi">' +
        '<div class="pm-kpi-value pm-text-green">' + esc(String(PERFORMANCE_METRICS.mfaAdoption.current)) + '%</div>' +
        '<div class="pm-kpi-label">MFA Adoption</div>' +
      '</div>' +
      '<div class="pm-kpi">' +
        '<div class="pm-kpi-value pm-text-green">' + esc(String(PERFORMANCE_METRICS.edpCoverage.current)) + '%</div>' +
        '<div class="pm-kpi-label">EDR Coverage</div>' +
      '</div>' +
    '</div>' +
    '<div class="pm-section-title">Vulnerability SLA Compliance</div>' +
    '<div class="pm-grid-4 pm-mb-16">';
  var slaPriorities = ['critical', 'high', 'medium', 'low'];
  for (var s = 0; s < slaPriorities.length; s++) {
    var sla = PERFORMANCE_METRICS.vulnerabilitySLA[slaPriorities[s]];
    var slaColor = sla.compliance >= 90 ? 'pm-text-green' : (sla.compliance >= 80 ? 'pm-text-yellow' : 'pm-text-red');
    html += '<div class="pm-kpi">' +
      '<div class="pm-kpi-value ' + slaColor + '">' + esc(String(sla.compliance)) + '%</div>' +
      '<div class="pm-kpi-label">' + esc(slaPriorities[s].toUpperCase()) + ' (' + esc(sla.sla) + ')</div>' +
    '</div>';
  }
  html += '</div>';
  return html;
}


// ============================================================================
// ADDITIONAL SUPPLY CHAIN VULNERABILITY CASCADES
// ============================================================================
var SUPPLY_CASCADE_SCENARIOS = [
  {id:'SCC01',name:'OpenSSL Zero-Day',component:'SC21',description:'Critical zero-day in OpenSSL affecting all TLS communications',affectedDownstream:['SC06','SC07','SC08','SC12','SC14','SC21','SC23','SC36','SC37','SC38','SC94','SC95'],estimatedImpact:'95% of monitored infrastructure',mitigationTime:'48-72 hours for emergency patch deployment',riskLevel:'critical'},
  {id:'SCC02',name:'Log4j Resurgence',component:'SC22',description:'New Log4j bypass discovered affecting version 2.23.x',affectedDownstream:['SC08','SC12','SC41','SC42','SC92','SC101'],estimatedImpact:'Java-based applications across all sectors',mitigationTime:'24-48 hours',riskLevel:'critical'},
  {id:'SCC03',name:'Container Escape',component:'SC46',description:'Docker Engine container escape allowing host compromise',affectedDownstream:['SC47','SC48','SC49','SC50','SC51'],estimatedImpact:'All containerized workloads',mitigationTime:'24 hours for emergency patch',riskLevel:'high'},
  {id:'SCC04',name:'Kubernetes API Bypass',component:'SC47',description:'Authentication bypass in Kubernetes API server',affectedDownstream:['SC50','SC51','SC97','SC103'],estimatedImpact:'All orchestrated workloads',mitigationTime:'24-48 hours',riskLevel:'critical'},
  {id:'SCC05',name:'Cisco IOS XE Worm',component:'SC61',description:'Self-propagating exploit for Cisco IOS XE creating network-wide backdoors',affectedDownstream:['SC81','SC106'],estimatedImpact:'Network perimeter and routing infrastructure',mitigationTime:'72-96 hours (requires device-by-device remediation)',riskLevel:'critical'},
  {id:'SCC06',name:'FortiOS Chain',component:'SC62',description:'Chained exploits in FortiOS allowing pre-auth RCE',affectedDownstream:['SC82','SC107'],estimatedImpact:'All Fortinet perimeter devices',mitigationTime:'48-72 hours',riskLevel:'critical'},
  {id:'SCC07',name:'npm Supply Chain',component:'SC06',description:'Malicious package injection into popular npm library',affectedDownstream:['SC14','SC15','SC16','SC18','SC27','SC28','SC29'],estimatedImpact:'JavaScript/Node.js applications',mitigationTime:'24 hours to identify, 48 hours to remediate',riskLevel:'high'},
  {id:'SCC08',name:'Python PyPI Compromise',component:'SC07',description:'Typosquatting attack on critical Python package',affectedDownstream:['SC13','SC19','SC30','SC33','SC34','SC35','SC56'],estimatedImpact:'Python applications and ML pipelines',mitigationTime:'24-48 hours',riskLevel:'high'}
];

function renderSupplyChainCascades() {
  var html = '<div class="pm-section-title">Supply Chain Cascade Scenarios</div>';
  for (var i = 0; i < SUPPLY_CASCADE_SCENARIOS.length; i++) {
    var scenario = SUPPLY_CASCADE_SCENARIOS[i];
    var riskBadge = scenario.riskLevel === 'critical' ? 'pm-badge-critical' : 'pm-badge-high';
    html += '<div class="pm-card pm-mb-12" style="border-left:3px solid ' + (scenario.riskLevel === 'critical' ? '#ff0040' : '#ff6600') + ';">' +
      '<div class="pm-flex-between pm-mb-8">' +
        '<span class="pm-text-sm pm-text-bold">' + esc(scenario.name) + '</span>' +
        '<span class="pm-badge ' + riskBadge + '">' + esc(scenario.riskLevel) + '</span>' +
      '</div>' +
      '<div class="pm-text-xs pm-text-muted pm-mb-8">' + esc(scenario.description) + '</div>' +
      '<div class="pm-text-xs pm-mb-8"><b>Source Component:</b> ' + esc(scenario.component) + ' | <b>Downstream Affected:</b> ' + esc(String(scenario.affectedDownstream.length)) + ' components</div>' +
      '<div class="pm-text-xs pm-mb-8"><b>Estimated Impact:</b> ' + esc(scenario.estimatedImpact) + '</div>' +
      '<div class="pm-text-xs"><b>Mitigation Time:</b> ' + esc(scenario.mitigationTime) + '</div>' +
      '<div class="pm-flex-wrap pm-mt-12">';
    for (var d = 0; d < scenario.affectedDownstream.length; d++) {
      var comp = null;
      for (var c = 0; c < SUPPLY_CHAIN.length; c++) {
        if (SUPPLY_CHAIN[c].id === scenario.affectedDownstream[d]) { comp = SUPPLY_CHAIN[c]; break; }
      }
      html += '<span class="pm-tag" style="border-color:#ff6600;">' + esc(comp ? comp.name : scenario.affectedDownstream[d]) + '</span>';
    }
    html += '</div></div>';
  }
  return html;
}

// ============================================================================
// FINAL OPERATIONAL DASHBOARD SUMMARY
// ============================================================================
function renderOperationalDashboard() {
  var risk = calculateOverallRiskScore();
  var landscape = analyzeThreatLandscape();
  var supplyRisk = analyzeSupplyChainRisk();

  var html = renderOverallRisk();
  html += '<div class="pm-grid-2 pm-mt-16">';
  html += '<div class="pm-card"><div class="pm-card-title">Active APT Campaigns</div>';
  var activeCampaigns = 0;
  for (var c = 0; c < APT_CAMPAIGNS.length; c++) {
    if (APT_CAMPAIGNS[c].status === 'active') {
      activeCampaigns++;
      var apt = getAPTById(APT_CAMPAIGNS[c].apt);
      html += '<div class="pm-campaign-card">' +
        '<div class="pm-campaign-title">' + esc(APT_CAMPAIGNS[c].name) + '</div>' +
        '<div class="pm-text-xs">' + esc(apt ? apt.name + ' (' + apt.nation + ')' : APT_CAMPAIGNS[c].apt) +
        ' | Victims: ' + esc(String(APT_CAMPAIGNS[c].victims)) +
        ' | Sectors: ' + esc(APT_CAMPAIGNS[c].sectors.join(', ')) + '</div>' +
      '</div>';
    }
  }
  html += '</div>';

  html += '<div class="pm-card"><div class="pm-card-title">Critical Geopolitical Triggers</div>';
  for (var g = 0; g < GEO_TRIGGERS.length; g++) {
    if (GEO_TRIGGERS[g].escalationRisk === 'critical') {
      html += '<div class="pm-alert-item pm-alert-critical">' +
        '<span class="pm-text-xs" style="min-width:80px;">' + esc(GEO_TRIGGERS[g].region) + '</span>' +
        '<span class="pm-text-sm">' + esc(GEO_TRIGGERS[g].event) + '</span>' +
        '<span class="pm-text-red" style="margin-left:auto;">' + esc(String(GEO_TRIGGERS[g].probability)) + '%</span>' +
      '</div>';
    }
  }
  html += '</div></div>';

  html += renderPrometheusMetrics();
  return html;
}

// ============================================================================
// EXECUTIVE DASHBOARD WIDGET RENDERER
// ============================================================================
function renderExecutiveSummary() {
  var now = new Date();
  var timeStr = (now.getUTCHours() < 10 ? '0' : '') + now.getUTCHours() + ':' + (now.getUTCMinutes() < 10 ? '0' : '') + now.getUTCMinutes() + 'Z';
  var risk = calculateOverallRiskScore();

  var html = '<div class="pm-card pm-card-glow pm-mb-16">' +
    '<div class="pm-flex-between pm-mb-12">' +
      '<div class="pm-text-green pm-text-bold" style="font-size:16px;">EXECUTIVE CYBER OPERATIONS SUMMARY</div>' +
      '<div class="pm-text-xs pm-text-muted">' + esc(timeStr) + ' | AUTO-REFRESH 60s</div>' +
    '</div>' +
    '<div class="pm-grid-5">' +
      '<div class="pm-kpi"><div class="pm-kpi-value pm-defcon-' + state.defcon + '">' + esc(String(state.defcon)) + '</div><div class="pm-kpi-label">DEFCON</div></div>' +
      '<div class="pm-kpi"><div class="pm-kpi-value" style="color:' + risk.color + ';">' + esc(String(risk.overall)) + '</div><div class="pm-kpi-label">Risk Score</div></div>' +
      '<div class="pm-kpi"><div class="pm-kpi-value pm-text-red">' + esc(String(getActiveThreats().length)) + '</div><div class="pm-kpi-label">Active Threats</div></div>' +
      '<div class="pm-kpi"><div class="pm-kpi-value">' + esc(String(INFRA_NODES.length)) + '</div><div class="pm-kpi-label">Nodes Online</div></div>' +
      '<div class="pm-kpi"><div class="pm-kpi-value pm-text-green">' + esc(String(DECEPTION_OPS.length)) + '</div><div class="pm-kpi-label">Deceptions Active</div></div>' +
    '</div>' +
  '</div>';
  return html;
}


// ============================================================================
// THREAT INTELLIGENCE DISSEMINATION TRACKING
// ============================================================================
var TI_DISSEMINATION = [
  {id:'TID01',product:'INTREP-2026-0913-001',type:'Intelligence Report',classification:'TS/SCI',date:'2026-09-13',recipients:['NSC','CISA','FBI','DOD','Five Eyes'],status:'disseminated',acknowledgements:4,actionsTaken:3},
  {id:'TID02',product:'SPOT-2026-0913-001',type:'SPOT Report',classification:'SECRET',date:'2026-09-13',recipients:['SOC','IR Team','CISO'],status:'disseminated',acknowledgements:3,actionsTaken:2},
  {id:'TID03',product:'INTSUM-2026-0912',type:'Intelligence Summary',classification:'SECRET',date:'2026-09-12',recipients:['C-Suite','SOC','IR Team','Sector ISACs'],status:'disseminated',acknowledgements:8,actionsTaken:5},
  {id:'TID04',product:'SITREP-2026-0912',type:'Situation Report',classification:'SECRET',date:'2026-09-12',recipients:['NSC','CISA','Sector ISACs','Five Eyes'],status:'disseminated',acknowledgements:12,actionsTaken:7},
  {id:'TID05',product:'IOC-FEED-2026-0913',type:'IOC Feed',classification:'CONFIDENTIAL',date:'2026-09-13',recipients:['SOC','EDR','Firewall','IDS'],status:'automated',acknowledgements:0,actionsTaken:0},
  {id:'TID06',product:'FLASH-2026-0912',type:'Flash Alert',classification:'SECRET',date:'2026-09-12',recipients:['All SOCs','IR Team','CISO','ISAC Members'],status:'disseminated',acknowledgements:15,actionsTaken:10},
  {id:'TID07',product:'APT-PROFILE-2026-Q3',type:'APT Profile Update',classification:'TS/SCI',date:'2026-09-10',recipients:['Intelligence Community','Five Eyes','NATO CCDCOE'],status:'disseminated',acknowledgements:6,actionsTaken:3},
  {id:'TID08',product:'VULNBRIEF-2026-0911',type:'Vulnerability Brief',classification:'CONFIDENTIAL',date:'2026-09-11',recipients:['Vulnerability Management','Patch Team','Sector ISACs'],status:'disseminated',acknowledgements:5,actionsTaken:4}
];

function renderDisseminationTracking() {
  var html = '<div class="pm-section-title">Intelligence Product Dissemination</div>' +
    '<div class="pm-table-wrap pm-mb-16"><table class="pm-table pm-compact">' +
    '<tr><th>Product ID</th><th>Type</th><th>Classification</th><th>Date</th><th>Recipients</th><th>Status</th><th>Acknowledged</th><th>Actions Taken</th></tr>';
  for (var i = 0; i < TI_DISSEMINATION.length; i++) {
    var ti = TI_DISSEMINATION[i];
    html += '<tr>' +
      '<td class="pm-text-xs pm-text-bold pm-text-green">' + esc(ti.product) + '</td>' +
      '<td class="pm-text-xs">' + esc(ti.type) + '</td>' +
      '<td><span class="pm-badge ' + getClassBadge(ti.classification) + '">' + esc(ti.classification) + '</span></td>' +
      '<td class="pm-text-xs">' + esc(ti.date) + '</td>' +
      '<td class="pm-text-xs">' + esc(String(ti.recipients.length)) + ' parties</td>' +
      '<td><span class="pm-badge ' + (ti.status === 'disseminated' ? 'pm-badge-info' : 'pm-badge-low') + '">' + esc(ti.status) + '</span></td>' +
      '<td class="pm-text-xs">' + esc(String(ti.acknowledgements)) + '</td>' +
      '<td class="pm-text-xs pm-text-green">' + esc(String(ti.actionsTaken)) + '</td>' +
    '</tr>';
  }
  html += '</table></div>';
  return html;
}

// ============================================================================
// END OF PROMETHEUS WEB INTERFACE
// ============================================================================


// ============================================================================
// ADDITIONAL THREAT HUNTING HYPOTHESES
// ============================================================================
var HUNT_HYPOTHESES = [
  {id:'HH01',hypothesis:'Sandworm has pre-positioned access in at least one power grid SCADA system',confidence:65,evidence:['SIGINT intercept','Scanning activity','Historical pattern','Geopolitical context'],nextSteps:['Review SCADA logs for anomalous Modbus commands','Check for unauthorized firmware changes','Monitor for C2 beacon patterns on OT network'],status:'investigating',priority:'critical',analyst:'TI-003'},
  {id:'HH02',hypothesis:'Volt Typhoon maintains dormant implants in telecom infrastructure via compromised SOHO routers',confidence:85,evidence:['Confirmed router compromise','LOTL technique usage','Prior campaign intelligence','Router firmware analysis'],nextSteps:['Baseline all SOHO router firmware','Deploy network traffic anomaly detection','Coordinate with ISPs for router audit'],status:'confirmed',priority:'critical',analyst:'TI-001'},
  {id:'HH03',hypothesis:'APT29 has compromised at least one OAuth application in government cloud environments',confidence:72,evidence:['Prior campaign TTPs','Cloud audit log anomalies','Token usage patterns','HUMINT reporting'],nextSteps:['Audit all third-party OAuth applications','Review token refresh patterns','Check for unauthorized Azure AD modifications'],status:'investigating',priority:'high',analyst:'TI-002'},
  {id:'HH04',hypothesis:'Lazarus Group is conducting reconnaissance against cryptocurrency exchange smart contracts',confidence:78,evidence:['On-chain analysis','Dark web intelligence','Prior theft patterns','DeFi protocol probing'],nextSteps:['Monitor for flash loan probing','Review smart contract audit results','Track mixer pre-positioning activity'],status:'active',priority:'high',analyst:'TI-004'},
  {id:'HH05',hypothesis:'Iranian actors are testing destructive capabilities against water treatment SCADA systems',confidence:60,evidence:['HUMINT reporting','Historical Unitronics targeting','Test environment indicators','Regional tensions'],nextSteps:['Verify all PLC firmware integrity','Review chemical dosing system logs','Deploy additional OT monitoring sensors'],status:'investigating',priority:'critical',analyst:'TI-005'},
  {id:'HH06',hypothesis:'Supply chain compromise exists in widely deployed network management software',confidence:35,evidence:['Anomalous update patterns','Build pipeline irregularities','Third-party vendor risk assessment'],nextSteps:['Hash verification of all recent updates','Source code review of suspect packages','Deploy SBOM monitoring'],status:'monitoring',priority:'medium',analyst:'TI-006'},
  {id:'HH07',hypothesis:'Insider threat exists within government classified network operations',confidence:30,evidence:['Behavioral analytics alert','After-hours access pattern','USB device usage anomaly'],nextSteps:['Enhanced monitoring without alerting subject','Review data access logs','Coordinate with counterintelligence'],status:'investigating',priority:'high',analyst:'CI-001'},
  {id:'HH08',hypothesis:'BGP hijacking infrastructure is being prepared for use during geopolitical crisis',confidence:45,evidence:['Unusual BGP test announcements','Infrastructure pre-positioning','SIGINT indicators'],nextSteps:['Deploy BGP monitoring on all critical prefixes','Coordinate with upstream providers','Prepare RPKI defenses'],status:'monitoring',priority:'medium',analyst:'TI-007'}
];

function renderHuntHypotheses() {
  var html = '<div class="pm-section-title">Active Threat Hunting Hypotheses</div>';
  for (var i = 0; i < HUNT_HYPOTHESES.length; i++) {
    var hyp = HUNT_HYPOTHESES[i];
    var confColor = hyp.confidence >= 70 ? '#ff0040' : (hyp.confidence >= 50 ? '#ffaa00' : '#00aaff');
    var priBadge = hyp.priority === 'critical' ? 'pm-badge-critical' : (hyp.priority === 'high' ? 'pm-badge-high' : 'pm-badge-medium');
    html += '<div class="pm-card pm-mb-12">' +
      '<div class="pm-flex-between pm-mb-8">' +
        '<span class="pm-badge ' + priBadge + '">' + esc(hyp.priority) + '</span>' +
        '<span class="pm-text-xs pm-text-muted">Analyst: ' + esc(hyp.analyst) + ' | Status: ' + esc(hyp.status) + '</span>' +
      '</div>' +
      '<div class="pm-text-sm pm-mb-8">' + esc(hyp.hypothesis) + '</div>' +
      '<div class="pm-flex-between pm-mb-8">' +
        '<span class="pm-label">Confidence</span>' +
        '<span style="color:' + confColor + ';font-weight:bold;">' + esc(String(hyp.confidence)) + '%</span>' +
      '</div>' +
      '<div class="pm-progress pm-mb-12"><div class="pm-progress-bar" style="width:' + hyp.confidence + '%;background:' + confColor + ';"></div></div>' +
      '<div class="pm-grid-2" style="gap:8px;">' +
        '<div><div class="pm-label pm-mb-8">Evidence</div>';
    for (var e = 0; e < hyp.evidence.length; e++) {
      html += '<div class="pm-text-xs pm-text-muted">&#8226; ' + esc(hyp.evidence[e]) + '</div>';
    }
    html += '</div><div><div class="pm-label pm-mb-8">Next Steps</div>';
    for (var n = 0; n < hyp.nextSteps.length; n++) {
      html += '<div class="pm-text-xs pm-text-green">&#8226; ' + esc(hyp.nextSteps[n]) + '</div>';
    }
    html += '</div></div></div>';
  }
  return html;
}

// ============================================================================
// END OF PROMETHEUS WEB INTERFACE — ALL MODULES
// ============================================================================



}
