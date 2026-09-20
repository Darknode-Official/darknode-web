// Darknode Threat Intelligence Database
// 35 APT groups, 50 malware families, 40 ransomware families

export const THREAT_INTEL = {
  "aptGroups": [
    {
      "name": "APT28",
      "aliases": [
        "Fancy Bear",
        "Sofacy",
        "Sednit",
        "STRONTIUM",
        "Forest Blizzard"
      ],
      "origin": "Russia",
      "targets": [
        "government",
        "military",
        "defense",
        "media",
        "energy"
      ],
      "active": true,
      "firstSeen": "2004",
      "description": "Russian GRU Unit 26165. Sophisticated cyber espionage targeting NATO countries, election interference, and military intelligence.",
      "associatedMalware": [
        "X-Agent",
        "Zebrocy",
        "Seduploader",
        "Komplex",
        "LoJax"
      ],
      "mitreTechniques": [
        "T1566",
        "T1059",
        "T1027",
        "T1071",
        "T1041",
        "T1078",
        "T1133"
      ],
      "notableCampaigns": [
        {
          "year": 2016,
          "name": "DNC Hack"
        },
        {
          "year": 2018,
          "name": "NotPetya Attribution"
        },
        {
          "year": 2020,
          "name": "COVID Vaccine Research Targeting"
        }
      ]
    },
    {
      "name": "APT29",
      "aliases": [
        "Cozy Bear",
        "The Dukes",
        "NOBELIUM",
        "Midnight Blizzard"
      ],
      "origin": "Russia",
      "targets": [
        "government",
        "think_tanks",
        "healthcare",
        "technology"
      ],
      "active": true,
      "firstSeen": "2008",
      "description": "Russian SVR intelligence. Long-term espionage campaigns, SolarWinds supply chain attack. Highly sophisticated with custom tooling.",
      "associatedMalware": [
        "SUNBURST",
        "TEARDROP",
        "GoldMax",
        "MagicWeb",
        "WellMess",
        "EnvyScout"
      ],
      "mitreTechniques": [
        "T1195",
        "T1059",
        "T1027",
        "T1071",
        "T1550",
        "T1078"
      ],
      "notableCampaigns": [
        {
          "year": 2020,
          "name": "SolarWinds SUNBURST"
        },
        {
          "year": 2021,
          "name": "Microsoft Exchange Exploitation"
        },
        {
          "year": 2023,
          "name": "Microsoft Teams Phishing"
        }
      ]
    },
    {
      "name": "APT41",
      "aliases": [
        "Double Dragon",
        "Wicked Panda",
        "BARIUM",
        "Winnti Group"
      ],
      "origin": "China",
      "targets": [
        "technology",
        "healthcare",
        "gaming",
        "telecommunications",
        "education"
      ],
      "active": true,
      "firstSeen": "2012",
      "description": "Chinese state-sponsored group conducting both espionage and financially motivated operations. Unique dual-mission mandate.",
      "associatedMalware": [
        "ShadowPad",
        "Winnti",
        "POISONPLUG",
        "Crosswalk",
        "DUSTPAN"
      ],
      "mitreTechniques": [
        "T1190",
        "T1059",
        "T1055",
        "T1071",
        "T1005",
        "T1567"
      ],
      "notableCampaigns": [
        {
          "year": 2019,
          "name": "Global Supply Chain Attacks"
        },
        {
          "year": 2020,
          "name": "COVID-19 Research Theft"
        },
        {
          "year": 2022,
          "name": "US State Government Compromise"
        }
      ]
    },
    {
      "name": "Lazarus Group",
      "aliases": [
        "HIDDEN COBRA",
        "Zinc",
        "Diamond Sleet",
        "Labyrinth Chollima"
      ],
      "origin": "North Korea",
      "targets": [
        "financial",
        "cryptocurrency",
        "defense",
        "entertainment",
        "energy"
      ],
      "active": true,
      "firstSeen": "2009",
      "description": "North Korean RGB Bureau 121. Financially motivated attacks funding DPRK weapons programs plus destructive attacks against adversaries.",
      "associatedMalware": [
        "WannaCry",
        "BLINDINGCAN",
        "AppleJeus",
        "DRATzarus",
        "ELECTRICFISH"
      ],
      "mitreTechniques": [
        "T1566",
        "T1059",
        "T1027",
        "T1071",
        "T1486",
        "T1565"
      ],
      "notableCampaigns": [
        {
          "year": 2014,
          "name": "Sony Pictures Hack"
        },
        {
          "year": 2016,
          "name": "Bangladesh Bank SWIFT Heist"
        },
        {
          "year": 2017,
          "name": "WannaCry Ransomware"
        },
        {
          "year": 2022,
          "name": "Ronin Bridge $620M Theft"
        }
      ]
    },
    {
      "name": "Turla",
      "aliases": [
        "Snake",
        "Venomous Bear",
        "KRYPTON",
        "Secret Blizzard",
        "Waterbug"
      ],
      "origin": "Russia",
      "targets": [
        "government",
        "military",
        "diplomatic",
        "research"
      ],
      "active": true,
      "firstSeen": "1996",
      "description": "Russian FSB-linked. One of the oldest and most sophisticated APT groups. Known for satellite-based C2 and hijacking other APTs' infrastructure.",
      "associatedMalware": [
        "Snake",
        "Carbon",
        "Kazuar",
        "Gazer",
        "ComRAT",
        "TinyTurla"
      ],
      "mitreTechniques": [
        "T1071",
        "T1059",
        "T1027",
        "T1055",
        "T1090",
        "T1048"
      ],
      "notableCampaigns": [
        {
          "year": 2008,
          "name": "Agent.btz Pentagon Breach"
        },
        {
          "year": 2017,
          "name": "Satellite C2 Infrastructure"
        },
        {
          "year": 2023,
          "name": "Hijacking APT Infrastructure"
        }
      ]
    },
    {
      "name": "Sandworm",
      "aliases": [
        "Voodoo Bear",
        "IRIDIUM",
        "Seashell Blizzard",
        "TeleBots"
      ],
      "origin": "Russia",
      "targets": [
        "energy",
        "government",
        "media",
        "financial",
        "critical_infrastructure"
      ],
      "active": true,
      "firstSeen": "2009",
      "description": "Russian GRU Unit 74455. Destructive attacks against Ukrainian infrastructure, NotPetya, Olympic Destroyer.",
      "associatedMalware": [
        "NotPetya",
        "Industroyer",
        "Olympic Destroyer",
        "CaddyWiper",
        "AcidRain",
        "BlackEnergy"
      ],
      "mitreTechniques": [
        "T1190",
        "T1059",
        "T1486",
        "T1485",
        "T1498",
        "T1565"
      ],
      "notableCampaigns": [
        {
          "year": 2015,
          "name": "Ukraine Power Grid Attack"
        },
        {
          "year": 2017,
          "name": "NotPetya Global Attack"
        },
        {
          "year": 2018,
          "name": "Olympic Destroyer"
        },
        {
          "year": 2022,
          "name": "Ukraine Wiper Campaign"
        }
      ]
    },
    {
      "name": "Equation Group",
      "aliases": [
        "EQGRP",
        "Tilded Team"
      ],
      "origin": "United States",
      "targets": [
        "government",
        "military",
        "telecommunications",
        "energy",
        "research"
      ],
      "active": true,
      "firstSeen": "2001",
      "description": "NSA TAO-linked. Most sophisticated threat actor known. Custom firmware implants, air-gap bridging capabilities.",
      "associatedMalware": [
        "DoubleFeature",
        "EquationDrug",
        "GrayFish",
        "UNITEDDRAKE",
        "EternalBlue"
      ],
      "mitreTechniques": [
        "T1542",
        "T1059",
        "T1027",
        "T1071",
        "T1048",
        "T1083"
      ],
      "notableCampaigns": [
        {
          "year": 2010,
          "name": "Stuxnet (with Unit 8200)"
        },
        {
          "year": 2017,
          "name": "Shadow Brokers Leak"
        }
      ]
    },
    {
      "name": "Charming Kitten",
      "aliases": [
        "APT35",
        "Phosphorus",
        "Mint Sandstorm",
        "TA453",
        "Newscaster"
      ],
      "origin": "Iran",
      "targets": [
        "government",
        "defense",
        "journalism",
        "academia",
        "human_rights"
      ],
      "active": true,
      "firstSeen": "2011",
      "description": "Iranian IRGC-linked. Social engineering heavy, targets journalists and activists. Known for elaborate fake personas.",
      "associatedMalware": [
        "POWERSTAR",
        "BellaCiao",
        "CharmPower",
        "HYPERSCRAPE",
        "DownPaper"
      ],
      "mitreTechniques": [
        "T1566",
        "T1059",
        "T1027",
        "T1071",
        "T1078",
        "T1556"
      ],
      "notableCampaigns": [
        {
          "year": 2019,
          "name": "US Presidential Campaign Targeting"
        },
        {
          "year": 2022,
          "name": "NATO Think Tank Espionage"
        }
      ]
    },
    {
      "name": "OceanLotus",
      "aliases": [
        "APT32",
        "SeaLotus",
        "Canvas Cyclone"
      ],
      "origin": "Vietnam",
      "targets": [
        "government",
        "media",
        "human_rights",
        "manufacturing",
        "hospitality"
      ],
      "active": true,
      "firstSeen": "2012",
      "description": "Vietnamese Ministry of Public Security-linked. Targets Southeast Asian governments, dissidents, and foreign corporations operating in Vietnam.",
      "associatedMalware": [
        "METALJACK",
        "Ratsnif",
        "Kerrdown",
        "PhantomNet",
        "Denis"
      ],
      "mitreTechniques": [
        "T1566",
        "T1059",
        "T1055",
        "T1071",
        "T1005",
        "T1567"
      ],
      "notableCampaigns": [
        {
          "year": 2017,
          "name": "ASEAN Summit Targeting"
        },
        {
          "year": 2020,
          "name": "COVID-19 Espionage"
        }
      ]
    },
    {
      "name": "Kimsuky",
      "aliases": [
        "Velvet Chollima",
        "Thallium",
        "Emerald Sleet",
        "TA406",
        "Black Banshee"
      ],
      "origin": "North Korea",
      "targets": [
        "government",
        "nuclear",
        "think_tanks",
        "academia",
        "defense"
      ],
      "active": true,
      "firstSeen": "2012",
      "description": "North Korean RGB. Focuses on intelligence collection targeting South Korean and US policy experts, nuclear analysts, and think tanks.",
      "associatedMalware": [
        "BabyShark",
        "AppleSeed",
        "GoldDragon",
        "RandomQuery",
        "FlowerPower"
      ],
      "mitreTechniques": [
        "T1566",
        "T1059",
        "T1027",
        "T1071",
        "T1005",
        "T1114"
      ],
      "notableCampaigns": [
        {
          "year": 2014,
          "name": "Korea Hydro Nuclear Power Hack"
        },
        {
          "year": 2023,
          "name": "Think Tank Credential Harvesting"
        }
      ]
    },
    {
      "name": "MuddyWater",
      "aliases": [
        "Mercury",
        "Mango Sandstorm",
        "Static Kitten",
        "TEMP.Zagros"
      ],
      "origin": "Iran",
      "targets": [
        "government",
        "telecommunications",
        "oil_gas",
        "defense"
      ],
      "active": true,
      "firstSeen": "2017",
      "description": "Iranian MOIS-linked. Targets Middle Eastern and Central Asian governments. Uses legitimate remote admin tools for C2.",
      "associatedMalware": [
        "POWERSTATS",
        "MuddyC2Go",
        "PhonyC2",
        "SHARPSTATS",
        "Aclip"
      ],
      "mitreTechniques": [
        "T1566",
        "T1059",
        "T1219",
        "T1071",
        "T1027",
        "T1105"
      ],
      "notableCampaigns": [
        {
          "year": 2022,
          "name": "Turkey Government Espionage"
        },
        {
          "year": 2023,
          "name": "Israeli Critical Infrastructure Targeting"
        }
      ]
    },
    {
      "name": "Volt Typhoon",
      "aliases": [
        "Bronze Silhouette",
        "Vanguard Panda",
        "DEV-0391"
      ],
      "origin": "China",
      "targets": [
        "critical_infrastructure",
        "telecommunications",
        "energy",
        "transportation",
        "water"
      ],
      "active": true,
      "firstSeen": "2021",
      "description": "Chinese state-sponsored. Pre-positions for destructive attacks on US critical infrastructure. Living-off-the-land techniques for stealth.",
      "associatedMalware": [
        "Custom web shells",
        "KV Botnet"
      ],
      "mitreTechniques": [
        "T1190",
        "T1059",
        "T1078",
        "T1021",
        "T1018",
        "T1033"
      ],
      "notableCampaigns": [
        {
          "year": 2023,
          "name": "US Critical Infrastructure Pre-positioning"
        },
        {
          "year": 2024,
          "name": "US Telecom Compromise"
        }
      ]
    },
    {
      "name": "Salt Typhoon",
      "aliases": [
        "GhostEmperor",
        "FamousSparrow"
      ],
      "origin": "China",
      "targets": [
        "telecommunications",
        "ISP",
        "government"
      ],
      "active": true,
      "firstSeen": "2019",
      "description": "Chinese state-sponsored group targeting global telecommunications providers. Intercepting communications and metadata for intelligence collection.",
      "associatedMalware": [
        "Demodex rootkit",
        "SparrowDoor",
        "custom backdoors"
      ],
      "mitreTechniques": [
        "T1190",
        "T1059",
        "T1078",
        "T1005",
        "T1056",
        "T1071"
      ],
      "notableCampaigns": [
        {
          "year": 2024,
          "name": "US Telecom Wiretap Systems Breach"
        }
      ]
    },
    {
      "name": "FIN7",
      "aliases": [
        "Carbanak",
        "Navigator Group",
        "Carbon Spider"
      ],
      "origin": "Russia",
      "targets": [
        "retail",
        "hospitality",
        "financial",
        "food_beverage"
      ],
      "active": true,
      "firstSeen": "2013",
      "description": "Financially motivated cybercrime group. Billions in losses from POS malware, business email compromise, and ransomware.",
      "associatedMalware": [
        "Carbanak",
        "Pillowmint",
        "Lizar",
        "BIRDWATCH",
        "Domino"
      ],
      "mitreTechniques": [
        "T1566",
        "T1059",
        "T1055",
        "T1071",
        "T1005",
        "T1567"
      ],
      "notableCampaigns": [
        {
          "year": 2018,
          "name": "Saks Fifth Avenue Breach"
        },
        {
          "year": 2021,
          "name": "Ransomware Operations"
        }
      ]
    },
    {
      "name": "FIN11",
      "aliases": [
        "TA505",
        "CLOP Gang",
        "DEV-0950"
      ],
      "origin": "Russia",
      "targets": [
        "financial",
        "retail",
        "healthcare",
        "technology"
      ],
      "active": true,
      "firstSeen": "2016",
      "description": "Financially motivated. Mass exploitation of zero-days (Accellion, GoAnywhere, MOVEit) for data extortion. Operates CLOP ransomware.",
      "associatedMalware": [
        "CLOP",
        "FlawedAmmyy",
        "FlawedGrace",
        "SDBbot",
        "Get2"
      ],
      "mitreTechniques": [
        "T1190",
        "T1059",
        "T1486",
        "T1567",
        "T1005",
        "T1027"
      ],
      "notableCampaigns": [
        {
          "year": 2021,
          "name": "Accellion FTA Exploitation"
        },
        {
          "year": 2023,
          "name": "MOVEit Zero-Day Mass Exploitation"
        }
      ]
    },
    {
      "name": "APT1",
      "aliases": [
        "Comment Crew",
        "PLA Unit 61398"
      ],
      "origin": "China",
      "targets": [
        "technology",
        "aerospace",
        "energy",
        "financial"
      ],
      "active": false,
      "firstSeen": "2006",
      "description": "PLA Unit 61398 based in Shanghai. One of the first publicly attributed Chinese APT groups by Mandiant.",
      "associatedMalware": [
        "WEBC2",
        "BISCUIT",
        "MANITSME"
      ],
      "mitreTechniques": [
        "T1566",
        "T1059",
        "T1005",
        "T1071"
      ],
      "notableCampaigns": [
        {
          "year": 2013,
          "name": "Mandiant APT1 Report"
        }
      ]
    },
    {
      "name": "APT3",
      "aliases": [
        "Gothic Panda",
        "Buckeye",
        "UPS Team"
      ],
      "origin": "China",
      "targets": [
        "technology",
        "aerospace",
        "defense",
        "telecommunications"
      ],
      "active": false,
      "firstSeen": "2007",
      "description": "Chinese MSS-contracted group. Known for developing exploits and targeting defense contractors.",
      "associatedMalware": [
        "Pirpi",
        "DoubleT",
        "OSInfo"
      ],
      "mitreTechniques": [
        "T1189",
        "T1059",
        "T1055",
        "T1071"
      ],
      "notableCampaigns": [
        {
          "year": 2015,
          "name": "Operation Clandestine Wolf"
        }
      ]
    },
    {
      "name": "APT10",
      "aliases": [
        "Stone Panda",
        "MenuPass",
        "POTASSIUM",
        "Red Apollo"
      ],
      "origin": "China",
      "targets": [
        "MSP",
        "technology",
        "government",
        "healthcare",
        "defense"
      ],
      "active": true,
      "firstSeen": "2006",
      "description": "Chinese MSS-linked. Notorious for Operation Cloud Hopper targeting managed service providers for supply chain access.",
      "associatedMalware": [
        "PlugX",
        "QuasarRAT",
        "RedLeaves",
        "ANEL",
        "ChChes"
      ],
      "mitreTechniques": [
        "T1199",
        "T1059",
        "T1078",
        "T1071",
        "T1005"
      ],
      "notableCampaigns": [
        {
          "year": 2017,
          "name": "Operation Cloud Hopper"
        }
      ]
    },
    {
      "name": "APT15",
      "aliases": [
        "Vixen Panda",
        "Ke3chang",
        "Nickel",
        "Playful Dragon"
      ],
      "origin": "China",
      "targets": [
        "government",
        "diplomatic",
        "energy",
        "military"
      ],
      "active": true,
      "firstSeen": "2010",
      "description": "Chinese group targeting European foreign ministries and government agencies for political intelligence.",
      "associatedMalware": [
        "Ketrican",
        "Okrum",
        "BS2005",
        "RoyalDNS"
      ],
      "mitreTechniques": [
        "T1566",
        "T1059",
        "T1027",
        "T1071"
      ],
      "notableCampaigns": [
        {
          "year": 2017,
          "name": "European Government Espionage"
        }
      ]
    },
    {
      "name": "APT17",
      "aliases": [
        "DeputyDog",
        "Aurora Panda",
        "Tailgater Team"
      ],
      "origin": "China",
      "targets": [
        "government",
        "technology",
        "defense",
        "law_firms"
      ],
      "active": true,
      "firstSeen": "2010",
      "description": "Chinese group using watering hole attacks and zero-day exploits targeting US government and defense.",
      "associatedMalware": [
        "BLACKCOFFEE",
        "DeputyDog",
        "Hikit"
      ],
      "mitreTechniques": [
        "T1189",
        "T1059",
        "T1027",
        "T1071"
      ],
      "notableCampaigns": [
        {
          "year": 2013,
          "name": "Operation DeputyDog"
        }
      ]
    },
    {
      "name": "APT19",
      "aliases": [
        "Deep Panda",
        "Codoso",
        "C0d0so0"
      ],
      "origin": "China",
      "targets": [
        "legal",
        "technology",
        "financial",
        "government"
      ],
      "active": true,
      "firstSeen": "2010",
      "description": "Chinese group targeting law firms and technology companies. Notable for Anthem healthcare breach connection.",
      "associatedMalware": [
        "Derusbi",
        "Sakula",
        "Bergard"
      ],
      "mitreTechniques": [
        "T1189",
        "T1059",
        "T1055",
        "T1071"
      ],
      "notableCampaigns": [
        {
          "year": 2015,
          "name": "Anthem Healthcare Breach Connection"
        }
      ]
    },
    {
      "name": "APT27",
      "aliases": [
        "Emissary Panda",
        "LuckyMouse",
        "Iron Tiger",
        "Bronze Union"
      ],
      "origin": "China",
      "targets": [
        "government",
        "defense",
        "technology",
        "aerospace",
        "energy"
      ],
      "active": true,
      "firstSeen": "2010",
      "description": "Chinese group targeting government and defense organizations worldwide for espionage.",
      "associatedMalware": [
        "SysUpdate",
        "HyperBro",
        "PlugX",
        "China Chopper"
      ],
      "mitreTechniques": [
        "T1190",
        "T1059",
        "T1055",
        "T1071",
        "T1078"
      ],
      "notableCampaigns": [
        {
          "year": 2020,
          "name": "SharePoint Server Exploitation"
        }
      ]
    },
    {
      "name": "APT30",
      "aliases": [
        "Naikon"
      ],
      "origin": "China",
      "targets": [
        "government",
        "military",
        "diplomatic",
        "media"
      ],
      "active": true,
      "firstSeen": "2004",
      "description": "Chinese group targeting ASEAN member countries and neighboring regions for military and political intelligence.",
      "associatedMalware": [
        "BACKSPACE",
        "NETEAGLE",
        "SHIPSHAPE"
      ],
      "mitreTechniques": [
        "T1566",
        "T1059",
        "T1005",
        "T1071"
      ],
      "notableCampaigns": [
        {
          "year": 2015,
          "name": "South China Sea Espionage"
        }
      ]
    },
    {
      "name": "APT33",
      "aliases": [
        "Elfin",
        "Refined Kitten",
        "Peach Sandstorm",
        "Holmium"
      ],
      "origin": "Iran",
      "targets": [
        "aerospace",
        "defense",
        "energy",
        "petrochemical"
      ],
      "active": true,
      "firstSeen": "2013",
      "description": "Iranian group targeting aerospace and energy sectors, particularly Saudi Arabian and US organizations.",
      "associatedMalware": [
        "Shamoon",
        "TURNEDUP",
        "NANOCORE",
        "DROPSHOT"
      ],
      "mitreTechniques": [
        "T1566",
        "T1059",
        "T1027",
        "T1071",
        "T1486"
      ],
      "notableCampaigns": [
        {
          "year": 2017,
          "name": "Shamoon 2 Attack"
        }
      ]
    },
    {
      "name": "APT34",
      "aliases": [
        "OilRig",
        "Helix Kitten",
        "Hazel Sandstorm",
        "COBALT GYPSY"
      ],
      "origin": "Iran",
      "targets": [
        "financial",
        "government",
        "energy",
        "telecommunications",
        "chemical"
      ],
      "active": true,
      "firstSeen": "2014",
      "description": "Iranian MOIS-linked. Targets Middle Eastern organizations using custom backdoors and DNS tunneling for exfiltration.",
      "associatedMalware": [
        "QUADAGENT",
        "BONDUPDATER",
        "TONEDEAF",
        "SideTwist",
        "Shark"
      ],
      "mitreTechniques": [
        "T1566",
        "T1059",
        "T1071",
        "T1048",
        "T1027"
      ],
      "notableCampaigns": [
        {
          "year": 2019,
          "name": "Tools Leaked on Telegram"
        }
      ]
    },
    {
      "name": "APT37",
      "aliases": [
        "Reaper",
        "ScarCruft",
        "Ricochet Chollima",
        "InkySquid"
      ],
      "origin": "North Korea",
      "targets": [
        "government",
        "military",
        "defense",
        "media",
        "human_rights"
      ],
      "active": true,
      "firstSeen": "2012",
      "description": "North Korean group targeting South Korean government and military, Japanese organizations, and defectors/activists.",
      "associatedMalware": [
        "ROKRAT",
        "BLUELIGHT",
        "Konni",
        "Dolphin",
        "M2RAT"
      ],
      "mitreTechniques": [
        "T1566",
        "T1059",
        "T1055",
        "T1071",
        "T1005"
      ],
      "notableCampaigns": [
        {
          "year": 2022,
          "name": "Internet Explorer Zero-Day Campaign"
        }
      ]
    },
    {
      "name": "APT38",
      "aliases": [
        "Bluenoroff",
        "Stardust Chollima",
        "BeagleBoyz"
      ],
      "origin": "North Korea",
      "targets": [
        "financial",
        "cryptocurrency",
        "banks"
      ],
      "active": true,
      "firstSeen": "2014",
      "description": "North Korean financially motivated subgroup of Lazarus. Targets banks via SWIFT system and cryptocurrency exchanges.",
      "associatedMalware": [
        "DYEPACK",
        "HERMES",
        "ELECTRICFISH",
        "COPPERHEDGE"
      ],
      "mitreTechniques": [
        "T1566",
        "T1059",
        "T1055",
        "T1071",
        "T1565",
        "T1486"
      ],
      "notableCampaigns": [
        {
          "year": 2016,
          "name": "Bangladesh Bank SWIFT Heist $81M"
        },
        {
          "year": 2022,
          "name": "Cryptocurrency Exchange Heists"
        }
      ]
    },
    {
      "name": "APT39",
      "aliases": [
        "Chafer",
        "Remix Kitten",
        "COBALT HICKMAN"
      ],
      "origin": "Iran",
      "targets": [
        "telecommunications",
        "travel",
        "hospitality",
        "technology"
      ],
      "active": true,
      "firstSeen": "2014",
      "description": "Iranian MOIS-linked group focusing on personal tracking and surveillance through telecom and travel industry targeting.",
      "associatedMalware": [
        "Remexi",
        "SEAWEED",
        "CACHEMONEY"
      ],
      "mitreTechniques": [
        "T1566",
        "T1059",
        "T1071",
        "T1005",
        "T1056"
      ],
      "notableCampaigns": [
        {
          "year": 2019,
          "name": "Global Telecom Espionage"
        }
      ]
    },
    {
      "name": "APT40",
      "aliases": [
        "Leviathan",
        "TEMP.Periscope",
        "Bronze Mohawk",
        "Gadolinium"
      ],
      "origin": "China",
      "targets": [
        "maritime",
        "defense",
        "government",
        "technology",
        "research"
      ],
      "active": true,
      "firstSeen": "2013",
      "description": "Chinese MSS Hainan State Security Department. Targets maritime industries and South China Sea interests.",
      "associatedMalware": [
        "BADFLICK",
        "China Chopper",
        "MURKYTOP",
        "ScanBox"
      ],
      "mitreTechniques": [
        "T1190",
        "T1566",
        "T1059",
        "T1071",
        "T1005"
      ],
      "notableCampaigns": [
        {
          "year": 2021,
          "name": "Microsoft Exchange ProxyLogon Exploitation"
        }
      ]
    },
    {
      "name": "Andariel",
      "aliases": [
        "Silent Chollima",
        "Onyx Sleet",
        "DarkSeoul"
      ],
      "origin": "North Korea",
      "targets": [
        "defense",
        "financial",
        "government",
        "energy"
      ],
      "active": true,
      "firstSeen": "2009",
      "description": "North Korean RGB-linked subgroup of Lazarus focused on South Korean targets and defense sector espionage.",
      "associatedMalware": [
        "Maui",
        "TigerRAT",
        "YamaBot",
        "EarlyRAT"
      ],
      "mitreTechniques": [
        "T1190",
        "T1059",
        "T1486",
        "T1071",
        "T1005"
      ],
      "notableCampaigns": [
        {
          "year": 2022,
          "name": "Maui Ransomware Healthcare Attacks"
        }
      ]
    },
    {
      "name": "Mustang Panda",
      "aliases": [
        "Bronze President",
        "TA416",
        "RedDelta",
        "Earth Preta"
      ],
      "origin": "China",
      "targets": [
        "government",
        "NGO",
        "think_tanks",
        "religious"
      ],
      "active": true,
      "firstSeen": "2017",
      "description": "Chinese group targeting European and Asian government entities using USB-propagating malware and PlugX variants.",
      "associatedMalware": [
        "PlugX",
        "Korplug",
        "TONEINS",
        "TONESHELL"
      ],
      "mitreTechniques": [
        "T1566",
        "T1091",
        "T1059",
        "T1071",
        "T1005"
      ],
      "notableCampaigns": [
        {
          "year": 2022,
          "name": "European Government USB Attacks"
        }
      ]
    },
    {
      "name": "Gamaredon",
      "aliases": [
        "Primitive Bear",
        "Actinium",
        "Shuckworm",
        "Armageddon"
      ],
      "origin": "Russia",
      "targets": [
        "government",
        "military",
        "NGO",
        "judiciary",
        "law_enforcement"
      ],
      "active": true,
      "firstSeen": "2013",
      "description": "Russian FSB-linked. Primarily targets Ukrainian government and military with high-volume, lower-sophistication attacks.",
      "associatedMalware": [
        "Pteranodon",
        "QuietSieve",
        "EvilGnome",
        "GammaLoad"
      ],
      "mitreTechniques": [
        "T1566",
        "T1059",
        "T1027",
        "T1071",
        "T1005"
      ],
      "notableCampaigns": [
        {
          "year": 2022,
          "name": "Ukraine Invasion Espionage Campaign"
        }
      ]
    },
    {
      "name": "Scattered Spider",
      "aliases": [
        "UNC3944",
        "Muddled Libra",
        "Star Fraud",
        "0ktapus"
      ],
      "origin": "United States/United Kingdom",
      "targets": [
        "technology",
        "telecommunications",
        "financial",
        "gaming",
        "hospitality"
      ],
      "active": true,
      "firstSeen": "2022",
      "description": "Young Western threat actors using social engineering, SIM swapping, and MFA bombing. Targeted MGM, Caesars, Coinbase.",
      "associatedMalware": [
        "ALPHV/BlackCat (affiliate)",
        "social engineering tools"
      ],
      "mitreTechniques": [
        "T1566",
        "T1556",
        "T1078",
        "T1021",
        "T1486"
      ],
      "notableCampaigns": [
        {
          "year": 2023,
          "name": "MGM Resorts $100M Attack"
        },
        {
          "year": 2023,
          "name": "Caesars Entertainment Ransom"
        }
      ]
    },
    {
      "name": "LAPSUS$",
      "aliases": [
        "DEV-0537"
      ],
      "origin": "United Kingdom/Brazil",
      "targets": [
        "technology",
        "gaming",
        "telecommunications"
      ],
      "active": false,
      "firstSeen": "2021",
      "description": "Teenage hackers using social engineering and insider recruitment. Breached Microsoft, Nvidia, Samsung, Okta, Uber.",
      "associatedMalware": [
        "No custom malware - social engineering"
      ],
      "mitreTechniques": [
        "T1566",
        "T1078",
        "T1213",
        "T1530",
        "T1567"
      ],
      "notableCampaigns": [
        {
          "year": 2022,
          "name": "Microsoft Source Code Theft"
        },
        {
          "year": 2022,
          "name": "Nvidia 1TB Data Theft"
        },
        {
          "year": 2022,
          "name": "Okta Support Breach"
        }
      ]
    },
    {
      "name": "DarkSide",
      "aliases": [
        "Carbon Spider (affiliate)"
      ],
      "origin": "Russia",
      "targets": [
        "energy",
        "manufacturing",
        "technology",
        "financial"
      ],
      "active": false,
      "firstSeen": "2020",
      "description": "Ransomware-as-a-Service operation. Responsible for Colonial Pipeline attack causing US East Coast fuel shortage.",
      "associatedMalware": [
        "DarkSide",
        "BlackMatter"
      ],
      "mitreTechniques": [
        "T1486",
        "T1490",
        "T1059",
        "T1078",
        "T1567"
      ],
      "notableCampaigns": [
        {
          "year": 2021,
          "name": "Colonial Pipeline Shutdown"
        }
      ]
    }
  ],
  "malwareFamilies": [
    {
      "name": "Emotet",
      "type": "loader",
      "firstSeen": "2014",
      "description": "Modular banking trojan turned malware-as-a-service loader. Most prolific malware distributor globally.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "TrickBot",
      "type": "trojan",
      "firstSeen": "2016",
      "description": "Modular banking trojan evolved into versatile cybercrime platform. Pre-cursor for ransomware deployment.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "QakBot",
      "type": "trojan",
      "firstSeen": "2008",
      "description": "Banking trojan with worm capabilities. Major initial access broker for ransomware gangs.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "IcedID",
      "type": "trojan",
      "firstSeen": "2017",
      "description": "Banking trojan used as initial access for ransomware. Modular with web injection capabilities.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Dridex",
      "type": "banker",
      "firstSeen": "2014",
      "description": "Banking trojan targeting financial institutions worldwide via phishing campaigns.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "BazarLoader",
      "type": "loader",
      "firstSeen": "2020",
      "description": "Loader malware linked to TrickBot operators. Used for initial access before ransomware.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Cobalt Strike",
      "type": "RAT",
      "firstSeen": "2012",
      "description": "Commercial adversary simulation tool widely abused by threat actors for C2 operations.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Meterpreter",
      "type": "RAT",
      "firstSeen": "2004",
      "description": "Metasploit Framework payload providing remote access with in-memory execution.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Sliver",
      "type": "RAT",
      "firstSeen": "2019",
      "description": "Open-source C2 framework. Growing replacement for Cobalt Strike among threat actors.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "BruteRatel",
      "type": "RAT",
      "firstSeen": "2022",
      "description": "Commercial red team C2 tool with advanced evasion. Cracked version circulating in criminal underground.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "ShadowPad",
      "type": "backdoor",
      "firstSeen": "2017",
      "description": "Modular backdoor used by multiple Chinese APT groups. Successor to PlugX in many operations.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "PlugX",
      "type": "RAT",
      "firstSeen": "2008",
      "description": "Modular RAT used extensively by Chinese APT groups. DLL side-loading for persistence.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "WannaCry",
      "type": "ransomware",
      "firstSeen": "2017",
      "description": "Self-propagating ransomware using EternalBlue. Caused $4B+ in global damages.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "NotPetya",
      "type": "wiper",
      "firstSeen": "2017",
      "description": "Destructive wiper disguised as ransomware. Caused $10B+ in global damages. Attributed to Sandworm.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Stuxnet",
      "type": "worm",
      "firstSeen": "2010",
      "description": "First known cyberweapon targeting industrial control systems. Destroyed Iranian centrifuges.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "BlackEnergy",
      "type": "trojan",
      "firstSeen": "2007",
      "description": "Modular trojan used in Ukrainian power grid attacks. Evolved from DDoS tool to APT weapon.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Industroyer",
      "type": "malware",
      "firstSeen": "2016",
      "description": "ICS-specific malware targeting power grid SCADA protocols. Used in Ukraine blackout.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Shamoon",
      "type": "wiper",
      "firstSeen": "2012",
      "description": "Destructive wiper malware targeting Saudi Arabian oil companies. Overwrites MBR.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "SUNBURST",
      "type": "backdoor",
      "firstSeen": "2020",
      "description": "SolarWinds supply chain backdoor. Compromised 18,000+ organizations including US government.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Pegasus",
      "type": "spyware",
      "firstSeen": "2016",
      "description": "NSO Group commercial spyware targeting iOS and Android. Used against journalists and activists.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "FinFisher",
      "type": "spyware",
      "firstSeen": "2011",
      "description": "Commercial surveillance malware sold to governments. Full device takeover capabilities.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Predator",
      "type": "spyware",
      "firstSeen": "2022",
      "description": "Cytrox/Intellexa commercial spyware. Zero-click exploitation of mobile devices.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Snake",
      "type": "rootkit",
      "firstSeen": "1996",
      "description": "Russian Turla group's flagship malware. Peer-to-peer C2 network spanning 50+ countries.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Regin",
      "type": "rootkit",
      "firstSeen": "2003",
      "description": "Highly sophisticated espionage platform attributed to Five Eyes. Multi-stage with encrypted VFS.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Flame",
      "type": "spyware",
      "firstSeen": "2012",
      "description": "Large modular espionage malware targeting Middle East. 20MB+ binary with Bluetooth collection.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Mirai",
      "type": "botnet",
      "firstSeen": "2016",
      "description": "IoT botnet exploiting default credentials. DDoS attacks reaching 1+ Tbps.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Hajime",
      "type": "botnet",
      "firstSeen": "2016",
      "description": "IoT worm rivaling Mirai. Claims to secure devices but builds massive botnet.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "BotenaGo",
      "type": "botnet",
      "firstSeen": "2021",
      "description": "Go-based malware targeting IoT devices with 30+ exploit modules.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "SmokeLoader",
      "type": "loader",
      "firstSeen": "2011",
      "description": "Modular loader selling access to compromised machines. Active underground marketplace.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Amadey",
      "type": "loader",
      "firstSeen": "2018",
      "description": "Loader-as-a-service used for deploying stealers and RATs.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "GuLoader",
      "type": "loader",
      "firstSeen": "2019",
      "description": "Shellcode-based downloader with strong anti-analysis. Cloud-hosted payloads.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "BumbleBee",
      "type": "loader",
      "firstSeen": "2022",
      "description": "Loader attributed to Conti ransomware group. Replaced BazarLoader in operations.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Pikabot",
      "type": "loader",
      "firstSeen": "2023",
      "description": "Modular loader with anti-analysis. Similar capabilities to QakBot post-takedown.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "DarkGate",
      "type": "loader",
      "firstSeen": "2023",
      "description": "MaaS loader with RAT capabilities, crypto mining, and keylogging. Sold on criminal forums.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "SystemBC",
      "type": "backdoor",
      "firstSeen": "2019",
      "description": "SOCKS5 proxy backdoor used to hide ransomware C2 traffic.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "CoinMiner",
      "type": "miner",
      "firstSeen": "2011",
      "description": "Generic cryptocurrency mining malware leveraging victim compute resources.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "XMRig",
      "type": "miner",
      "firstSeen": "2017",
      "description": "Open-source Monero miner widely deployed by threat actors on compromised systems.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "RedLine",
      "type": "stealer",
      "firstSeen": "2020",
      "description": "Information stealer targeting browser credentials, crypto wallets, and system info.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Raccoon",
      "type": "stealer",
      "firstSeen": "2019",
      "description": "Stealer-as-a-service. Cheap, effective, widely deployed for credential theft.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Vidar",
      "type": "stealer",
      "firstSeen": "2018",
      "description": "Information stealer evolved from Arkei. Targets browsers, crypto, and 2FA apps.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Agent Tesla",
      "type": "stealer",
      "firstSeen": "2014",
      "description": "Keylogger and information stealer distributed via phishing. .NET-based.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "FormBook",
      "type": "stealer",
      "firstSeen": "2016",
      "description": "Form grabber and keylogger sold as MaaS. Rebranded as XLoader for macOS.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "LokiBot",
      "type": "stealer",
      "firstSeen": "2015",
      "description": "Information stealer targeting browser passwords, email clients, and FTP credentials.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Snake Keylogger",
      "type": "keylogger",
      "firstSeen": "2020",
      "description": ".NET keylogger with credential theft, clipboard monitoring, and screenshot capture.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "AsyncRAT",
      "type": "RAT",
      "firstSeen": "2019",
      "description": "Open-source .NET RAT with keylogging, screen capture, and file management.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Quasar RAT",
      "type": "RAT",
      "firstSeen": "2014",
      "description": "Open-source .NET RAT popular among cybercriminals. Full device control capabilities.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "Remcos",
      "type": "RAT",
      "firstSeen": "2016",
      "description": "Commercial remote administration tool widely abused as RAT. Sold legally as monitoring software.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "njRAT",
      "type": "RAT",
      "firstSeen": "2012",
      "description": "Popular RAT in Middle Eastern cybercrime. Keylogging, webcam, file management.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "DarkComet",
      "type": "RAT",
      "firstSeen": "2008",
      "description": "Legacy RAT with extensive surveillance capabilities. Development ceased after Syria controversy.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    },
    {
      "name": "XWorm",
      "type": "RAT",
      "firstSeen": "2022",
      "description": "Modular RAT sold on criminal forums. Keylogging, ransomware, DDoS, crypto mining.",
      "iocs": [
        "hash",
        "domain",
        "ip",
        "url"
      ],
      "associatedGroups": [],
      "mitreTechniques": [
        "T1059",
        "T1071"
      ]
    }
  ],
  "ransomwareTracker": [
    {
      "name": "LockBit 3.0",
      "extensions": [
        ".lockbit",
        ".lock3"
      ],
      "ransomNote": "Restore-My-Files.txt",
      "decryptorAvailable": true,
      "averageRansom": "$50,000",
      "cryptocurrency": "BTC/XMR",
      "description": "LockBit 3.0 ransomware family."
    },
    {
      "name": "BlackCat/ALPHV",
      "extensions": [
        ".alphv",
        ".sphynx"
      ],
      "ransomNote": "RECOVER-FILES.txt",
      "decryptorAvailable": false,
      "averageRansom": "$200,000",
      "cryptocurrency": "BTC/XMR",
      "description": "BlackCat/ALPHV ransomware family."
    },
    {
      "name": "Royal",
      "extensions": [
        ".royal"
      ],
      "ransomNote": "README.TXT",
      "decryptorAvailable": false,
      "averageRansom": "$250,000",
      "cryptocurrency": "BTC",
      "description": "Royal ransomware family."
    },
    {
      "name": "Play",
      "extensions": [
        ".play"
      ],
      "ransomNote": "ReadMe.txt",
      "decryptorAvailable": false,
      "averageRansom": "$500,000",
      "cryptocurrency": "BTC",
      "description": "Play ransomware family."
    },
    {
      "name": "Akira",
      "extensions": [
        ".akira"
      ],
      "ransomNote": "akira_readme.txt",
      "decryptorAvailable": false,
      "averageRansom": "$200,000",
      "cryptocurrency": "BTC",
      "description": "Akira ransomware family."
    },
    {
      "name": "CLOP",
      "extensions": [
        ".clop",
        ".CIop"
      ],
      "ransomNote": "ClopReadMe.txt",
      "decryptorAvailable": false,
      "averageRansom": "$1,000,000",
      "cryptocurrency": "BTC",
      "description": "CLOP ransomware family."
    },
    {
      "name": "Hive",
      "extensions": [
        ".hive",
        ".key.hive"
      ],
      "ransomNote": "HOW_TO_DECRYPT.txt",
      "decryptorAvailable": true,
      "averageRansom": "$100,000",
      "cryptocurrency": "BTC",
      "description": "Hive ransomware family."
    },
    {
      "name": "Conti",
      "extensions": [
        ".CONTI",
        ".DATAA"
      ],
      "ransomNote": "readme.txt",
      "decryptorAvailable": false,
      "averageRansom": "$150,000",
      "cryptocurrency": "BTC",
      "description": "Conti ransomware family."
    },
    {
      "name": "REvil/Sodinokibi",
      "extensions": [
        ".random",
        ".sodinokibi"
      ],
      "ransomNote": "random-readme.txt",
      "decryptorAvailable": true,
      "averageRansom": "$500,000",
      "cryptocurrency": "XMR",
      "description": "REvil/Sodinokibi ransomware family."
    },
    {
      "name": "Ryuk",
      "extensions": [
        ".RYK"
      ],
      "ransomNote": "RyukReadMe.html",
      "decryptorAvailable": false,
      "averageRansom": "$300,000",
      "cryptocurrency": "BTC",
      "description": "Ryuk ransomware family."
    },
    {
      "name": "WannaCry",
      "extensions": [
        ".WNCRY",
        ".WNCRYT"
      ],
      "ransomNote": "@WanaDecryptor@.exe",
      "decryptorAvailable": true,
      "averageRansom": "$300",
      "cryptocurrency": "BTC",
      "description": "WannaCry ransomware family."
    },
    {
      "name": "Maze",
      "extensions": [
        ".maze"
      ],
      "ransomNote": "DECRYPT-FILES.html",
      "decryptorAvailable": false,
      "averageRansom": "$500,000",
      "cryptocurrency": "BTC",
      "description": "Maze ransomware family."
    },
    {
      "name": "DarkSide",
      "extensions": [
        ".darkside",
        ".d4rks1de"
      ],
      "ransomNote": "README.txt",
      "decryptorAvailable": false,
      "averageRansom": "$200,000",
      "cryptocurrency": "BTC",
      "description": "DarkSide ransomware family."
    },
    {
      "name": "BlackBasta",
      "extensions": [
        ".basta"
      ],
      "ransomNote": "readme.txt",
      "decryptorAvailable": false,
      "averageRansom": "$300,000",
      "cryptocurrency": "BTC",
      "description": "BlackBasta ransomware family."
    },
    {
      "name": "Medusa",
      "extensions": [
        ".MEDUSA"
      ],
      "ransomNote": "!!!READ_ME_MEDUSA!!!.txt",
      "decryptorAvailable": false,
      "averageRansom": "$100,000",
      "cryptocurrency": "BTC",
      "description": "Medusa ransomware family."
    },
    {
      "name": "Phobos",
      "extensions": [
        ".phobos",
        ".eking",
        ".eight"
      ],
      "ransomNote": "info.txt",
      "decryptorAvailable": false,
      "averageRansom": "$50,000",
      "cryptocurrency": "BTC",
      "description": "Phobos ransomware family."
    },
    {
      "name": "Trigona",
      "extensions": [
        ".locked"
      ],
      "ransomNote": "how_to_decrypt.hta",
      "decryptorAvailable": false,
      "averageRansom": "$100,000",
      "cryptocurrency": "XMR",
      "description": "Trigona ransomware family."
    },
    {
      "name": "NoEscape",
      "extensions": [
        ".NOESCAPE"
      ],
      "ransomNote": "HOW_TO_RECOVER_FILES.txt",
      "decryptorAvailable": false,
      "averageRansom": "$200,000",
      "cryptocurrency": "BTC",
      "description": "NoEscape ransomware family."
    },
    {
      "name": "Rhysida",
      "extensions": [
        ".rhysida"
      ],
      "ransomNote": "CriticalBreachDetected.pdf",
      "decryptorAvailable": false,
      "averageRansom": "$300,000",
      "cryptocurrency": "BTC",
      "description": "Rhysida ransomware family."
    },
    {
      "name": "BianLian",
      "extensions": [
        ".bianlian"
      ],
      "ransomNote": "Look at this instruction.txt",
      "decryptorAvailable": false,
      "averageRansom": "$500,000",
      "cryptocurrency": "BTC",
      "description": "BianLian ransomware family."
    },
    {
      "name": "Cuba",
      "extensions": [
        ".cuba"
      ],
      "ransomNote": "!! READ ME !!.txt",
      "decryptorAvailable": false,
      "averageRansom": "$100,000",
      "cryptocurrency": "BTC",
      "description": "Cuba ransomware family."
    },
    {
      "name": "AvosLocker",
      "extensions": [
        ".avos",
        ".avos2"
      ],
      "ransomNote": "GET_YOUR_FILES_BACK.txt",
      "decryptorAvailable": false,
      "averageRansom": "$200,000",
      "cryptocurrency": "XMR",
      "description": "AvosLocker ransomware family."
    },
    {
      "name": "Vice Society",
      "extensions": [
        ".v-society"
      ],
      "ransomNote": "AllYFilesAE.txt",
      "decryptorAvailable": false,
      "averageRansom": "$100,000",
      "cryptocurrency": "BTC",
      "description": "Vice Society ransomware family."
    },
    {
      "name": "Babuk",
      "extensions": [
        ".babyk",
        ".babuk"
      ],
      "ransomNote": "How To Restore Your Files.txt",
      "decryptorAvailable": true,
      "averageRansom": "$50,000",
      "cryptocurrency": "BTC/XMR",
      "description": "Babuk ransomware family."
    },
    {
      "name": "RagnarLocker",
      "extensions": [
        ".ragnar_*"
      ],
      "ransomNote": "RGNR_*.txt",
      "decryptorAvailable": false,
      "averageRansom": "$1,000,000",
      "cryptocurrency": "BTC",
      "description": "RagnarLocker ransomware family."
    },
    {
      "name": "GandCrab",
      "extensions": [
        ".GDCB",
        ".CRAB",
        ".KRAB"
      ],
      "ransomNote": "GDCB-DECRYPT.txt",
      "decryptorAvailable": true,
      "averageRansom": "$1,000",
      "cryptocurrency": "DASH",
      "description": "GandCrab ransomware family."
    },
    {
      "name": "Dharma/CrySiS",
      "extensions": [
        ".dharma",
        ".cezar",
        ".cesar"
      ],
      "ransomNote": "FILES ENCRYPTED.txt",
      "decryptorAvailable": true,
      "averageRansom": "$5,000",
      "cryptocurrency": "BTC",
      "description": "Dharma/CrySiS ransomware family."
    },
    {
      "name": "MedusaLocker",
      "extensions": [
        ".encrypted",
        ".ReadTheManual"
      ],
      "ransomNote": "Recovery_Instructions.html",
      "decryptorAvailable": true,
      "averageRansom": "$10,000",
      "cryptocurrency": "BTC",
      "description": "MedusaLocker ransomware family."
    },
    {
      "name": "BlackMatter",
      "extensions": [
        ".random"
      ],
      "ransomNote": "*.README.txt",
      "decryptorAvailable": false,
      "averageRansom": "$100,000",
      "cryptocurrency": "XMR",
      "description": "BlackMatter ransomware family."
    },
    {
      "name": "Quantum",
      "extensions": [
        ".quantum"
      ],
      "ransomNote": "README_TO_DECRYPT.html",
      "decryptorAvailable": false,
      "averageRansom": "$150,000",
      "cryptocurrency": "BTC",
      "description": "Quantum ransomware family."
    },
    {
      "name": "Nokoyawa",
      "extensions": [
        ".NOKOYAWA"
      ],
      "ransomNote": "NOKOYAWA_readme.txt",
      "decryptorAvailable": false,
      "averageRansom": "$200,000",
      "cryptocurrency": "BTC",
      "description": "Nokoyawa ransomware family."
    },
    {
      "name": "LockBit 2.0",
      "extensions": [
        ".lockbit"
      ],
      "ransomNote": "Restore-My-Files.txt",
      "decryptorAvailable": false,
      "averageRansom": "$50,000",
      "cryptocurrency": "BTC",
      "description": "LockBit 2.0 ransomware family."
    },
    {
      "name": "Yanluowang",
      "extensions": [
        ".yanluowang"
      ],
      "ransomNote": "README.txt",
      "decryptorAvailable": false,
      "averageRansom": "$500,000",
      "cryptocurrency": "BTC",
      "description": "Yanluowang ransomware family."
    },
    {
      "name": "Karakurt",
      "extensions": [],
      "ransomNote": "readme.txt",
      "decryptorAvailable": false,
      "averageRansom": "$100,000",
      "cryptocurrency": "BTC/XMR",
      "description": "Karakurt ransomware family."
    },
    {
      "name": "ALPHV Sphynx",
      "extensions": [
        ".sphynx"
      ],
      "ransomNote": "RECOVER-FILES-sphynx.txt",
      "decryptorAvailable": false,
      "averageRansom": "$300,000",
      "cryptocurrency": "BTC/XMR",
      "description": "ALPHV Sphynx ransomware family."
    },
    {
      "name": "Cactus",
      "extensions": [
        ".cts1",
        ".cts6"
      ],
      "ransomNote": "cAcTuS.readme.txt",
      "decryptorAvailable": false,
      "averageRansom": "$200,000",
      "cryptocurrency": "BTC",
      "description": "Cactus ransomware family."
    },
    {
      "name": "Hunters International",
      "extensions": [
        ".locked"
      ],
      "ransomNote": "Contact Us.txt",
      "decryptorAvailable": false,
      "averageRansom": "$500,000",
      "cryptocurrency": "BTC",
      "description": "Hunters International ransomware family."
    },
    {
      "name": "8Base",
      "extensions": [
        ".8base"
      ],
      "ransomNote": "info.hta",
      "decryptorAvailable": false,
      "averageRansom": "$50,000",
      "cryptocurrency": "BTC",
      "description": "8Base ransomware family."
    },
    {
      "name": "Mallox",
      "extensions": [
        ".mallox",
        ".exploit"
      ],
      "ransomNote": "FILE RECOVERY.txt",
      "decryptorAvailable": false,
      "averageRansom": "$100,000",
      "cryptocurrency": "BTC",
      "description": "Mallox ransomware family."
    },
    {
      "name": "Inc Ransom",
      "extensions": [
        ".INC"
      ],
      "ransomNote": "INC-README.txt",
      "decryptorAvailable": false,
      "averageRansom": "$300,000",
      "cryptocurrency": "BTC",
      "description": "Inc Ransom ransomware family."
    }
  ]
};

export const APT_COUNT = 35;
export const MALWARE_COUNT = 50;
export const RANSOMWARE_COUNT = 40;
