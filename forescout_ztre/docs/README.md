# CRE Forescout v1.0.0 README

## Release Notes
### 1.0.0
#### Added

- Initial Release.
- The Forescout plugin fetches hosts and their risk information from All Hosts page of Forescout. It does not support any actions on Forescout. Netskope normalization score calculation for OT Security Risk Score and CYSIV Risk Score => ((Forescout Score - Min Forescout) / (Max Forescout - Min Forescout)) * (Max Netskope - Min Netskope) + Min Netskope


## Description

The Forescout plugin fetches hosts and their risk information from All Hosts page of Forescout. It does not support any actions on Forescout. 


## Plugin Scope

| Type of data supported        |    |                                     
|-------------------------------|------------------------------------------------------|
| Type of data pulled       | Hosts   |
| Actions Supported       |Not Supported   |

## Prerequisites

- Netskope Tenant (or multiple, for example, production and development/test instances)
- Netskope Cloud Exchange: CRE module
- Forescout Username and Password


## Connectivity to the following hosts

- Connectivity to Forescout platform https://<Instance IP\>

## CE Version Compatibility

- Netskope CE v5.1.0

## Mappings

The below mapping can be used to pull the Hosts and their respective details. Mapped fields during plugin configuration will be visible on the Records page once the data is pulled. Below is the suggested mapping that should be used while configuring the plugin.


### Pull Mapping

|Plugin Field|Expected Datatype |Suggested Field Name|Suggested Field Aggregate Strategy
|--|--|--|--|
|Host ID  |String|Host ID  |Unique|
|Classification Score  |String|Classification Score |Overwrite|
|CYSIV Risk Device Criticality	  |String|CYSIV Device Criticality|Overwrite|
|CYSIV Risk Score  |String|CYSIV Score  |Overwrite|
|CYSIV Risk Severity  |String|CYSIV Severity  |Overwrite|
|Discovery Score  |String|Discovery Score  |Overwrite|
|Firmware Classification Score  |String|Firmware Classification Score  |Overwrite|
|Host Mac Address  |String|Host Mac Address  |Overwrite|
|Model Classification Score  |String|Model Classification Score  |Overwrite|
|OS Discovery Score  |String|OS Discovery Score  |Overwrite|
|OT Criticality  |String|OT Criticality  |Overwrite|
|OT Operational Risk  |String|OT Operational Risk  |Overwrite|
|OT Security Risk  |String|OT Security Risk  |Overwrite|
|Prim Discovery Score  |String|Prim Discovery Score  |Overwrite|
|Vendor Classification Score  |String|Vendor Classification Score  |Overwrite|
|Netskope Normalized Score  |String|Netskope Normalized Score  |Overwrite|


## API Details

### List of APIs used

|API Endpoint  |Method  | Use case  |
|--|--|-- |
| /api/login|POST|Get auth token|
| /api/hosts|GET|Pull host IDs|
| /api/hosts/<Host ID>|GET|Pull host risk details|

### Get auth token

**Endpoint:** /api/login

**Method:** POST

**Headers**

|Key|Value |
|--|--|
|User-Agent  |netskope-ce-5.1.0-cre-forescout-v1.0.0|
|Content-Type |application/x-www-form-urlencoded|



**Parameters**

|Key|Value |
|--|--|
|username |<UserName\>|
|password |<Password\>|


#### Sample API Response
```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiLim6TpurPlpZXpgJvmv6fotJ3njJ7iiLLqi7zuspPkl6Lnj7npkb3vvJvktpjrl7Hsv6npgorquITqrr3hhrjku4vjoZHptbLugYDsp4Tni5HnvpHph4zug5_sg5rinpzit4XQq-6jgs2K65yB5Lym5ZiD5qGg6LSy4oyg6ZWy44yl642w6J2F6qag4KW57qev45C-75Wc46KL6qOE7YW86amH7Iyu4qeZ6Kib5Kaf7Z7J-X5aaR27rtm6LuroDmmY7nhZXtgKfmtprskorioobkkaIiLCJleHAiOjE3MjU1Mjg5NTF9.AeuUS69vof-Iq9kpaEdJMol5EQNadbw_zW4EcBJa088
```

### Pull Host IDs


**Endpoint:** /api/hosts

**Method:** POST

**Headers**

|Key|Value |
|--|--|
|User-Agent  |netskope-ce-5.1.0-cre-forescout-v1.0.0|
|Content-Type |application/x-www-form-urlencoded|
|If-None-Match|Initially it is not setted but in the 2nd request onwards the <Response Headers.ETag> ETag received from the response headers will be added.|



#### Sample API Response
```
{
    "hosts": [
        {
            "hostId": 167838209,
            "ip": "10.1.2.1",
            "mac": null,
            "links": [
                {
                    "rel": "self",
                    "href": "https://10.0.1.15/api/hosts/167838209"
                }
            ]
        },
]
}
```

### Pull host risk detail

**Endpoint:** /api/hosts/<Host ID>

**Method:** GET

**Headers**

|Key|Value |
|--|--|
|User-Agent  |netskope-ce-5.1.0-cre-forescout-v1.0.0|
|Authorization |<Auth Token\>|


#### Sample API Response
```
{
    "host": {
        "ip": "10.5.0.22",
        "mac": "0022e51f9018",
        "fields": {
            "rem_category": {
                "timestamp": 1724755548,
                "value": "OT"
            },
            "model_classification_source": {
                "timestamp": 1724839679,
                "value": "otsm"
            },
            "is_behind_nat": {
                "timestamp": 1724753946,
                "value": "false"
            },
            "cysiv_risk_severity": {
                "timestamp": 1724755548,
                "value": "low"
            },
            "onsite": {
                "timestamp": 1724395424,
                "value": "true"
            },
            "classification_source_os": {
                "timestamp": 1724839679,
                "value": "dpl"
            },
            "linux_manage": {
                "timestamp": 1724753946,
                "value": "false"
            },
            "access_ip": {
                "timestamp": 1724839650,
                "value": "10.5.0.22"
            },
            "openports": [
                {
                    "timestamp": 1724398100,
                    "value": "18507/UDP"
                }
            ],
            "cc_last_saved_value": {
                "timestamp": 1724395455,
                "value": "{\"raw_data_value\":\"{\\\"db_creation_date\\\":\\\"2024-07-30 10:41:16.407\\\",\\\"os\\\":\\\"NA\\\",\\\"os_version\\\":\\\"NA\\\",\\\"caption\\\":\\\"NA\\\",\\\"type\\\":\\\"NA\\\",\\\"db_version\\\":\\\"2.0\\\",\\\"has_data\\\":\\\"false\\\",\\\"os_build\\\":\\\"NA\\\",\\\"vendor\\\":\\\"NA\\\",\\\"rank\\\":\\\"NA\\\",\\\"model\\\":\\\"NA\\\",\\\"make\\\":\\\"NA\\\",\\\"group\\\":\\\"NA\\\"}\",\"request_parameters\":[{\"property_value\":\"0022e51f9018\",\"property_name\":\"mac\"}]}"
            },
            "otsm_details_firmware_version": {
                "timestamp": 1724826201,
                "value": "12.3.0.4972.xr"
            },
            "segment_path_calculated": [
                {
                    "timestamp": 1724395424,
                    "value": "5305124740861699347/-8087060916317949182/-2438220170031211496/"
                }
            ],
            "otsm_details_server_protos": [
                {
                    "timestamp": 1724826201,
                    "value": "DELTAV_IO (UDP 18507)"
                },
                {
                    "timestamp": 1724826201,
                    "value": "DELTAV_MGMT (TCP 18519)"
                }
            ],
            "agent_install_mode": {
                "timestamp": 1724839650,
                "value": "None"
            },
            "otsm_details_manufacturer": {
                "timestamp": 1724826201,
                "value": "Emerson"
            },
            "in-group": [
                {
                    "timestamp": 0,
                    "value": "Purdue0HostVulnerability"
                },
                {
                    "timestamp": 0,
                    "value": "Purdue0Host"
                },
                {
                    "timestamp": 0,
                    "value": "HostCriticality4"
                },
                {
                    "timestamp": 0,
                    "value": "ICS Client Protocols"
                },
                {
                    "timestamp": 0,
                    "value": "HighHostwithVulnerability"
                },
                {
                    "timestamp": 0,
                    "value": "CVSS-8andHigher"
                },
                {
                    "timestamp": 0,
                    "value": "IoT Devices"
                },
                {
                    "timestamp": 0,
                    "value": "Properties - Passive Learning"
                },
                {
                    "timestamp": 0,
                    "value": "IOOffline"
                },
                {
                    "timestamp": 0,
                    "value": "CVSS-High Matching Confidence"
                },
                {
                    "timestamp": 0,
                    "value": "ICS Server Protocols"
                },
                {
                    "timestamp": 0,
                    "value": "Campus Network"
                }
            ],
            "rem_firmware": {
                "timestamp": 1724755548,
                "value": "12.3.0.4972.xr"
            },
            "agent_visible_mode": {
                "timestamp": 1724839650,
                "value": "None"
            },
            "classification_source_func": {
                "timestamp": 1724839679,
                "value": "otsm"
            },
            "otsm_details_cves": [
                {
                    "timestamp": 1724826201,
                    "value": {
                        "cvss_score": "7.5",
                        "vendor_specific_id": "",
                        "cvss_temporal_score": "0.0",
                        "title": "Emerson DeltaV 10.3.1, 11.3, 11.3.1, and 12.3 uses hardcoded credentials for diagnostic services",
                        "matching_confidence": "product",
                        "cvss_access_complexity": "LOW",
                        "cvss_exploitability": "UNDEFINED",
                        "cvss_remediation_level": "OFFICIAL_FIX",
                        "cvss_authentication": "NONE",
                        "icsa_id": "ICSA-14-133-02",
                        "cvss_confidentiality_impact": "PARTIAL",
                        "cve_id": "CVE-2014-2350",
                        "cvss_reporting_confidence": "CONFIRMED",
                        "cvss_availability_impact": "PARTIAL",
                        "id": "CVE-2014-2350",
                        "suppressed": "false",
                        "cvss_access_vector": "NETWORK",
                        "cvss_integrity_impact": "PARTIAL"
                    }
                },
                {
                    "timestamp": 1724826201,
                    "value": {
                        "cvss_score": "4.2",
                        "vendor_specific_id": "",
                        "cvss_temporal_score": "0.0",
                        "title": "OT:ICEFALL: Use of hard-coded credentials vulnerability in Emerson DeltaV",
                        "matching_confidence": "productVersion",
                        "cvss_remediation_level": "OFFICIAL_FIX",
                        "icsa_id": "ICSA-22-181-03",
                        "cvss_confidentiality_impact": "LOW",
                        "cve_id": "CVE-2022-29962",
                        "cvss_reporting_confidence": "CONFIRMED",
                        "cvss_availability_impact": "LOW",
                        "id": "CVE-2022-29962",
                        "suppressed": "false",
                        "cvss_integrity_impact": "LOW"
                    }
                },
                {
                    "timestamp": 1724826201,
                    "value": {
                        "cvss_score": "6.8",
                        "vendor_specific_id": "",
                        "cvss_temporal_score": "0.0",
                        "title": "OT:ICEFALL: Missing authentication for critical function vulnerability in Emerson DeltaV",
                        "matching_confidence": "productVersion",
                        "cvss_remediation_level": "OFFICIAL_FIX",
                        "icsa_id": "ICSA-22-181-03",
                        "cvss_confidentiality_impact": "NONE",
                        "cve_id": "CVE-2022-29957",
                        "cvss_reporting_confidence": "CONFIRMED",
                        "cvss_availability_impact": "HIGH",
                        "id": "CVE-2022-29957",
                        "suppressed": "false",
                        "cvss_integrity_impact": "HIGH"
                    }
                },
                {
                    "timestamp": 1724826201,
                    "value": {
                        "cvss_score": "6.3",
                        "vendor_specific_id": "",
                        "cvss_temporal_score": "0.0",
                        "title": "OT:ICEFALL: Insufficient verification of data authenticity vulnerability in Emerson DeltaV",
                        "matching_confidence": "productVersion",
                        "cvss_remediation_level": "OFFICIAL_FIX",
                        "icsa_id": "ICSA-22-181-03",
                        "cvss_confidentiality_impact": "HIGH",
                        "cve_id": "CVE-2022-30620",
                        "cvss_reporting_confidence": "CONFIRMED",
                        "cvss_availability_impact": "HIGH",
                        "id": "CVE-2022-30620",
                        "suppressed": "false",
                        "cvss_integrity_impact": "HIGH"
                    }
                },
                {
                    "timestamp": 1724826201,
                    "value": {
                        "cvss_score": "8.8",
                        "vendor_specific_id": "",
                        "cvss_temporal_score": "0.0",
                        "title": "OT:ICEFALL: Broken cryptographic algorithm vulnerability in Emerson DeltaV",
                        "matching_confidence": "productVersion",
                        "cvss_remediation_level": "UNAVAILABLE",
                        "icsa_id": "ICSA-22-181-03",
                        "cvss_confidentiality_impact": "HIGH",
                        "cve_id": "CVE-2022-29965",
                        "cvss_reporting_confidence": "CONFIRMED",
                        "cvss_availability_impact": "HIGH",
                        "id": "CVE-2022-29965",
                        "suppressed": "false",
                        "cvss_integrity_impact": "HIGH"
                    }
                },
                {
                    "timestamp": 1724826201,
                    "value": {
                        "cvss_score": "4.2",
                        "vendor_specific_id": "",
                        "cvss_temporal_score": "0.0",
                        "title": "OT:ICEFALL: Use of hard-coded credentials vulnerability in Emerson DeltaV",
                        "matching_confidence": "productVersion",
                        "cvss_remediation_level": "OFFICIAL_FIX",
                        "icsa_id": "ICSA-22-181-03",
                        "cvss_confidentiality_impact": "LOW",
                        "cve_id": "CVE-2022-29964",
                        "cvss_reporting_confidence": "CONFIRMED",
                        "cvss_availability_impact": "LOW",
                        "id": "CVE-2022-29964",
                        "suppressed": "false",
                        "cvss_integrity_impact": "LOW"
                    }
                },
                {
                    "timestamp": 1724826201,
                    "value": {
                        "cvss_score": "1.8",
                        "vendor_specific_id": "",
                        "cvss_temporal_score": "0.0",
                        "title": "OT:ICEFALL: Use of hard-coded credentials vulnerability in Emerson DeltaV",
                        "matching_confidence": "productVersion",
                        "cvss_remediation_level": "OFFICIAL_FIX",
                        "icsa_id": "ICSA-22-181-03",
                        "cvss_confidentiality_impact": "LOW",
                        "cve_id": "CVE-2022-29963",
                        "cvss_reporting_confidence": "CONFIRMED",
                        "cvss_availability_impact": "NONE",
                        "id": "CVE-2022-29963",
                        "suppressed": "false",
                        "cvss_integrity_impact": "NONE"
                    }
                }
            ],
            "mac_prefix32": {
                "timestamp": 1724839643,
                "value": "0022e51f"
            },
            "samba_open_ports": {
                "timestamp": 1724753951,
                "value": "0"
            },
            "model_classification_score": {
                "timestamp": 1724839679,
                "value": "95"
            },
            "otsm_details_last_seen": {
                "timestamp": 1724826201,
                "value": "1724826194"
            },
            "model_classification": {
                "timestamp": 1724839679,
                "value": "Wireless I/O Card"
            },
            "otsm_details_host_name": {
                "timestamp": 1724826201,
                "value": "wioc-1f903a"
            },
            "macs": [
                {
                    "timestamp": 1724839650,
                    "value": "0022e51f9018"
                }
            ],
            "dpl_model_classification": {
                "timestamp": 1724839679,
                "value": ""
            },
            "cysiv_risk_device_criticality": {
                "timestamp": 1724755548,
                "value": "high"
            },
            "os_discovery_score": {
                "timestamp": 1724839675,
                "value": "64"
            },
            "prim_discovery_score": {
                "timestamp": 1724839675,
                "value": "83"
            },
            "otsm_details_host_mac_addresses": [
                {
                    "timestamp": 1724826201,
                    "value": "00:22:E5:1F:90:18"
                }
            ],
            "mediator_otsm_prim_classification": {
                "timestamp": 1724839649,
                "value": "Operational Technology/Industrial Control Systems/IO Module"
            },
            "vendor_classification_score": {
                "timestamp": 1724839675,
                "value": "46"
            },
            "rem_equipment_function": {
                "timestamp": 1724755548,
                "value": "Unknown"
            },
            "mac": {
                "timestamp": 1724839650,
                "value": "0022e51f9018"
            },
            "otsm_details_security_risk": {
                "timestamp": 1724839643,
                "value": "8.2"
            },
            "manufacturer_classification": {
                "timestamp": 1724839679,
                "value": "Emerson"
            },
            "vendor": {
                "timestamp": 1724839643,
                "value": "fisher-rosemount systems inc."
            },
            "segment_name_calculated": {
                "timestamp": 1724395424,
                "value": "Operational Technology"
            },
            "hostname_calculated": {
                "timestamp": 1724395424,
                "value": "wioc-1f903a"
            },
            "mediator_otsm_vendor_classification": {
                "timestamp": 1724839649,
                "value": "Emerson"
            },
            "dex_Forescout_Risk_Score": {
                "timestamp": 1724839648,
                "value": "0"
            },
            "gst_signed_in_stat": {
                "timestamp": 1724753946,
                "value": "na"
            },
            "vendor_discovery_score": {
                "timestamp": 1724839675,
                "value": "93"
            },
            "vpn_login": {
                "timestamp": 1724821286,
                "value": "false"
            },
            "groups_path_calculated": [
                {
                    "timestamp": 1724818528,
                    "value": "5483371701762015725/"
                },
                {
                    "timestamp": 1724818528,
                    "value": "5006884535761276673/6881123241563699922/-774523594407371799/-7432780537313919341/"
                },
                {
                    "timestamp": 1724818528,
                    "value": "5006884535761276673/6881123241563699922/-774523594407371799/8677054046804567500/"
                }
            ],
            "eds_empty_results": [
                {
                    "timestamp": 1724839648,
                    "value": "dex_Forescout_Risk_Score"
                }
            ],
            "cysiv_risk_score_last_updated": {
                "timestamp": 1724755548,
                "value": "1724755324"
            },
            "mac_calculated": {
                "timestamp": 1724395424,
                "value": "0022e51f9018"
            },
            "dpl_vendor_classification": {
                "timestamp": 1724839675,
                "value": "Emerson"
            },
            "cysiv_risk_cve_list": [
                {
                    "timestamp": 1724755548,
                    "value": {
                        "cysiv_cve_reported_time": "1400792106",
                        "cysiv_cve_cisa": "false",
                        "cysiv_cve_cvss_score": "7.5",
                        "cysiv_cve_exploitability_level": "Low",
                        "cysiv_cve_id": "CVE-2014-2350",
                        "cysiv_cve_exploitability_percentile": "0.754"
                    }
                },
                {
                    "timestamp": 1724755548,
                    "value": {
                        "cysiv_cve_reported_time": "1672035310",
                        "cysiv_cve_cisa": "false",
                        "cysiv_cve_cvss_score": "7.8",
                        "cysiv_cve_exploitability_level": "Low",
                        "cysiv_cve_id": "CVE-2022-30260",
                        "cysiv_cve_exploitability_percentile": "0.268"
                    }
                }
            ],
            "classification_score": {
                "timestamp": 1724839675,
                "value": "32"
            },
            "firmware_classification": {
                "timestamp": 1724839651,
                "value": "12.3.0.4972.xr"
            },
            "otsm_details_module_identities": [
                {
                    "timestamp": 1724826201,
                    "value": {
                        "vendor": "Rosemount",
                        "name": "",
                        "model": "781 RL",
                        "serial_number": "",
                        "firmware_version": "",
                        "state": "UNDEFINED",
                        "type": "Wireless Access Point",
                        "hardware_version": "",
                        "slot_number": "WAP01"
                    }
                },
                {
                    "timestamp": 1724826201,
                    "value": {
                        "vendor": "Emerson",
                        "name": "WIOC-1F903A",
                        "model": "12P5030X032",
                        "serial_number": "",
                        "firmware_version": "12.3.0.4972.xr",
                        "state": "UNDEFINED",
                        "type": "Wireless I/O Card",
                        "hardware_version": "9.3",
                        "slot_number": "0"
                    }
                }
            ],
            "manage_agent": {
                "timestamp": 1724839650,
                "value": "false"
            },
            "dpl_os_classification": {
                "timestamp": 1724839675,
                "value": "Unknown"
            },
            "ipv4_report_time": {
                "timestamp": 1724826081,
                "value": "true"
            },
            "manufacturer_classification_score": {
                "timestamp": 1724839679,
                "value": "-1"
            },
            "otsm_details_first_seen": {
                "timestamp": 1724826201,
                "value": "1635282777"
            },
            "firmware_classification_source": {
                "timestamp": 1724839651,
                "value": "otsm"
            },
            "otsm_details_cc_ip": {
                "timestamp": 1724826201,
                "value": "10.0.1.60"
            },
            "otsm_details_hardware_version": {
                "timestamp": 1724826201,
                "value": "9.3"
            },
            "classification_source_vendor": {
                "timestamp": 1724839679,
                "value": "dpl"
            },
            "mac_vendor_string": {
                "timestamp": 1724839643,
                "value": "FISHER-ROSEMOUNT SYSTEMS INC."
            },
            "rem_function": {
                "timestamp": 1724755548,
                "value": "IO Module"
            },
            "mediator_otsm_model_classification": {
                "timestamp": 1724839649,
                "value": "Wireless I/O Card"
            },
            "prim_classification_source": {
                "timestamp": 1724839679,
                "value": "otsm"
            },
            "otsm_details_client_protos": [
                {
                    "timestamp": 1724826201,
                    "value": "DELTAV_IO (UDP 18507)"
                }
            ],
            "firmware_classification_score": {
                "timestamp": 1724839651,
                "value": "60"
            },
            "ccg_prim_classification": {
                "timestamp": 1724395455,
                "value": "Unknown"
            },
            "os_classification_score": {
                "timestamp": 1724839679,
                "value": "-1"
            },
            "prim_classification_score": {
                "timestamp": 1724839679,
                "value": "-1"
            },
            "mediator_otsm_firmware_classification": {
                "timestamp": 1724839649,
                "value": "12.3.0.4972.xr"
            },
            "otsm_details_sensor_names": [
                {
                    "timestamp": 1724839643,
                    "value": "Sensor1 at 10.0.1.60"
                }
            ],
            "adm": [
                {
                    "timestamp": 1724395388,
                    "value": "new"
                },
                {
                    "timestamp": 1724839643,
                    "value": "online_again"
                }
            ],
            "snow_mac_exist": {
                "timestamp": 1724839650,
                "value": "snow_mac_exist_true"
            },
            "otsm_details_model": {
                "timestamp": 1724826201,
                "value": "Wireless I/O Card"
            },
            "wifi_client_login": {
                "timestamp": 1724817697,
                "value": "false"
            },
            "rem_vendor": {
                "timestamp": 1724755548,
                "value": "Emerson"
            },
            "matched_fingerprints": [
                {
                    "timestamp": 1724839675,
                    "value": "SM-Vendor-Emerson"
                },
                {
                    "timestamp": 1724839675,
                    "value": "SM-IO module"
                }
            ],
            "otsm_details_criticality": {
                "timestamp": 1724826201,
                "value": "4"
            },
            "os_classification_source": {
                "timestamp": 1724839679,
                "value": "dpl"
            },
            "discovery_score": {
                "timestamp": 1724839675,
                "value": "80"
            },
            "compliance_state": {
                "timestamp": 1724839680,
                "value": "COMPLY"
            },
            "device_role": {
                "timestamp": 1724839675,
                "value": "false"
            },
            "dpl_prim_classification": {
                "timestamp": 1724839675,
                "value": "Operational Technology/Industrial Control Systems/IO Module"
            },
            "manufacturer_classification_source": {
                "timestamp": 1724839679,
                "value": "dpl"
            },
            "os_classification": {
                "timestamp": 1724839679,
                "value": "Unknown"
            },
            "cc_host_classifier": {
                "timestamp": 1724395455,
                "value": "{\"db_creation_date\":\"2024-07-30 10:41:16.407\",\"os\":\"NA\",\"os_version\":\"NA\",\"caption\":\"NA\",\"type\":\"NA\",\"db_version\":\"2.0\",\"has_data\":\"false\",\"os_build\":\"NA\",\"vendor\":\"NA\",\"rank\":\"NA\",\"model\":\"NA\",\"make\":\"NA\",\"group\":\"NA\"}"
            },
            "snow_add_update_status": {
                "timestamp": 1724817882,
                "value": "2"
            },
            "cact_script_result.2a1b2d019d0fb891a7c8d7c32d3f8a6c": {
                "timestamp": 1724752766,
                "value": "Sending ICMP MS_SYNC_REQ\nSending ICMP ECHO"
            },
            "rem_function_taxonomy": {
                "timestamp": 1724755548,
                "value": "Operational Technology/Industrial Control Systems/IO Module"
            },
            "otsm_details_role": {
                "timestamp": 1724826201,
                "value": "io_module"
            },
            "cysiv_risk_score": {
                "timestamp": 1724755548,
                "value": "2.0"
            },
            "is_iot": {
                "timestamp": 1724839675,
                "value": "false"
            },
            "manage_domain_strict": {
                "timestamp": 1724753951,
                "value": "false"
            },
            "ipv4_calculated": {
                "timestamp": 1724395424,
                "value": "10.5.0.22"
            },
            "misc": {
                "timestamp": 1724839658,
                "value": "3* cysiv_risk_internet_exposure_indication 1724755548 mac_manage 1724817902 p2p_running 1724839650 aws_resource_tag 1724817902 nbthost 1724839650 aws_instance_id 1724817808 va_netfunc 1724839650 ad_memberof 1724755633 ad_departmenp 0 1 1724752155 0 0 cloud_application_running 0 1 1724752155 0 0 service 0 1 1724752155 0 0 device_interfaces 0 1 1724752155 0 0 nmap_def_fp7 0 1 1724752155 0 0 p2p_running 0 1 1724752155 0 0 nmap_def_fp5 0 1 1724752155 0 0 va_netfunc 0 1 1724752155 0 0 snmp2 0 1 1724752155 0 0 user 0 1 1724752155 0 0 comp_application 0 1 1724752155 0 0 registry_1 0 1 1724752155 0 0 * cysiv_risk_last_vulnerability_scans 1724755548 suggested_prim_classification 1724817903 suggested_vendor_classification 1724817903 atc_ioc_scan_stats 1724752053 cysiv_risk_exposed_services 1724755548 "
            },
            "prim_classification": {
                "timestamp": 1724839679,
                "value": "Operational Technology/Industrial Control Systems/IO Module"
            },
            "vendor_classification": {
                "timestamp": 1724839675,
                "value": "Emerson"
            },
            "rem_model": {
                "timestamp": 1724755548,
                "value": "Wireless I/O Card"
            },
            "rem_os": {
                "timestamp": 1724755548,
                "value": "Unknown"
            },
            "otsm_details_operational_risk": {
                "timestamp": 1724839643,
                "value": "0.0"
            },
            "last_nbt_report_time": {
                "timestamp": 1724753947,
                "value": "1724753947"
            },
            "otsm_details_purdue_level": {
                "timestamp": 1724826201,
                "value": "LEVEL0"
            },
            "agent_version": {
                "timestamp": 1724753946,
                "value": "None"
            },
            "rem_os_taxonomy": {
                "timestamp": 1724755548,
                "value": "Unknown"
            },
            "local-credentials-OK": {
                "timestamp": 1724753946,
                "value": "false"
            },
            "_times": [
                {
                    "timestamp": 1724839643,
                    "value": "last_onsite"
                }
            ],
            "online": {
                "timestamp": 1724839643,
                "value": "true"
            },
            "engine_seen_packet": {
                "timestamp": 1724839643,
                "value": "true"
            }
        },
        "id": 168099862
    },
    "links": [
        {
            "rel": "self",
            "href": "https://10.0.1.15/api/hosts/168099862"
        }
    ]
}

```

## User Agent

- netskope-ce-5.1.0-cre-forescout-v1.0.0

## Workflow

- Get Forescout URL, Username and Password
- Configure the Forescout plugin

## Configuration on Forescout

Follow the steps provided in the below Forescout documentation in order to generate the plugin configuration parameter.

https://docs.forescout.com/bundle/web-api-1-5-3-h/page/web-api-1-5-3-h.Configure-Web-API-Plugin.html


## Configuration on Netskope CE

### Forescout Plugin configuration

- Login to your Netskope CE and navigate to Settings > Plugins. Search for the CRE Forescout plugin and click on the plugin box to configure the plugin.

![Plugin page](./forescoutplugin.png)


- Fill out the form with these values:
    - **Configuration Name:** Unique name for the configuration
    - **Sync Interval:** Leave default
	- **Use System Proxy:** Enable if the proxy is required for communication
   
![Plugin page](./forescout-basic-info.png)

- Click on Next and provide the below details.
    - **Base URL:** Base URL of Forescout instance. e.g. https://<Instance IP>.
    - **Username:** Username of Forescout account. Username can be generated from the Settings > Web API > User Settings page.
    - **Password:** Password of Forescout account. Password can be generated from the Settings > Web API > User Settings page.
    - **Netskope Normalization Field:** Select the field to be used for normalization in the Netskope Score Range.

![Plugin page](./forescout-config-param.png)

![Plugin page](./Forescout-mapping.png)