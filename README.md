# Netskope Cloud Exchange Plugins 

<div style="text-align: justify">
An admin can configure plugins. Netskope Cloud Exchange (CE) comes with a library of supported plugins. In the case where the integration for desired product is not available, CE allows users to add their own Cloud Exchange plugin. 
Additionally, each plugin that is published as part of the CE has its own configuration guide that administrators can and should refer to.

When building a plugin the following guildlines need to be followed. 
</div>

## CTE [Plugin Name] v[Plugin Version] Plugin Guide

## Description 

&lt;Add a brief description regarding this plugin guide understanding.>


### Prerequisites 



* List down all the prerequisites as bullet points.


### Connectivity to the following hosts 



* [https://google.com](https://google.com)
* [https://hub.docker.com](https://hub.dokcker.com)


## CE Version Compatibility 

Netskope CE version x, version y

Product name and version (If applicable)


## Plugin Scope 

&lt; One-liner description for the plugin workflow>


### Type of data supported 

<table>
  <tr>
   <td>Fetched indicator types
   </td>
   <td>URL(Domains,URLs, IPv4, IPv6), SHA256, MD5
   </td>
  </tr>
  <tr>
   <td>Shared indicator types
   </td>
   <td>URL(Domains,URLs, IPv4, IPv6), SHA256, MD5
   </td>
  </tr>
</table>



### Mappings 

Add a one-liner description explaining the purpose/use of mapping


#### Severity Mapping 


<table>
  <tr>
   <td>Netskope CE Severity
   </td>
   <td>Third-Party Severity
   </td>
  </tr>
  <tr>
   <td>Field 1
   </td>
   <td>xyzfield1
   </td>
  </tr>
  <tr>
   <td>Field 2
   </td>
   <td>xyzfield1
   </td>
  </tr>
</table>



#### Pull Mapping 


<table>
  <tr>
   <td>Netskope CE Fields
   </td>
   <td>Third-Party field
   </td>
  </tr>
  <tr>
   <td>Field 1
   </td>
   <td>xyzfield1
   </td>
  </tr>
  <tr>
   <td>Field 2
   </td>
   <td>xyzfield1
   </td>
  </tr>
</table>



#### Push Mapping 


<table>
  <tr>
   <td>Netskope CE fields 
   </td>
   <td>Third-Party fields
   </td>
  </tr>
  <tr>
   <td>Field 1
   </td>
   <td>xyzfield1
   </td>
  </tr>
  <tr>
   <td>Field 2
   </td>
   <td>xyzfield1
   </td>
  </tr>
</table>



## Permissions  



* Permission needed 1
* Permission needed 2


## API Details 


### List of APIs used 


<table>
  <tr>
   <td><strong>API Endpoint</strong>
   </td>
   <td><strong>Method</strong>
   </td>
   <td><strong>Use case</strong>
   </td>
  </tr>
  <tr>
   <td>API Endpoint
   </td>
   <td>GET/POST
   </td>
   <td>API purpose
   </td>
  </tr>
</table>



### API Endpoint name 

**Parameters: **(add in tabular format)


#### Pull Data  

**Example:**

**API Endpoint: **&lt;api endpoint>

**Method: **GET/POST

**Parameters:** if any

**API Request Endpoint:**


```
<api request>
```


**Sample API Response:**


```
Xyz
ABC
```



## Performance Matrix 

Description mentioning how to refer to this performance matrix


<table>
  <tr>
   <td>Stack details
   </td>
   <td>Size: Large
<p>
RAM: 32 GB
<p>
CPU: 16 Cores
   </td>
  </tr>
  <tr>
   <td>Indicators fetched from third-party product
   </td>
   <td>~X per minute
   </td>
  </tr>
  <tr>
   <td>Indicators shared with third-party product
   </td>
   <td>~X per minute
   </td>
  </tr>
</table>



## User Agent 

The user-agent added in this plugin is in the following format netskope-ce-&lt;ce_version>-&lt;module>-&lt;plugin_name>-&lt;plugin_version>


## Workflow 

Briefly list all the points needed for the plugin. Check the CTE ThreatConnect plugin guide hosted on the Netskope docs for reference. [https://docs.netskope.com/en/netskope-help/integrations-439794/netskope-cloud-exchange/threat-exchange-module/configure-3rd-party-threat-exchange-plugins/threatconnect-plugin-for-threat-exchange/](https://docs.netskope.com/en/netskope-help/integrations-439794/netskope-cloud-exchange/threat-exchange-module/configure-3rd-party-threat-exchange-plugins/threatconnect-plugin-for-threat-exchange/)


## Configuration on Netskope Tenant 

Follow the steps provided in the below document to configure the Netskope Tenant:

[https://docs.netskope.com/en/netskope-help/integrations-439794/netskope-cloud-exchange/get-started-with-cloud-exchange/configure-netskope-tenants/](https://docs.netskope.com/en/netskope-help/integrations-439794/netskope-cloud-exchange/get-started-with-cloud-exchange/configure-netskope-tenants/)

Follow the steps provided in the below document to configure the URL List on Netskope Tenant:

[https://docs.netskope.com/en/netskope-help/data-security/real-time-protection/custom-category/url-lists/](https://docs.netskope.com/en/netskope-help/data-security/real-time-protection/custom-category/url-lists/)

Follow the steps provided in the below document in order to configure the Netskope plugin on Cloud Exchange.

[https://docs.netskope.com/en/netskope-help/integrations-439794/netskope-cloud-exchange/get-started-with-cloud-exchange/configure-the-netskope-plugin-for-threat-exchange/](https://docs.netskope.com/en/netskope-help/integrations-439794/netskope-cloud-exchange/get-started-with-cloud-exchange/configure-the-netskope-plugin-for-threat-exchange/)


## Configuration on &lt;Third party product name> 


### Obtaining configuration parameter 



* Rename the title appropriately.
* Add steps instructing users on enabling some settings that are a prerequisite to configuring the plugin.
* Add necessary screenshots.


## Configuration on Netskope CE 


### [Plugin Name] Plugin configuration 



* Add detailed steps along with screenshots.


### Adding Business Rule 



* Steps with proper Screenshots.


### Adding SIEM Mapping/Sharing/Queue/Actions 



* Steps with proper Screenshots.


## Validation 


### Validate the Pull 



* Steps to verify pulling from Netskope CE with Screenshots.
* Provide screenshots of pulled data for all supported IOC  types.
* Add Steps to verify the data pulled from a third-party platform.


### Validate the Push 



* Steps to verify sharing/data ingestion with Screenshots from CE to Third Party.
* Provide screenshots of pushed data for all supported IOC  types.


## Troubleshooting 



* Unable to pull data from Third-Party
* Unable to push data to Third-Party
* Point 3


## Limitation 



* Point 1(if any)
* Point 2(if any)
