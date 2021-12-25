This script reads data from:
- Tanium: pulling from a splunk index so api call to splunk 
- CMDB: a seperate script makes api call to service now to pull cmdb asset data and business data (used for determining asset owner)
- STATIC ASSETS: reads a file with static assets 
- SCANNERS: reads a static file with scanners as well
- CRITICAL ASSETS: static file with assets that are critical



Then it consolidates them into the format expected for splunk:
	ip,mac,nt_host,dns,owner,priority,lat,long,city,country,bunit,category,pci_domain,is_expected,should_timesync,should_update,requires_av,cim_entity_zone