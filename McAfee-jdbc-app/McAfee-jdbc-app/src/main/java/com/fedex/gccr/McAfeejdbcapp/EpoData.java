package com.fedex.gccr.McAfeejdbcapp;

public class EpoData {
	private String timestamp = "";
	private String autoID = "";
	private String signature = ""; 
	private String threat_type = "";
	private String signature_id = "";
	private String category = "";
	private String severity_id = "";
	private String event_description = "";
	private String detected_timestamp = "";
	private String file_name = "";
	private String detection_method = "";
	private String vendor_action = "";
	private String threat_handled = "";
	private String logon_user = "";
	private String user = "";
	private String dest_nt_domain = "";
	private String dest_dns = "";
	private String dest_nt_host = "";
	private String fqdn = "";
	private String dest_ip = "";
	private String dest_netmask = "";
	private String dest_mac = "";
	private String os = ""; 
	private String sp = "";
	private String os_version = "";
	private String os_build = "";
	private String timezone = "";
	private String src_dns = "";
	private String src_ip = "";
	private String src_mac = "";
	private String process = "";
	private String url = "";
	private String source_logon_user = "";
	private String is_laptop = "";
	private String product = "";
	private String product_version = "";
	private String engine_version = "";
	private String dat_version = "";
	private String vse_dat_version = "";
	private String vse_engine64_version = "";
	private String vse_engine_version = "";
	private String vse_hotfix = "";
	private String vse_product_version = "";
	private String vse_source_file_hash = "";
	private String vse_parent_process_hash = "";
	private String vse_source_process_hash = "";
	private String vse_target_file_hash = "";
	private String vse_source_file_path = "";
	private String vse_source_description = "";
	private String vse_target_path = "";
	private String vse_target_name = "";
	private String vse_first_action_status = "";
	private String vse_second_action_status = "";
	private String alert_description = "";
	private String analyzer_rule_name = "";
	private String vse_sp = "";
	
	EpoData(String timestamp, String autoID,  String signature,  String threat_type,  String signature_id,  String category,  String severity_id,  String event_description,  String detected_timestamp,  String file_name,  String detection_method,  String vendor_action,  String threat_handled,  String logon_user,  String user,  String dest_nt_domain,  String dest_dns,  String dest_nt_host,  String fqdn,  String dest_ip,  String dest_netmask,  String dest_mac,  String os,  String sp,  String os_version,  String os_build,  String timezone,  String src_dns,  String src_ip,  String src_mac,  String process,  String url,  String source_logon_user,  String is_laptop,  String product,  String product_version,  String engine_version,  String dat_version,  String vse_dat_version,  String vse_engine64_version,  String vse_engine_version,  String vse_hotfix,  String vse_product_version,  String vse_source_file_hash,  String vse_parent_process_hash,  String vse_source_process_hash,  String vse_target_file_hash,  String vse_source_file_path,  String vse_source_description,  String vse_target_path,  String vse_target_name,  String vse_first_action_status,  String vse_second_action_status, String alert_description, String analyzer_rule_name, String vse_sp){
		this.timestamp = timestamp;
		this.autoID = autoID;
		this.signature = signature; 
		this.threat_type = threat_type;
		this.signature_id = signature_id;
		this.category = category;
		this.severity_id = severity_id;
		this.event_description = event_description;
		this.detected_timestamp = detected_timestamp;
		this.file_name = file_name;
		this.detection_method = detection_method;
		this.vendor_action = vendor_action;
		this.threat_handled = threat_handled;
		this.logon_user = logon_user;
		this.user = user;
		this.dest_nt_domain = dest_nt_domain;
		this.dest_dns = dest_dns;
		this.dest_nt_host = dest_nt_host;
		this.fqdn = fqdn;
		this.dest_ip = dest_ip;
		this.dest_netmask = dest_netmask;
		this.dest_mac = dest_mac;
		this.os = os; 
		this.sp = sp;
		this.os_version = os_version;
		this.os_build = os_build;
		this.timezone = timezone;
		this.src_dns = src_dns;
		this.src_ip = src_ip;
		this.src_mac = src_mac;
		this.process = process;
		this.url = url;
		this.source_logon_user = source_logon_user;
		this.is_laptop = is_laptop;
		this.product = product;
		this.product_version = product_version;
		this.engine_version = engine_version;
		this.dat_version = dat_version;
		this.vse_dat_version = vse_dat_version;
		this.vse_engine64_version = vse_engine64_version;
		this.vse_engine_version = vse_engine_version;
		this.vse_hotfix = vse_hotfix;
		this.vse_product_version = vse_product_version;
		this.vse_source_file_hash = vse_source_file_hash;
		this.vse_parent_process_hash = vse_parent_process_hash;
		this.vse_source_process_hash = vse_source_process_hash;
		this.vse_target_file_hash = vse_target_file_hash;
		this.vse_source_file_path = vse_source_file_path;
		this.vse_source_description = vse_source_description;
		this.vse_target_path = vse_target_path;
		this.vse_target_name = vse_target_name;
		this.vse_first_action_status = vse_first_action_status;
		this.vse_second_action_status = vse_second_action_status;
		this.alert_description = alert_description; 
		this.analyzer_rule_name = analyzer_rule_name;
		this.vse_sp = vse_sp;
	}

	public String getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(String timestamp) {
		this.timestamp = timestamp;
	}

	public String getAutoID() {
		return autoID;
	}

	public void setAutoID(String autoID) {
		this.autoID = autoID;
	}

	public String getSignature() {
		return signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

	public String getThreat_type() {
		return threat_type;
	}

	public void setThreat_type(String threat_type) {
		this.threat_type = threat_type;
	}

	public String getSignature_id() {
		return signature_id;
	}

	public void setSignature_id(String signature_id) {
		this.signature_id = signature_id;
	}

	public String getCategory() {
		return category;
	}

	public void setCategory(String category) {
		this.category = category;
	}

	public String getSeverity_id() {
		return severity_id;
	}

	public void setSeverity_id(String severity_id) {
		this.severity_id = severity_id;
	}

	public String getEvent_description() {
		return event_description;
	}

	public void setEvent_description(String event_description) {
		this.event_description = event_description;
	}

	public String getDetected_timestamp() {
		return detected_timestamp;
	}

	public void setDetected_timestamp(String detected_timestamp) {
		this.detected_timestamp = detected_timestamp;
	}

	public String getFile_name() {
		return file_name;
	}

	public void setFile_name(String file_name) {
		this.file_name = file_name;
	}

	public String getDetection_method() {
		return detection_method;
	}

	public void setDetection_method(String detection_method) {
		this.detection_method = detection_method;
	}

	public String getVendor_action() {
		return vendor_action;
	}

	public void setVendor_action(String vendor_action) {
		this.vendor_action = vendor_action;
	}

	public String getThreat_handled() {
		return threat_handled;
	}

	public void setThreat_handled(String threat_handled) {
		this.threat_handled = threat_handled;
	}

	public String getLogon_user() {
		return logon_user;
	}

	public void setLogon_user(String logon_user) {
		this.logon_user = logon_user;
	}

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

	public String getDest_nt_domain() {
		return dest_nt_domain;
	}

	public void setDest_nt_domain(String dest_nt_domain) {
		this.dest_nt_domain = dest_nt_domain;
	}

	public String getDest_dns() {
		return dest_dns;
	}

	public void setDest_dns(String dest_dns) {
		this.dest_dns = dest_dns;
	}

	public String getDest_nt_host() {
		return dest_nt_host;
	}

	public void setDest_nt_host(String dest_nt_host) {
		this.dest_nt_host = dest_nt_host;
	}

	public String getFqdn() {
		return fqdn;
	}

	public void setFqdn(String fqdn) {
		this.fqdn = fqdn;
	}

	public String getDest_ip() {
		return dest_ip;
	}

	public void setDest_ip(String dest_ip) {
		this.dest_ip = dest_ip;
	}

	public String getDest_netmask() {
		return dest_netmask;
	}

	public void setDest_netmask(String dest_netmask) {
		this.dest_netmask = dest_netmask;
	}

	public String getDest_mac() {
		return dest_mac;
	}

	public void setDest_mac(String dest_mac) {
		this.dest_mac = dest_mac;
	}

	public String getOs() {
		return os;
	}

	public void setOs(String os) {
		this.os = os;
	}

	public String getSp() {
		return sp;
	}

	public void setSp(String sp) {
		this.sp = sp;
	}

	public String getOs_version() {
		return os_version;
	}

	public void setOs_version(String os_version) {
		this.os_version = os_version;
	}

	public String getOs_build() {
		return os_build;
	}

	public void setOs_build(String os_build) {
		this.os_build = os_build;
	}

	public String getTimezone() {
		return timezone;
	}

	public void setTimezone(String timezone) {
		this.timezone = timezone;
	}

	public String getSrc_dns() {
		return src_dns;
	}

	public void setSrc_dns(String src_dns) {
		this.src_dns = src_dns;
	}

	public String getSrc_ip() {
		return src_ip;
	}

	public void setSrc_ip(String src_ip) {
		this.src_ip = src_ip;
	}

	public String getSrc_mac() {
		return src_mac;
	}

	public void setSrc_mac(String src_mac) {
		this.src_mac = src_mac;
	}

	public String getProcess() {
		return process;
	}

	public void setProcess(String process) {
		this.process = process;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getSource_logon_user() {
		return source_logon_user;
	}

	public void setSource_logon_user(String source_logon_user) {
		this.source_logon_user = source_logon_user;
	}

	public String getIs_laptop() {
		return is_laptop;
	}

	public void setIs_laptop(String is_laptop) {
		this.is_laptop = is_laptop;
	}

	public String getProduct() {
		return product;
	}

	public void setProduct(String product) {
		this.product = product;
	}

	public String getProduct_version() {
		return product_version;
	}

	public void setProduct_version(String product_version) {
		this.product_version = product_version;
	}

	public String getEngine_version() {
		return engine_version;
	}

	public void setEngine_version(String engine_version) {
		this.engine_version = engine_version;
	}

	public String getDat_version() {
		return dat_version;
	}

	public void setDat_version(String dat_version) {
		this.dat_version = dat_version;
	}

	public String getVse_dat_version() {
		return vse_dat_version;
	}

	public void setVse_dat_version(String vse_dat_version) {
		this.vse_dat_version = vse_dat_version;
	}

	public String getVse_engine64_version() {
		return vse_engine64_version;
	}

	public void setVse_engine64_version(String vse_engine64_version) {
		this.vse_engine64_version = vse_engine64_version;
	}

	public String getVse_engine_version() {
		return vse_engine_version;
	}

	public void setVse_engine_version(String vse_engine_version) {
		this.vse_engine_version = vse_engine_version;
	}

	public String getVse_hotfix() {
		return vse_hotfix;
	}

	public void setVse_hotfix(String vse_hotfix) {
		this.vse_hotfix = vse_hotfix;
	}

	public String getVse_product_version() {
		return vse_product_version;
	}

	public void setVse_product_version(String vse_product_version) {
		this.vse_product_version = vse_product_version;
	}

	public String getVse_source_file_hash() {
		return vse_source_file_hash;
	}

	public void setVse_source_file_hash(String vse_source_file_hash) {
		this.vse_source_file_hash = vse_source_file_hash;
	}

	public String getVse_parent_process_hash() {
		return vse_parent_process_hash;
	}

	public void setVse_parent_process_hash(String vse_parent_process_hash) {
		this.vse_parent_process_hash = vse_parent_process_hash;
	}

	public String getVse_source_process_hash() {
		return vse_source_process_hash;
	}

	public void setVse_source_process_hash(String vse_source_process_hash) {
		this.vse_source_process_hash = vse_source_process_hash;
	}

	public String getVse_target_file_hash() {
		return vse_target_file_hash;
	}

	public void setVse_target_file_hash(String vse_target_file_hash) {
		this.vse_target_file_hash = vse_target_file_hash;
	}

	public String getVse_source_file_path() {
		return vse_source_file_path;
	}

	public void setVse_source_file_path(String vse_source_file_path) {
		this.vse_source_file_path = vse_source_file_path;
	}

	public String getVse_source_description() {
		return vse_source_description;
	}

	public void setVse_source_description(String vse_source_description) {
		this.vse_source_description = vse_source_description;
	}

	public String getVse_target_path() {
		return vse_target_path;
	}

	public void setVse_target_path(String vse_target_path) {
		this.vse_target_path = vse_target_path;
	}

	public String getVse_target_name() {
		return vse_target_name;
	}

	public void setVse_target_name(String vse_target_name) {
		this.vse_target_name = vse_target_name;
	}

	public String getVse_first_action_status() {
		return vse_first_action_status;
	}

	public void setVse_first_action_status(String vse_first_action_status) {
		this.vse_first_action_status = vse_first_action_status;
	}

	public String getVse_second_action_status() {
		return vse_second_action_status;
	}

	public void setVse_second_action_status(String vse_second_action_status) {
		this.vse_second_action_status = vse_second_action_status;
	}

	public String getAlert_description() {
		return alert_description;
	}

	public void setAlert_description(String alert_description) {
		this.alert_description = alert_description;
	}
	
	public String getanalyzer_rule_name() {
		return analyzer_rule_name;
	}

	public void setAnalyzer_rule_name(String analyzer_rule_name) {
		this.analyzer_rule_name = analyzer_rule_name;
	}
	public String getVse_sp() {
		return vse_sp;
	}

	public void setVse_sp(String vse_sp) {
		this.vse_sp = vse_sp;
	}
}
