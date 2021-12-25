package com.fedex.gccr.McAfeejdbcapp;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.TimeUnit;

import org.apache.kafka.common.errors.RecordTooLargeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.stream.messaging.Source;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageHandlingException;
import org.springframework.messaging.support.MessageBuilder;

import com.google.gson.Gson;
import com.microsoft.sqlserver.jdbc.SQLServerDataSource;

public class McAfeeEpoReaderClient {
	private final Logger logger 		= LoggerFactory.getLogger("mcafee_reader");
	private final Logger errorLogger 	= LoggerFactory.getLogger("mcafee_reader_errors");
	private final Logger autoIdTracker	= LoggerFactory.getLogger("autoID_tracker");
	//private final int retries;
	private final String sqlQuery;
	private SQLServerDataSource ds;
	private final int delayBetweenRequests;
	private final Source source;
    
	McAfeeEpoReaderClient(Source source, SQLServerDataSource ds, int retries, String sqlQuery, int delayBetweenRequests){
		this.source 				= source;
		//this.retries 				= retries;
		this.sqlQuery 				= sqlQuery;
		this.ds 					= ds;
		this.delayBetweenRequests 	= delayBetweenRequests;
	}
	public void getData(String autoID) {
		String latestID = new String();
		Gson gson 		= new Gson();
		
		try (Connection con = ds.getConnection(); Statement stmt = con.createStatement();) {
        	do {
        		String latestQuery = sqlQuery + autoID + " ORDER BY [EPOEvents].[AutoID] ASC"; 
          		logger.info("Run next Query for epoData");
                ResultSet rs 	= stmt.executeQuery(latestQuery);
                int resultCount	= 0;
                // Iterate through the data in the result set.
                while (rs.next()) {
                    EpoData epoData = new EpoData (rs.getString("timestamp"), rs.getString("AutoID"), rs.getString("signature"), rs.getString("threat_type"), rs.getString("signature_id"), rs.getString("category"), rs.getString("severity_id"), rs.getString("event_description"), rs.getString("detected_timestamp"), rs.getString("file_name"), rs.getString("detection_method"), rs.getString("vendor_action"), rs.getString("threat_handled"), rs.getString("logon_user"), rs.getString("user"), rs.getString("dest_nt_domain"), rs.getString("dest_dns"), rs.getString("dest_nt_host"), rs.getString("fqdn"), rs.getString("dest_ip"), rs.getString("dest_netmask"), rs.getString("dest_mac"), rs.getString("os"), rs.getString("sp"), rs.getString("os_version"), rs.getString("os_build"), rs.getString("timezone"), rs.getString("src_dns"), rs.getString("src_ip"), rs.getString("src_mac"), rs.getString("process"), rs.getString("url"), rs.getString("source_logon_user"), rs.getString("is_laptop"), rs.getString("product"), rs.getString("product_version"), rs.getString("engine_version"), rs.getString("dat_version"), rs.getString("vse_dat_version"), rs.getString("vse_engine64_version"), rs.getString("vse_engine_version"), rs.getString("vse_hotfix"), rs.getString("vse_product_version"), rs.getString("vse_source_file_hash"), rs.getString("vse_parent_process_hash"), rs.getString("vse_source_process_hash"), rs.getString("vse_target_file_hash"), rs.getString("vse_source_file_path"), rs.getString("vse_source_description"), rs.getString("vse_target_path"), rs.getString("vse_target_name"), rs.getString("vse_first_action_status"), rs.getString("vse_second_action_status"), rs.getString("alert_description"), rs.getString("analyzer_rule_name"), rs.getString("vse_sp"));
                    String epoDataJson = gson.toJson(epoData);
                    logger.debug(epoDataJson);
                    sendMessageToKafka(epoDataJson);
                    autoIdTracker.info(rs.getString("AutoID"));
                    latestID = rs.getString("AutoID"); 
                    resultCount++;
                }
                if(!(latestID.isEmpty())){
                	autoID=latestID; 
                }
                logger.info("Result Count from last query: " +resultCount); 
        		logger.info("Delay "+delayBetweenRequests+ "ms till next DB query");
        		TimeUnit.MILLISECONDS.sleep(delayBetweenRequests);
        	}while (!(latestID.isEmpty()));
			
        }catch (SQLException e){
            errorLogger.error(e.getMessage());
        }catch (InterruptedException e) {
			errorLogger.error(e.getMessage());
		}catch (Exception ex) {
        	errorLogger.error(ex.getMessage());
        }

    	//return latestID;
	}
	
	public void sendMessageToKafka(String msg) {
		try {
			Message<String> message = MessageBuilder.withPayload(msg).build();
			logger.debug("Payload of the Message to be sent = " + message.getPayload().toString());
			source.output().send(message);
		} catch (MessageHandlingException ex) {
			errorLogger.error("Message Handling Exception: " + ex.getMessage());
		} catch (RecordTooLargeException recordToLarge) {
			recordToLarge.printStackTrace();
			errorLogger.error("Record too large exception: " + recordToLarge.getMessage());
		} catch (Exception e) {
			errorLogger.error(e.getMessage());
		}
	}
	
	
}
