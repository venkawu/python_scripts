package com.fedex.gccr.McAfeejdbcapp;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.stream.annotation.EnableBinding;
import org.springframework.cloud.stream.messaging.Source;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.microsoft.sqlserver.jdbc.SQLServerDataSource;

@EnableBinding(Source.class)
@Configuration
@EnableScheduling
@Component
public class McAfeeEpoReaderScheduler {
	private final Logger logger 		= LoggerFactory.getILoggerFactory().getLogger("mcafee_reader");
	
	@Autowired
	private Source source;
	
	@Value("${mcafee.db.server}")
	private String dbServer;
	
	@Value("${mcafee.db.port}")
	private int dbPort;
	
	@Value("${mcafee.db.retries}")
	private int retries;
	
	@Value("${mcafee.db.user}")
	private String user;
	
	@Value("${mcafee.db.password}")
	private String password;
	
	@Value("${mcafee.db.sqlStatement}")
	private String sqlStatmt;
	
	@Value("${mcafee.db.autoID}")
	private String autoID;
	
	@Value("${mcafee.db.delayBetweenRequests}")
	private int delayBetweenRequests;
	
	@Value("${mcafee.db.autoIDLogFile}")
	private String autoIDLogFile;
			
	//@Scheduled(cron = "${cron.expression}")
    //@Scheduled(initialDelay=10000, fixedDelayString  = "${schedule.interval}")
	@Scheduled(initialDelay=10000, fixedDelayString  = "${schedule.interval}")
	public void getMcAfeeEvents() {
		String strLine 			= new String();
		String lastAutoID 		= new String();
		SQLServerDataSource ds 	= new SQLServerDataSource();
        ds.setUser(user);
        ds.setPassword(password);
        ds.setServerName(dbServer);
        ds.setPortNumber(dbPort);
        
        logger.debug("User: " + user);
        //logger.debug("PW: " + password);
        logger.debug("Server:" + dbServer+":"+dbPort);
        
        try {
            BufferedReader br = new BufferedReader(new FileReader(autoIDLogFile));
            while (br.ready())
            {
               strLine = br.readLine();
               lastAutoID=strLine;
            }
            br.close();
       } catch (FileNotFoundException e) {
           System.err.println("File not found");
   
       } catch (IOException e) {
           System.err.println("Unable to read the file.");
       }
        
        McAfeeEpoReaderClient readerClient = new McAfeeEpoReaderClient(source,  ds, retries, sqlStatmt, delayBetweenRequests);
        
        if(!(lastAutoID.isEmpty())) {
        	logger.info("_____RESTARTING____");
			logger.debug(lastAutoID);
			readerClient.getData(lastAutoID);
        }else {
        	readerClient.getData(autoID);
        }
	}
}
