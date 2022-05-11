/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.ascanrules;

import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;

/**
 * This rule checks tampering of origin in web requests
 *
 */
public class RefererScanRule extends AbstractAppParamPlugin {

    private static final String MESSAGE_PREFIX = "ascanrules.referer.";

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG);

    private static final String FAKE_WEBSITE = "https://fakewebsite.com";

    private static Logger log = LogManager.getLogger(RefererScanRule.class);

    @Override
    public int getId() {
        return 40278;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
		return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }

    @Override
    public String getSolution() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    /**
     * Raises alert
     * @param msg HttpMessage
     * @param param String
     */
	private void raiseAlert(HttpMessage msg, String param, String cause) {	
				newAlert()
					.setName(getName())
					.setRisk(getRisk())
					.setConfidence(Alert.CONFIDENCE_MEDIUM)
					.setParam(HttpHeader.REFERER)
					.setAttack("Cross Site Request Forgery")
					.setMessage(msg)
					.setDescription(getDescription() + " " + cause)
					.raise();
	}

    @Override
    public void scan(HttpMessage sourceMsg, String param, String value) {
    	
        try {
        	
            int retCode;
            int verifyCode;

            // is referrer present in header?
            HttpMessage msg = sourceMsg.cloneRequest();
            
            log.debug("REFERER: " + msg.getRequestHeader().toString());
            
            try {
                sendAndReceive(msg);
            } catch (URIException e) {
                log.debug("Failed to send HTTP message, cause: {}", e.getMessage());
                return;
            }

            if (isStop()) {
                return;
            }          

            List<String> referer = msg.getRequestHeader().getHeaderValues(HttpHeader.REFERER);       
            
            if(referer.isEmpty()) {
         	   // raiseAlert(msg, param, "Referer was not found during active testing."); // referrer was not found. Do not raise an alert, passive scan already did that
         	   return; // if referrer was not found, application doesn't react to its' tampering
            }
            verifyCode = msg.getResponseHeader().getStatusCode(); // save status code for testing
            
            // delete referrer in header and check
            HttpMessage msg2 = sourceMsg.cloneRequest();
            msg2.getRequestHeader().setHeader(HttpHeader.REFERER, null);
            
            try {
                sendAndReceive(msg2);
            } catch (URIException e) {
                log.debug("Failed to send HTTP message, cause: {}", e.getMessage());
                return;
            }

            if (isStop()) {
                return;
            }       
            
            retCode = msg2.getResponseHeader().getStatusCode();
            
            if(verifyCode == retCode) {
         	    raiseAlert(sourceMsg, param, "Referer was removed, website didn't react to change.");
            }
            
            // set origin to fake site header and check
            HttpMessage msg3 = sourceMsg.cloneRequest();
            msg3.getRequestHeader().setHeader(HttpHeader.REFERER, FAKE_WEBSITE);
            
            try {
                sendAndReceive(msg3);
            } catch (URIException e) {
                log.debug("Failed to send HTTP message, cause: {}", e.getMessage());
                return;
            }

            if (isStop()) {
                return;
            }       
            
            retCode = msg3.getResponseHeader().getStatusCode();
            
            if(verifyCode == retCode) {
         	    raiseAlert(sourceMsg, param, "Referer was set to fake website, website didn't react to change.");
            }
            
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }
    
    /**
     * Copies request header without referrer present
     * @param h HttpRequestHeader
     * @return HttpRequestHeader
     */ /*
    private HttpRequestHeader copyRequestNoReferer(HttpRequestHeader h) {
    	HttpRequestHeader ret = new HttpRequestHeader();
    	List<HttpHeaderField> fields = h.getHeaders();
    	for(HttpHeaderField field : fields) {
    		if(!field.getName().equals(HttpHeader.REFERER)) {
    			ret.addHeader(field.getName(), field.getValue());
    		}
    	}
    	try {
			ret.setURI(h.getURI());
		} catch (URIException e) {
            log.error(e.getMessage(), e);
		}
    	return ret;
    } */

    @Override
    public int getRisk() {
        return Alert.RISK_LOW;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public int getCweId() {
		return 293; // CWE Id 293
    }

    @Override
    public int getWascId() {
		return 9; // WASCId 9 - CSRF
    }
}
