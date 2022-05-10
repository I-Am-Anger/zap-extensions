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

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.SourceSinkUtils;
import org.zaproxy.zap.extension.ascanrules.httputils.HtmlContext;
import org.zaproxy.zap.extension.ascanrules.httputils.HtmlContextAnalyser;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

public class OriginScanRule extends AbstractAppParamPlugin {

    private static final String MESSAGE_PREFIX = "ascanrules.origin.";

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG);

    private static final String FAKE_WEBSITE = "https://fakewebsite.com";
	private static final String ORIGIN = "Origin";

    private static Logger log = LogManager.getLogger(OriginScanRule.class);

    @Override
    public int getId() {
        return 40178;
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
					.setParam(ORIGIN)
					.setAttack("Cross Site Request Forgery")
					.setMessage(msg)
					.setDescription(getDescription() + " " + cause)
					.raise();
	}

    @Override
    public void scan(HttpMessage sourceMsg, String param, String value) {
    	
    	// String report = "";
    	// boolean vuln = false;

        try {
        	
            int retCode;
            int verifyCode;
            
            // is origin present in header?
            HttpMessage msg = sourceMsg.cloneRequest();
            
            try {
                sendAndReceive(msg, false);
            } catch (URIException e) {
                log.debug("Failed to send HTTP message, cause: {}", e.getMessage());
                return;
            }

            if (isStop()) {
                return;
            }       
            
            String origin = msg.getRequestHeader().getHeader(ORIGIN);       
            verifyCode = msg.getResponseHeader().getStatusCode(); // save status code for testing
            
            if(origin == null) {
            	// vuln = true;
            	// report += "Origin was not found during active testing.\n";
         	    raiseAlert(msg, param, "Origin was not found during active testing."); // Origin was not found in active testing
            }
            
            // delete origin in header and check
            HttpMessage msg2 = sourceMsg.cloneRequest();
            msg2.setRequestHeader(copyRequestNoOrigin(sourceMsg.getRequestHeader()));
            
            try {
                sendAndReceive(msg2, false);
            } catch (URIException e) {
                log.debug("Failed to send HTTP message, cause: {}", e.getMessage());
                return;
            }

            if (isStop()) {
                return;
            }       
            
            retCode = msg2.getResponseHeader().getStatusCode();
            
            if(verifyCode == retCode) {
            	// vuln = true;
            	// report += "Origin was removed, website didn't react to change.\n";
            	raiseAlert(msg2, param, "Origin was removed, website didn't react to change.");
            }
            
            // set origin to fake website header and check
            HttpMessage msg3 = sourceMsg.cloneRequest();
            msg3.setRequestHeader(copyRequestNoOrigin(sourceMsg.getRequestHeader()));
            msg3.getRequestHeader().addHeader(ORIGIN, FAKE_WEBSITE);
            
            try {
                sendAndReceive(msg3, false);
            } catch (URIException e) {
                log.debug("Failed to send HTTP message, cause: {}", e.getMessage());
                return;
            }

            if (isStop()) {
                return;
            }       
            
            retCode = msg3.getResponseHeader().getStatusCode();
            
            if(verifyCode == retCode) {
            	// vuln = true;
            	// report += "Origin was set to fake website, website didn't react to change.\n";
            	raiseAlert(msg3, param, "Origin was set to fake website, website didn't react to change.");
            }
            
            /* if(vuln) {
            	raiseAlert(msg, param, report);
            } */
            
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }
    
    /**
     * Copies request header without origin present
     * @param h HttpRequestHeader
     * @return HttpRequestHeader
     */
    private HttpRequestHeader copyRequestNoOrigin(HttpRequestHeader h) {
    	HttpRequestHeader ret = new HttpRequestHeader();
    	List<HttpHeaderField> fields = h.getHeaders();
    	for(HttpHeaderField field : fields) {
    		if(!field.getName().equals(ORIGIN)) {
    			ret.addHeader(field.getName(), field.getValue());
    		}
    	}
    	try {
			ret.setURI(h.getURI());
		} catch (URIException e) {
            log.error(e.getMessage(), e);
		}
    	return ret;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public int getCweId() {
        return 1385;
    }

    @Override
    public int getWascId() {
        return 9;
    }
}
