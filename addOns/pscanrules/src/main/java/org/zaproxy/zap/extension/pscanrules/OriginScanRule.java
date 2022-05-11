package org.zaproxy.zap.extension.pscanrules;

import java.util.List;
import java.util.Map;
import net.htmlparser.jericho.Source;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Checks web requests for presence of Origin header
 * 
 */
public class OriginScanRule extends PluginPassiveScanner {

	/** Prefix for internationalised messages used by this rule */
	private static final String MESSAGE_PREFIX = "pscanrules.origin.";

	private static final String ORIGIN = "Origin";

	private static final Map<String, String> ALERT_TAGS = CommonAlertTag.toMap(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG);

	private static final int PLUGIN_ID = 10178;

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		List<String> origin = msg.getRequestHeader().getHeaderValues(ORIGIN);
		URI baseURI = msg.getRequestHeader().getURI();
		
		if (origin.isEmpty()) {
			return; // nothing to check
		}
		
		// check if scope is equal
		URI origURI;
		String originVal = origin.get(0);
		try {
			origURI = new URI(originVal, false);
		} catch (URIException | NullPointerException e) {
			return;
		}
		try {
		if (!baseURI.getHost().equals(origURI.getHost())) {
				this.raiseAlert(msg, id,  "Base URI: " + baseURI.getHost() + "\nrOrigin URI: " + origURI.getHost());
			}
		} catch (URIException e) {
			return;
		}
	}

	/**
	 * Raises alert
	 * @param msg HttpMessage
	 * @param id int
	 * @param String param
	 */
	private void raiseAlert(HttpMessage msg, int id, String param) {
		// creates new alert
		
		newAlert()
			.setName(getName())
			.setRisk(getRisk())
			.setConfidence(Alert.CONFIDENCE_MEDIUM)
			.setDescription(getDescription())
			.setParam(ORIGIN)
			.setOtherInfo(param)
			.setSolution(getSolution())
			.setReference(getReference())
			.setCweId(getCweId())
			.setWascId(getWascId())
			.raise();
	}

	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}

	public String getDescription() {
		return Constant.messages.getString(MESSAGE_PREFIX + "desc");
	}

	public String getSolution() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln");
	}

	public String getReference() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}

	@Override
	public Map<String, String> getAlertTags() {
		return ALERT_TAGS;
	}

	public int getCweId() {
		return 1385; // CWE Id 1385
	}

	public int getWascId() {
		return 9; // WASCId 9 - CSRF
	}

	public int getRisk() {
		return Alert.RISK_INFO;
	}

	@Override
	public int getPluginId() {
		return PLUGIN_ID;
	}
}
