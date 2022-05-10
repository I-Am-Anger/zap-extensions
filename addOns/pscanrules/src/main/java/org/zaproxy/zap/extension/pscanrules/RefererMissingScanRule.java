package org.zaproxy.zap.extension.pscanrules;

import java.util.List;
import java.util.Map;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Checks web requests for presence of Referer header
 * 
 *
 */
public class RefererMissingScanRule extends PluginPassiveScanner {

	/** Prefix for internationalised messages used by this rule */
	private static final String MESSAGE_PREFIX = "pscanrules.referermissing.";

	private static final Map<String, String> ALERT_TAGS = CommonAlertTag.toMap(CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
			CommonAlertTag.OWASP_2017_A05_BROKEN_AC);

	private static final int PLUGIN_ID = 10278;

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		List<String> referer = msg.getRequestHeader().getHeaderValues(HttpHeader.REFERER);
		String baseUrl = msg.getRequestHeader().getURI().toString();
		boolean missingReferer = referer.isEmpty();
		if (missingReferer) {
			this.raiseAlert(msg, id, missingReferer);
			return;
		}
		String refererUrl = referer.get(0);
		int oLen = refererUrl.length();
		int bLen = baseUrl.length();
		String longerUrl = baseUrl;
		String shorterUrl = refererUrl;
		if (oLen >= bLen) {
			longerUrl = refererUrl;
			shorterUrl = baseUrl;
		}
		if (!longerUrl.contains(shorterUrl)) {
			this.raiseAlert(msg, id, missingReferer);
		}
	}

	private void raiseAlert(HttpMessage msg, int id, boolean missingReferer) {
		String issue = getName(missingReferer);

		newAlert().setName(issue).setRisk(getRisk(missingReferer)).setConfidence(Alert.CONFIDENCE_MEDIUM)
				.setDescription(getDescription(missingReferer)).setParam(HttpHeader.REFERER)
				.setSolution(getSolution(missingReferer)).setReference(getReference()).setCweId(getCweId())
				.setWascId(getWascId()).raise();
	}

	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}

	public String getName(boolean missingReferer) {
		if (missingReferer) {
			return Constant.messages.getString(MESSAGE_PREFIX + "name");
		}
		return Constant.messages.getString(MESSAGE_PREFIX + "name.inc");
	}

	public String getDescription(boolean missingReferer) {
		if (missingReferer) {
			return Constant.messages.getString(MESSAGE_PREFIX + "desc");
		}
		return Constant.messages.getString(MESSAGE_PREFIX + "desc.inc");
	}

	public String getSolution(boolean missingReferer) {
		if (missingReferer) {
			return Constant.messages.getString(MESSAGE_PREFIX + "soln");
		}
		return Constant.messages.getString(MESSAGE_PREFIX + "soln.inc");
	}

	public String getReference() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}

	@Override
	public Map<String, String> getAlertTags() {
		return ALERT_TAGS;
	}

	public int getCweId() {
		return 293; // CWE Id 1385
	}

	public int getWascId() {
		return 9; // WASCId 9 - CSRF
	}

	public int getRisk(boolean missingReferer) {
		if (missingReferer) {
			return Alert.RISK_MEDIUM;
		}
		return Alert.RISK_INFO;
	}

	@Override
	public int getPluginId() {
		return PLUGIN_ID;
	}
}
