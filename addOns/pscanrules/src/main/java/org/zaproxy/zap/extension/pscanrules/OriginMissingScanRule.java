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
 * Checks web requests for presence of Origin header
 * 
 * @author Ales Repas
 */
public class OriginMissingScanRule extends PluginPassiveScanner {

	/** Prefix for internationalised messages used by this rule */
	private static final String MESSAGE_PREFIX = "pscanrules.originmissing.";

	public static final String ORIGIN = "Origin";

	private static final Map<String, String> ALERT_TAGS = CommonAlertTag.toMap(CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
			CommonAlertTag.OWASP_2017_A05_BROKEN_AC);

	private static final int PLUGIN_ID = 10178;

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		List<String> origin = msg.getRequestHeader().getHeaderValues(ORIGIN);
		String baseUrl = msg.getRequestHeader().getURI().toString();
		boolean missingOrigin = origin.isEmpty();
		if (missingOrigin) {
			this.raiseAlert(msg, id, missingOrigin);
			return;
		}
		String originUrl = origin.get(0);
		int oLen = originUrl.length();
		int bLen = baseUrl.length();
		String longerUrl = baseUrl;
		String shorterUrl = originUrl;
		if (oLen >= bLen) {
			longerUrl = originUrl;
			shorterUrl = baseUrl;
		}
		if (!longerUrl.contains(shorterUrl)) {
			this.raiseAlert(msg, id, missingOrigin);
		}
	}

	private void raiseAlert(HttpMessage msg, int id, boolean missingOrigin) {
		String issue = getName(missingOrigin);

		newAlert().setName(issue).setRisk(getRisk(missingOrigin)).setConfidence(Alert.CONFIDENCE_MEDIUM)
				.setDescription(getDescription(missingOrigin)).setParam(ORIGIN).setSolution(getSolution(missingOrigin))
				.setReference(getReference()).setCweId(getCweId()).setWascId(getWascId()).raise();
	}

	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}

	public String getName(boolean missingOrigin) {
		if (missingOrigin) {
			return Constant.messages.getString(MESSAGE_PREFIX + "name");
		}
		return Constant.messages.getString(MESSAGE_PREFIX + "name.inc");
	}

	public String getDescription(boolean missingOrigin) {
		if (missingOrigin) {
			return Constant.messages.getString(MESSAGE_PREFIX + "desc");
		}
		return Constant.messages.getString(MESSAGE_PREFIX + "desc.inc");
	}

	public String getSolution(boolean missingOrigin) {
		if (missingOrigin) {
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
		return 1385; // CWE Id 1385
	}

	public int getWascId() {
		return 9; // WASCId 9 - CSRF
	}

	public int getRisk(boolean missingOrigin) {
		if (missingOrigin) {
			return Alert.RISK_LOW;
		}
		return Alert.RISK_INFO;
	}

	@Override
	public int getPluginId() {
		return PLUGIN_ID;
	}
}
