/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.addon.csrfModule;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

/**
 * A pop up menu item shown in components that contain HTTP messages, it shows an internationalised
 * message with the request-uri of the HTTP message.
 *
 * @see HttpMessageContainer
 */

public class RightClickMsgMenu extends PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = 1L;

    @SuppressWarnings("unused")
    private ExtensionCSRF extension;

    public RightClickMsgMenu(ExtensionCSRF ext, String label) {
        super(label);
        this.extension = ext;
    }

    @Override
    public void performAction(HttpMessage msg) {
    }

    @Override
    public boolean isEnableForInvoker(Invoker invoker, HttpMessageContainer httpMessageContainer) {
        return true;
    }

    @Override
    public boolean isSafe() {
        return true;
    }
}
