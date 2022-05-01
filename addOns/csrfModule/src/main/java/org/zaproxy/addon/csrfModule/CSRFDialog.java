/**
 * 
 */
package org.zaproxy.addon.csrfModule;

import java.awt.Dimension;
import java.awt.Frame;
import java.util.ArrayList;
import java.util.List;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.view.StandardFieldsDialog;

/**
 * @author Ales Repas
 * Window
 */
public class CSRFDialog extends StandardFieldsDialog {

	private static final long serialVersionUID = 1L;

	private static final String FIELD_START = "csrfModule.dialog.start";
    private static final String FIELD_CONTEXT = "csrfModule.dialog.context";
    private static final String FIELD_USER = "csrfModule.dialog.user";

	private final ExtensionUserManagement extUserMgmt;

	private Target target;

	private ExtensionCSRF extension = null;

	public CSRFDialog(ExtensionCSRF ext, Frame owner, Dimension dim) {
		super(owner, ExtensionCSRF.PREFIX + ".dialog.title", dim);
		this.extension = ext;
		this.extUserMgmt = Control.getSingleton().getExtensionLoader().getExtension(ExtensionUserManagement.class);
	}

	/**
	 * Create window
	 * @param target
	 */
	public void init(Target target) {
		if (target != null) {
			this.target = target;
		}

		this.removeAllFields();
		
		this.addTargetSelectField(FIELD_START, this.target, true, false);
        this.addComboField(FIELD_CONTEXT, new String[] {}, "");
        this.addComboField(FIELD_USER, new String[] {}, "");
        getField(FIELD_CONTEXT).setEnabled(false);
        getField(FIELD_USER).setEnabled(false);
        this.addFieldListener(FIELD_CONTEXT, e -> setUsers());
        if (target != null) {
            this.targetSelected(FIELD_START, this.target);
            this.setUsers();
        } else {
            getField(FIELD_CONTEXT).setEnabled(false);
            getField(FIELD_USER).setEnabled(false);
        }

		this.pack();
	}
	
    private Context getSelectedContext() {
        String ctxName = this.getStringValue(FIELD_CONTEXT);
        if (this.extUserMgmt != null && !this.isEmptyField(FIELD_CONTEXT)) {
            Session session = Model.getSingleton().getSession();
            return session.getContext(ctxName);
        }
        return null;
    }

    private User getSelectedUser() {
        Context context = this.getSelectedContext();
        if (context != null && extUserMgmt != null) {
            String userName = this.getStringValue(FIELD_USER);
            List<User> users =
                    this.extUserMgmt.getContextUserAuthManager(context.getId()).getUsers();
            for (User user : users) {
                if (userName.equals(user.getName())) {
                    return user;
                }
            }
        }
        return null;
    }

    private void setUsers() {
        Context context = this.getSelectedContext();
        List<String> userNames = new ArrayList<>();
        if (context != null && extUserMgmt != null) {
            List<User> users = extUserMgmt.getContextUserAuthManager(context.getId()).getUsers();
            userNames.add("");
            for (User user : users) {
                userNames.add(user.getName());
            }
        }
        this.setComboFields(FIELD_USER, userNames, "");
        this.getField(FIELD_USER).setEnabled(userNames.size() > 1);
    }
    
    @Override
    public void targetSelected(String field, Target target) {
        List<String> ctxNames = new ArrayList<>();
        if (target != null) {
            this.target = target;
            if (target.getStartNode() != null) {
                Session session = Model.getSingleton().getSession();
                List<Context> contexts = session.getContextsForNode(target.getStartNode());
                ctxNames.add("");
                for (Context context : contexts) {
                    ctxNames.add(context.getName());
                }

            } else if (target.getContext() != null) {
                ctxNames.add(target.getContext().getName());
            }
        }
        this.setComboFields(FIELD_CONTEXT, ctxNames, "");
        this.getField(FIELD_CONTEXT).setEnabled(ctxNames.size() > 1);
    }
	
    @Override
    public String getSaveButtonText() {
        return Constant.messages.getString("csrfModule.dialog.scan");
    }

	public void reset() {
		target = null;

		init(target);
		repaint();
	}

	@Override
	public void save() {

	}

	@Override
	public String validateFields() {

		return null;
	}

}
