package com.google.apigee.edgecallouts.util;

import com.apigee.flow.message.MessageContext;

public class Debug {
    private MessageContext msgCtx;
    private String prefix;

    public Debug(MessageContext msgCtx, String prefix) {
        this.msgCtx = msgCtx;
        this.prefix = prefix;
    }

    public void setVar(String name, String value) {
        msgCtx.setVariable(prefix + ".debug."+name, value);
    }
}