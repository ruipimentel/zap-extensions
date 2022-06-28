/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.processors;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.TreeSet;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.anticsrf.AntiCsrfToken;
import org.zaproxy.zap.extension.anticsrf.ExtensionAntiCSRF;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzResult;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessor;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerTaskProcessorUtils;

// Custom RUI:
import java.util.ArrayList;
import java.net.HttpCookie;

public class AntiCsrfHttpFuzzerMessageProcessor implements HttpFuzzerMessageProcessor {

    private static final String NAME =
            Constant.messages.getString("fuzz.httpfuzzer.processor.acsrffuzz.message.name");

    private static final String ERROR_MESSAGE =
            Constant.messages.getString("fuzz.httpfuzzer.processor.acsrffuzz.message.error");

    private ExtensionAntiCSRF extensionAntiCSRF;
    private AntiCsrfToken acsrfToken;
    private boolean showTokenRequests;
    
    // Custom RUI:
    private String sessionKey;
    private String sessionToken;
    private String antiCsrfToken;

    public AntiCsrfHttpFuzzerMessageProcessor(
            ExtensionAntiCSRF extensionAntiCSRF,
            AntiCsrfToken acsrfToken,
            boolean showTokenRequests) {
        if (acsrfToken == null) {
            throw new IllegalArgumentException("Parameter acsrfToken must not be null.");
        }
        this.extensionAntiCSRF = extensionAntiCSRF;
        this.acsrfToken = acsrfToken;
        this.showTokenRequests = showTokenRequests;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public HttpMessage processMessage(HttpFuzzerTaskProcessorUtils utils, HttpMessage message) {
        HttpMessage tokenMessage = this.acsrfToken.getMsg().cloneAll();

        // Custom RUI:
        // Sets up the session in the token ("Anti-CSRF Token Refresh") message:
        setSessionToken(tokenMessage);

        // Custom RUI:
        // TO DO: REFACTOR! We must not hardcode the method as "GET", but rather
        // offer a proper GUI element for the selection of both URL and method:
        tokenMessage.getRequestHeader().setMethod("GET");

        if (!utils.sendMessage(tokenMessage)) {
            utils.increaseErrorCount(ERROR_MESSAGE);
            return message;
        }

        if (showTokenRequests) {
            utils.addMessageToResults(NAME, tokenMessage, null, null);
        }

        // If we've got a token value here then the AntiCSRF extension must have been registered
        String tokenValue = extensionAntiCSRF.getTokenValue(tokenMessage, acsrfToken.getName());

        // Custom RUI:
        // Detects "Set-cookie" HTTP Response Headers:
        detectSessionChange(tokenMessage);

        // Custom RUI:
        // Sets up the session in the fuzzed message:
        setSessionToken(message);

        if (tokenValue == null) {
            tokenValue = antiCsrfToken;
        }
        
        if (tokenValue != null) {
            antiCsrfToken = tokenValue;
            // Replace token value - only supported in the body right now
            String replaced = message.getRequestBody().toString();
            try {
                replaced =
                        replaced.replace(
                                URLEncoder.encode(
                                        acsrfToken.getValue(), StandardCharsets.UTF_8.name()),
                                URLEncoder.encode(tokenValue, StandardCharsets.UTF_8.name()));
            } catch (UnsupportedEncodingException ignore) {
                // UTF-8 is a standard charset
            }
            message.setRequestBody(replaced);

            // Correct the content length for the above changes
            message.getRequestHeader().setContentLength(message.getRequestBody().length());
        }

        return message;
    }

    @Override
    public boolean processResult(HttpFuzzerTaskProcessorUtils utils, HttpFuzzResult fuzzResult) {
        // Custom RUI:
        detectSessionChange(fuzzResult.getHttpMessage());
        return true;
    }

    /**
     * Sets up the session cookie key-value pair in the specified message,
     * unless there is no session token detected so far in the current execution
     * of the fuzzer.
     *
     * @param message Message where the session cookie will be set up.
     */
    private void setSessionToken(HttpMessage message) {
        if (sessionToken != null) {
            ArrayList<HttpCookie> cookies = new ArrayList<HttpCookie>();

            // Creates a session key-value pair using the detected settings:
            cookies.add(new HttpCookie(sessionKey, sessionToken));

            // Sets up the session in the specified HTTP request:
            message.getRequestHeader().setCookies(cookies);
        }
    }

    /**
     * Detects a "Set-cookie" HTTP response header in the specified message.
     *
     * @param message Message where the session cookie will be set up.
     */
    private void detectSessionChange(HttpMessage message) {
        // Custom RUI:
        if (message != null) {
            HttpResponseHeader responseHeader = message.getResponseHeader();
            if (responseHeader != null) {
                TreeSet<HtmlParameter> cookieParams = responseHeader.getCookieParams();
                if (cookieParams != null) {
                    for (Iterator<HtmlParameter> iterator = cookieParams.iterator(); iterator.hasNext();) {
                        HtmlParameter htmlParameter = iterator.next();
                        // TO DO: REFACTOR! We must look for any of the possible
                        // session keys, not only for "session" specifically:
                        if (htmlParameter.getName().compareTo("session") == 0) {
                            sessionKey = htmlParameter.getName();
                            sessionToken = htmlParameter.getValue();
                        }
                    }
                }
            }
        }
    }
}
