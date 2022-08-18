package com.google.apigee.edgecallouts;
 
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Base64.Decoder;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
 
import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.Message;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.edgecallouts.util.VarResolver;

public class AlexaVerifierCallout implements Execution {

    private static final Map<String, X509Certificate> CERTIFICATE_CACHE = new ConcurrentHashMap<>();
    private static final Decoder base64decoder = Base64.getDecoder();

    private static final String VALID_SIGNING_CERT_CHAIN_URL_HOST_NAME = "s3.amazonaws.com";
    private static final String VALID_SIGNING_CERT_CHAIN_URL_PATH_PREFIX = "/echo.api/";
    private static final String VALID_SIGNING_CERT_CHAIN_PROTOCOL = "https";
    private static final int UNSPECIFIED_SIGNING_CERT_CHAIN_URL_PORT_VALUE = -1;

    public static final String CALLOUT_VAR_PREFIX = "apigee-alexa-verifier-callout";
    public static final String MESSAGE_VAR_PROP = "message-variable-ref";
    private static final String SIGNING_CERT_CHAIN_URL = "signature-cert-chain-url";
    private static final String REQUEST_SIGNATURE = "request-signature";
    private static final String REQUEST_SIGNATURE_VALIDATION_RESULT = "request-signature-val-result";
    private static final String REQUEST_BODY_TIMESTAMP = "request-body-timestamp";

    private static final Integer DOMAIN_NAME_SUBJECT_ALTERNATIVE_NAME_ENTRY = 2;
    private static final int CERT_RETRIEVAL_RETRY_COUNT = 5;
    private static final int DELAY_BETWEEN_RETRIES_MS = 500;
    private static final int HTTP_OK_RESPONSE_CODE = 200;

    private final Map properties;
	private ByteArrayOutputStream stdoutOS;
	private ByteArrayOutputStream stderrOS;
	private PrintStream stdout;
	private PrintStream stderr;

    public AlexaVerifierCallout(Map properties) throws UnsupportedEncodingException {
		this.properties = properties;
		this.stdoutOS = new ByteArrayOutputStream();
		this.stderrOS = new ByteArrayOutputStream();
		this.stdout = new PrintStream(stdoutOS, true, StandardCharsets.UTF_8.name());
		this.stderr = new PrintStream(stderrOS, true, StandardCharsets.UTF_8.name());
	}

    public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext)  {
    
        try {

            VarResolver vars = new VarResolver(messageContext, properties);
            
            verify(messageContext, vars);

            return ExecutionResult.SUCCESS;

        } catch (Error | Exception e) {
			e.printStackTrace(stderr);
			return ExecutionResult.SUCCESS;
		}
		finally {
			saveOutputs(messageContext);
		}
    
    }

    private void saveOutputs(MessageContext msgCtx) {
        msgCtx.setVariable(CALLOUT_VAR_PREFIX + ".info.stdout", new String(stdoutOS.toByteArray(), StandardCharsets.UTF_8));
        msgCtx.setVariable(CALLOUT_VAR_PREFIX + ".info.stderr", new String(stderrOS.toByteArray(), StandardCharsets.UTF_8));
        stdoutOS.reset();
        stderrOS.reset();
        }
        
        public void verify(final MessageContext messageContext, final VarResolver vars) {
        
            String messageVariable = vars.getProp(MESSAGE_VAR_PROP);
            Message msg = (Message) messageContext.getVariable(messageVariable);
        
            String messageBody = msg.getContent();
        
            String signingCertChainURLVariable = vars.getProp(SIGNING_CERT_CHAIN_URL);
            String signingCertificateChainUrl = messageContext.getVariable(signingCertChainURLVariable);
        
            String requestSignatureVariable = vars.getProp(REQUEST_SIGNATURE);
            String baseEncoded64Signature = messageContext.getVariable(requestSignatureVariable);

            String requestBodyTimestamp = vars.getProp(REQUEST_BODY_TIMESTAMP);
            String bodyTimestamp = messageContext.getVariable(requestBodyTimestamp);

            //REQUEST_BODY_TIMESTAMP
            
            String requestSignatureValResult = vars.getProp(REQUEST_SIGNATURE_VALIDATION_RESULT);
        
        
            if ((baseEncoded64Signature == null) || (signingCertificateChainUrl == null)) {
                messageContext.setVariable(requestSignatureValResult, false);
                throw new SecurityException(
                        "Missing signature/certificate for the provided skill request");
            }
        
            try {
                X509Certificate signingCertificate = CERTIFICATE_CACHE.get(signingCertificateChainUrl);
                if (signingCertificate != null && signingCertificate.getNotAfter().after(new Date())) {
                    /*
                     * check the before/after dates on the certificate are still valid for the present
                     * time
                     */
                    signingCertificate.checkValidity();
                } else {
                    signingCertificate = retrieveAndVerifyCertificateChain(signingCertificateChainUrl);
        
                    // if certificate is valid, then add it to the cache
                    CERTIFICATE_CACHE.put(signingCertificateChainUrl, signingCertificate);
                }
        
                // verify that the request was signed by the provided certificate
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initVerify(signingCertificate.getPublicKey());
                signature.update(messageBody.getBytes("UTF-8"));
                if (!signature.verify(base64decoder.decode(baseEncoded64Signature
                        .getBytes("UTF-8")))) {
                            messageContext.setVariable(requestSignatureValResult, false);
                    throw new SecurityException(
                            "Failed to verify the signature/certificate for the provided skill request");
                }

                // Verify request timestamp. "2022-08-05T18:38:06Z"
                SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX");
                Date bodyDate = simpleDateFormat.parse(bodyTimestamp);
                Date now = new Date(System.currentTimeMillis()); 
                Long diff = now.getTime() - bodyDate.getTime();
                long difference = TimeUnit.MILLISECONDS.toSeconds(diff);
                if(difference > 150L){
                    throw new SecurityException(
                            "Request is more than 150 seconds out of sync");
                }
                messageContext.setVariable(requestSignatureValResult, true);
            } catch (GeneralSecurityException | IOException | ParseException ex) {
                messageContext.setVariable(requestSignatureValResult, false);
                throw new SecurityException(
                        "Failed to verify the signature/certificate for the provided skill request",
                        ex);
            }
        }
        
        private X509Certificate retrieveAndVerifyCertificateChain(final String signingCertificateChainUrl) throws CertificateException {
            for (int attempt = 0; attempt <= CERT_RETRIEVAL_RETRY_COUNT; attempt++) {
                InputStream in = null;
                try {
                    HttpURLConnection connection =
                            (HttpURLConnection) getAndVerifySigningCertificateChainUrl(signingCertificateChainUrl).openConnection();
        
                    if (connection.getResponseCode() != HTTP_OK_RESPONSE_CODE) {
                        if (waitForRetry(attempt)) {
                            continue;
                        } else {
                            throw new CertificateException("Got a non-200 status code when retrieving certificate at URL: " + signingCertificateChainUrl);
                        }
                    }
        
                    in = connection.getInputStream();
                    CertificateFactory certificateFactory =
                            CertificateFactory.getInstance("X.509");
                    @SuppressWarnings("unchecked")
                    Collection<X509Certificate> certificateChain =
                            (Collection<X509Certificate>) certificateFactory.generateCertificates(in);
                    /*
                     * check the before/after dates on the certificate date to confirm that it is valid on
                     * the current date
                     */
                    X509Certificate signingCertificate = certificateChain.iterator().next();
                    signingCertificate.checkValidity();
        
                    // check the certificate chain
                    TrustManagerFactory trustManagerFactory =
                            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                    trustManagerFactory.init((KeyStore) null);
        
                    X509TrustManager x509TrustManager = null;
                    for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
                        if (trustManager instanceof X509TrustManager) {
                            x509TrustManager = (X509TrustManager) trustManager;
                        }
                    }
        
                    if (x509TrustManager == null) {
                        throw new IllegalStateException(
                                "No X509 TrustManager available. Unable to check certificate chain");
                    } else {
                        x509TrustManager.checkServerTrusted(
                                certificateChain.toArray(new X509Certificate[certificateChain.size()]),
                                "RSA");
                    }
        
                    /*
                     * verify Echo API's hostname is specified as one of subject alternative names on the
                     * signing certificate
                     */
                    if (!subjectAlernativeNameListContainsEchoSdkDomainName(signingCertificate
                            .getSubjectAlternativeNames())) {
                        throw new CertificateException(
                                "The provided certificate is not valid for the ASK SDK");
                    }
        
                    return signingCertificate;
                } catch (IOException e) {
                    if (!waitForRetry(attempt)) {
                        throw new CertificateException("Unable to retrieve certificate from URL: " + signingCertificateChainUrl, e);
                    }
                } catch (Exception e) {
                    throw new CertificateException("Unable to verify certificate at URL: " + signingCertificateChainUrl, e);
                } finally {
                    if (in != null) {
                        try{in.close();} catch (Exception ex){//IGNORED
                        }
                    }
                }
            }
            throw new RuntimeException("Unable to retrieve signing certificate due to an unhandled exception");
        }
        
        private boolean subjectAlernativeNameListContainsEchoSdkDomainName(
                final Collection<List<?>> subjectAlternativeNameEntries) {
            for (List<?> entry : subjectAlternativeNameEntries) {
                // first ensure that the subject alternative entry is in the expected form
                if (entry.get(0) instanceof Integer && entry.get(1) instanceof String) {
                    /*
                     * if the entry is for a domain name and that domain name matches the domain name
                     * for the echo sdk then return true
                     */
                    if (DOMAIN_NAME_SUBJECT_ALTERNATIVE_NAME_ENTRY.equals(entry.get(0))
                            && "echo-api.amazon.com".equals((entry.get(1)))) {
                        return true;
                    }
                }
            }
            return false;
        }
        
        private boolean waitForRetry(final int attempt) {
            if (attempt < CERT_RETRIEVAL_RETRY_COUNT) {
                try {
                    Thread.sleep(DELAY_BETWEEN_RETRIES_MS);
                    return true;
                } catch (InterruptedException ex) {
                    throw new RuntimeException("Interrupted while waiting for certificate retrieval retry attempt", ex);
                }
            } else {
                return false;
            }
        }
        
        static URL getAndVerifySigningCertificateChainUrl(final String signingCertificateChainUrl)
                throws CertificateException {
            try {
                URL url = new URI(signingCertificateChainUrl).normalize().toURL();
                // Validate the hostname
                if (!VALID_SIGNING_CERT_CHAIN_URL_HOST_NAME.equalsIgnoreCase(url.getHost())) {
                    throw new CertificateException(String.format(
                            "SigningCertificateChainUrl [%s] does not contain the required hostname"
                                    + " of [%s]", signingCertificateChainUrl,
                            VALID_SIGNING_CERT_CHAIN_URL_HOST_NAME));
                }
        
                // Validate the path prefix
                String path = url.getPath();
                if (!path.startsWith(VALID_SIGNING_CERT_CHAIN_URL_PATH_PREFIX)) {
                    throw new CertificateException(String.format(
                            "SigningCertificateChainUrl path [%s] is invalid. Expecting path to "
                                    + "start with [%s]", signingCertificateChainUrl,
                            VALID_SIGNING_CERT_CHAIN_URL_PATH_PREFIX));
                }
        
                // Validate the protocol
                String urlProtocol = url.getProtocol();
                if (!VALID_SIGNING_CERT_CHAIN_PROTOCOL.equalsIgnoreCase(urlProtocol)) {
                    throw new CertificateException(String.format(
                            "SigningCertificateChainUrl [%s] contains an unsupported protocol [%s]",
                            signingCertificateChainUrl, urlProtocol));
                }
        
                // Validate the port uses the default of 443 for HTTPS if explicitly defined in the URL
                int urlPort = url.getPort();
                if ((urlPort != UNSPECIFIED_SIGNING_CERT_CHAIN_URL_PORT_VALUE)
                        && (urlPort != url.getDefaultPort())) {
                    throw new CertificateException(String.format(
                            "SigningCertificateChainUrl [%s] contains an invalid port [%d]",
                            signingCertificateChainUrl, urlPort));
                }
        
                return url;
            } catch (IllegalArgumentException | MalformedURLException | URISyntaxException ex) {
                throw new CertificateException(String.format(
                        "SigningCertificateChainUrl [%s] is malformed", signingCertificateChainUrl), ex);
            }
        }        

}