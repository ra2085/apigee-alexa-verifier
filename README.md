## Alexa Custom Skill Verifier for Apigee

Alexa provides a [Skill Kit](https://developer.amazon.com/en-US/docs/alexa/ask-overviews/what-is-the-alexa-skills-kit.html) that allows developers to create apps that end users can interact with through voice commands. [Custom Skills](https://developer.amazon.com/en-US/docs/alexa/custom-skills/host-a-custom-skill-as-a-web-service.html#verify-request-sent-by-alexa) can be hosted as APIs that are managed by Apigee, however, a custom security validation is required to only allow requests coming from Alexa. The security verification is also required to certify the custom Alexa Skill before being allowed into the marketplace.

## What's inside this repository?

* An Apigee Java Callout implementation to verify Alexa API calls
* A compiled distribution of the Java Callout.
* A sample Shared Flow that can be referenced in a Proxy or Flow hook

### Java Callout

The callout implementation does the following validations:

* `SignatureCertChainUrl` header presence and validity
* `Signature-256` header presence and validity
* `timestamp` payload attribute presence and validity

### Compiled distribution

You can find a pre-built JAR file under the callout/target directory.

### Sample Shared Flow use in Apigee

You'll find 3 policies in the flow that do the following tasks in sequential order:

* Extract `SignatureCertChainUrl`, `Signature-256` and `timestamp` values and store them into variables.
* Verify extracted values using the Java Callout
* Verify verification result

You'll find that the Java Callout requires properties that will be used as variables that must be populated by the Extract Variables policies.

```
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<JavaCallout continueOnError="false" enabled="true" name="JC-Alexa-Verifier">
    <DisplayName>JC-Alexa-Verifier</DisplayName>
    <Properties>
        <Property name="signature-cert-chain-url">alexa_signature_chain_url</Property>
        <Property name="request-signature">alexa_signature_256</Property>
        <Property name="message-variable-ref">message</Property>
        <Property name="request-body-timestamp">request_body_timestamp</Property>
        <Property name="request-signature-val-result">alexa_vallidation_result</Property>
    </Properties>
    <ClassName>com.google.apigee.edgecallouts.AlexaVerifierCallout</ClassName>
    <ResourceURL>java://apigee-alexa-verifier.jar</ResourceURL>
</JavaCallout>
```

The verification result will be expressed as a boolean value that can be used to create a custom error response message and Code.

```
...
<Step>
    <Condition>alexa_vallidation_result != "true"</Condition>
    <Name>RF-Unauthorized</Name>
</Step>
...
```

You'll find ready-to-deploy Shared Flow bundle under the /dist directory.

## Not Google Product Clause

This is not an officially supported Google product.
