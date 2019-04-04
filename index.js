module.exports = {
    getSAMLResponse
};
var xmlbuilder = require('xmlbuilder');
var XMLNS = {
    SAML: 'urn:oasis:names:tc:SAML:2.0:assertion',
    SAMLP: 'urn:oasis:names:tc:SAML:2.0:protocol',
    MD: 'urn:oasis:names:tc:SAML:2.0:metadata',
    DS: 'http://www.w3.org/2000/09/xmldsig#',
    XENC: 'http://www.w3.org/2001/04/xmlenc#',
    EXC_C14N: 'http://www.w3.org/2001/10/xml-exc-c14n#'
};

function getSAMLResponse() {
    return xmlbuilder.create({
        AuthnRequest: {
            '@xmlns': XMLNS.SAMLP,
            '@xmlns:saml': XMLNS.SAML,
            '@Version': '2.0',
            '@ID': id,
            '@IssueInstant': (new Date()).toISOString(),
            '@Destination': destination,
            '@AssertionConsumerServiceURL': assert_endpoint,
            '@ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            '@ForceAuthn': force_authn,
            'saml:Issuer': issuer,
            NameIDPolicy: {
                '@Format': nameid_format || 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
                '@AllowCreate': 'true'
            },
            RequestedAuthnContext: context_element
        }
    }).end();
}
