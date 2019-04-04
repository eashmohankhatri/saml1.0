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
            '@Version': '1.0',
            '@IssueInstant': (new Date()).toISOString(),
            NameIDPolicy: {
                '@AllowCreate': 'true'
            }
        }
    }).end();
}
