
var utils = require('./utils'),
    Parser = require('xmldom').DOMParser,
    SignedXml = require('xml-crypto').SignedXml,
    xmlenc = require('xml-encryption'),
    moment = require('moment');
async = require('async');
crypto = require('crypto');

var fs = require('fs');
var path = require('path');
var saml = fs.readFileSync(path.join(__dirname, 'saml.template')).toString();

var NAMESPACE = 'urn:oasis:names:tc:SAML:1.0:assertion';

var algorithms = {
    signature: {
        'rsa-sha256': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'rsa-sha1': 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
    },
    digest: {
        'sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
        'sha1': 'http://www.w3.org/2000/09/xmldsig#sha1'
    }
};

exports.getSAMLResponse = function (options, callback) {
    if (!options.key)
        throw new Error('Expect a private key in pem format');

    if (!options.cert)
        throw new Error('Expect a public key cert in pem format');

    options.signatureAlgorithm = options.signatureAlgorithm || 'rsa-sha256';
    options.digestAlgorithm = options.digestAlgorithm || 'sha256';

    var cert = utils.pemToCert(options.cert);

    var sig = new SignedXml(null, { signatureAlgorithm: algorithms.signature[options.signatureAlgorithm], idAttribute: 'AssertionID' });
    sig.addReference("//*[local-name(.)='Assertion']",
        ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
        algorithms.digest[options.digestAlgorithm]);

    sig.signingKey = options.key;

    sig.keyInfoProvider = {
        getKeyInfo: function () {
            return "<X509Data><X509Certificate>" + cert + "</X509Certificate></X509Data>";
        }
    };

    var doc;
    try {
        doc = new Parser().parseFromString(saml.toString());
    } catch (err) {
        return utils.reportError(err, callback);
    }

    var now = moment.utc();
    //doc.documentElement.setAttribute('AssertionID', '_' + (options.uid || utils.uid(32)));
    if (options.issuer) {
        //doc.documentElement.setAttribute('Issuer', options.issuer);
        doc.getElementsByTagName('saml:Assertion')[0].setAttribute('Issuer', options.issuer);
        doc.getElementsByTagName('saml:Assertion')[0].setAttribute('IssueInstant', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
        doc.getElementsByTagName('saml:Assertion')[0].setAttribute('AssertionID', '_' + (options.uid || utils.uid(32)));
    }


    doc.documentElement.setAttribute('IssueInstant', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
    var conditions = doc.documentElement.getElementsByTagName('saml:Conditions');

    if (options.lifetimeInSeconds) {
        conditions[0].setAttribute('NotBefore', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
        conditions[0].setAttribute('NotOnOrAfter', now.add(options.lifetimeInSeconds, 'seconds').format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
    }

    if (options.audiences) {
        var audiences = options.audiences instanceof Array ? options.audiences : [options.audiences];
        audiences.forEach(function (audience) {
            var element = doc.createElementNS(NAMESPACE, 'saml:Audience');
            element.textContent = audience;
            // var audienceCondition = conditions[0].getElementsByTagNameNS(NAMESPACE, 'AudienceRestrictionCondition')[0];
            // audienceCondition.appendChild(element);
        });
    }

    if (options.attributes) {
        var statement = doc.getElementsByTagName('saml:Assertion')[0];

        var confirmationMethodElem = doc.createElement('saml:ConfirmationMethod');
        confirmationMethodElem.textContent = 'urn:oasis:names:tc:SAML:1.0:cm:bearer';

        var subConfirmElem = doc.createElement('saml:SubjectConfirmation');
        subConfirmElem.appendChild(confirmationMethodElem);

        var nameIdentifierElem = doc.createElement('saml:NameIdentifier');
        nameIdentifierElem.setAttribute('Format', 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');

        var subjectElem = doc.createElement('saml:Subject');
        subjectElem.appendChild(nameIdentifierElem);
        subjectElem.appendChild(subConfirmElem);






        Object.keys(options.attributes).forEach(function (prop) {
            if (typeof options.attributes[prop] === 'undefined') return;

            // <saml:Attribute AttributeName="name" AttributeNamespace="http://schemas.xmlsoap.org/claims/identity">
            //    <saml:AttributeValue>Foo Bar</saml:AttributeValue>
            // </saml:Attribute>
            var name = prop.indexOf('/') > -1 ? prop.substring(prop.lastIndexOf('/') + 1) : prop;
            var namespace = (options.issuer) ? options.issuer : prop.indexOf('/') > -1 ? prop.substring(0, prop.lastIndexOf('/')) : '';

            var attributeStatementElement = doc.createElementNS(NAMESPACE, 'saml:AttributeStatement');

            var attributeElement = doc.createElement('saml:Attribute');
            attributeElement.setAttribute('AttributeNamespace', namespace);
            attributeElement.setAttribute('AttributeName', name);
            var values = options.attributes[prop] instanceof Array ? options.attributes[prop] : [options.attributes[prop]];
            values.forEach(function (value) {
                var valueElement = doc.createElementNS(NAMESPACE, 'saml:AttributeValue');
                valueElement.textContent = value;
                attributeElement.appendChild(valueElement);
            });

            // var subjectElement = new Parser().parseFromString(subjectStr.toString());

            var confirmationMethodElem = doc.createElement('saml:ConfirmationMethod');
            confirmationMethodElem.textContent = 'urn:oasis:names:tc:SAML:1.0:cm:bearer';

            var subConfirmElem = doc.createElement('saml:SubjectConfirmation');
            subConfirmElem.appendChild(confirmationMethodElem);

            var nameIdentifierElem = doc.createElement('saml:NameIdentifier');
            nameIdentifierElem.setAttribute('Format', 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');

            var subjectElement = doc.createElement('saml:Subject');
            subjectElement.appendChild(nameIdentifierElem);
            subjectElement.appendChild(subConfirmElem);

            if (options.nameIdentifier) {
                subjectElement.getElementsByTagName(
                    'saml:NameIdentifier')[0].textContent = options.nameIdentifier;

                subjectElement.getElementsByTagName(
                    'saml:NameIdentifier')[0].setAttribute('NameQualifier', 'urn:' + namespace);
            }


            attributeStatementElement.appendChild(subjectElement);
            attributeStatementElement.appendChild(attributeElement);


            if (values && values.length > 0) {
                // saml:Attribute must have at least one saml:AttributeValue
                statement.appendChild(attributeStatementElement);
            }
        });
    }

    doc.getElementsByTagName('saml:AuthenticationStatement')[0]
        .setAttribute('AuthenticationInstant', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));

    var nameID = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'NameIdentifier')[0];

    if (options.nameIdentifier) {
        nameID.textContent = options.nameIdentifier;

        doc.getElementsByTagName('saml:AuthenticationStatement')[0]
            .getElementsByTagName('saml:NameIdentifier')[0]
            .textContent = options.nameIdentifier;

        doc.getElementsByTagName('saml:AttributeStatement')[0]
            .getElementsByTagName('saml:NameIdentifier')[0]
            .textContent = options.nameIdentifier;
    }

    if (options.nameIdentifierFormat) {
        var nameIDs = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'NameIdentifier');
        nameIDs[0].setAttribute('Format', options.nameIdentifierFormat);
        nameIDs[1].setAttribute('Format', options.nameIdentifierFormat);
    }

    if (!options.encryptionCert) return sign(options, sig, doc, callback);

    // encryption is turned on, 
    var proofSecret;
    async.waterfall([
        function (cb) {
            if (!options.subjectConfirmationMethod && options.subjectConfirmationMethod !== 'holder-of-key')
                return cb();

            crypto.randomBytes(32, function (err, randomBytes) {
                proofSecret = randomBytes;
                addSubjectConfirmation(options, doc, options.holderOfKeyProofSecret || randomBytes, cb);
            });

        },
        function (cb) {
            sign(options, sig, doc, function (err, signed) {
                if (err) return cb(err);
                return encrypt(options, signed, cb);
            });
        }
    ], function (err, result) {
        if (err) return callback(err);
        callback(null, result, proofSecret);
    });
};

function addSubjectConfirmation(options, doc, randomBytes, callback) {
    var encryptOptions = {
        rsa_pub: options.encryptionPublicKey,
        pem: options.encryptionCert,
        keyEncryptionAlgorighm: options.keyEncryptionAlgorighm || 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
    };

    xmlenc.encryptKeyInfo(randomBytes, encryptOptions, function (err, keyinfo) {
        if (err) return cb(err);
        var subjectConfirmationNodes = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'SubjectConfirmation');

        for (var i = 0; i < subjectConfirmationNodes.length; i++) {
            var keyinfoDom;
            try {
                keyinfoDom = new Parser().parseFromString(keyinfo);
            } catch (error) {
                return utils.reportError(error, callback);
            }

            var method = subjectConfirmationNodes[i].getElementsByTagNameNS(NAMESPACE, 'ConfirmationMethod')[0];
            method.textContent = 'urn:oasis:names:tc:SAML:1.0:cm:holder-of-key';
            subjectConfirmationNodes[i].appendChild(keyinfoDom.documentElement);
        }

        callback();
    });
}

function sign(options, sig, doc, callback) {
    var token = utils.removeWhitespace(doc.toString());
    var signed;

    try {
        var opts = options.xpathToNodeBeforeSignature ? {
            location: {
                reference: options.xpathToNodeBeforeSignature,
                action: 'after'
            }
        } : {};

        sig.computeSignature(token, opts);
        signed = sig.getSignedXml();
    } catch (err) {
        return utils.reportError(err, callback);
    }

    if (!callback) return signed;

    return callback(null, signed);
}

function encrypt(options, signed, callback) {
    var encryptOptions = {
        rsa_pub: options.encryptionPublicKey,
        pem: options.encryptionCert,
        encryptionAlgorithm: options.encryptionAlgorithm || 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
        keyEncryptionAlgorighm: options.keyEncryptionAlgorighm || 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
    };

    xmlenc.encrypt(signed, encryptOptions, function (err, encrypted) {
        if (err) return callback(err);
        callback(null, utils.removeWhitespace(encrypted));
    });
}
