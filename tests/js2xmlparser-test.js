"use strict";

var js2xmlparser = require("js2xmlparser");
var xmlCrypto = require('xml-crypto');

function SecurityTokenReferenceKeyInfoProvider(tokenIdentifier) {
    this.tokenIdentifier = tokenIdentifier;

    this.getKeyInfo = function (key, prefix) {
        var securityTokenReferenceData = {
            "@": {
                "xmlns:wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            },
            "wsse:Reference": {
                "@": {
                    "ValueType": "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/sct",
                    "URI": this.tokenIdentifier
                }
            }
        };
        var result = js2xmlparser("wsse:SecurityTokenReference", securityTokenReferenceData, {
            declaration: {
                include: false
            }
        });
        return result;
    };
}

exports['test js2xmlparser'] = function (test) {
    var data = {
        "@": {
            "xmlns:async": "urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing:1.0",
            "xmlns:dss": "urn:oasis:names:tc:dss:1.0:core:schema",
            "xmlns:wsa": "http://www.w3.org/2005/08/addressing",
            "xmlns:wsu": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
            "Profile": "urn:be:e-contract:dssp:1.0"
        },
        "dss:OptionalInputs": {
            "dss:AdditionalProfile": "urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing",
            "async:ResponseID": "responseId",
            "wsa:MessageID": "uuid:a-message-id",
            "wsu:Timestamp": {
                "wsu:Created": "2015-10-11T18:00:00Z",
                "wsu:Expires": "2015-10-11T20:00:00Z"
            },
            "wsa:ReplyTo": {
                "wsa:Address": "https://the.landing.url"
            }
        }
    };
    var result = js2xmlparser("async:PendingRequest", data);
    console.log(result);
    var signature = new xmlCrypto.SignedXml();
    signature.signingKey = "1234";
    signature.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
    signature.addReference("/", ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
            "http://www.w3.org/2000/09/xmldsig#sha1", "", "", "", true);
    signature.keyInfoProvider = new SecurityTokenReferenceKeyInfoProvider("a token identifier");
    signature.computeSignature(result, {
        prefix: "ds",
        location: {
            reference: "dss:OptionalInputs"
        }
    });
    console.log(signature.getSignedXml());
    test.done();
};