/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2015-2017 e-Contract.be BVBA.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

"use strict";

var js2xmlparser = require("js2xmlparser");
var xmlCrypto = require('xml-crypto');
var xmldom = require('xmldom');
var crypto = require("crypto");

function SecurityTokenReferenceKeyInfoProvider(tokenIdentifier, key) {
    this.tokenIdentifier = tokenIdentifier;
    this.key = key;

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
        var result = js2xmlparser.parse("wsse:SecurityTokenReference", securityTokenReferenceData, {
            declaration: {
                include: false
            }
        });
        return result;
    };

    this.getKey = function (keyInfo) {
        return this.key;
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
    var result = js2xmlparser.parse("async:PendingRequest", data);
    console.log(result);
    var signature = new xmlCrypto.SignedXml();
    var key = crypto.randomBytes(32);
    signature.signingKey = key;
    signature.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
    signature.addReference("//*[local-name(.)='PendingRequest']", ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
            "http://www.w3.org/2000/09/xmldsig#sha1", "", "", "", true);
    signature.keyInfoProvider = new SecurityTokenReferenceKeyInfoProvider("a token identifier", key);
    signature.computeSignature(result, {
        prefix: "ds",
        location: {
            reference: "dss:OptionalInputs"
        }
    });
    console.log(signature.getSignedXml());

    var doc = new xmldom.DOMParser().parseFromString(signature.getSignedXml());
    var signatureElement = xmlCrypto.xpath(doc, "/*/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
    console.log("signature: " + signatureElement);
    var verify = new xmlCrypto.SignedXml();
    verify.signingKey = "1234";
    verify.loadSignature(signatureElement);
    verify.keyInfoProvider = new SecurityTokenReferenceKeyInfoProvider("a token identifier", key);
    var result = verify.checkSignature(signature.getSignedXml());
    test.equal(result, true);

    test.done();
};