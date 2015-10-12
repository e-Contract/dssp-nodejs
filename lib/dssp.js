/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2015 e-Contract.be BVBA.
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

var soap = require('soap');
var jade = require('jade');
var js2xmlparser = require("js2xmlparser");
var psha1 = require("psha1");
var xmlCrypto = require('xml-crypto');
var crypto = require("crypto");

function DSSP() {
}

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
        var result = js2xmlparser("wsse:SecurityTokenReference", securityTokenReferenceData, {
            declaration: {
                include: false
            }
        });
        return result;
    };

    // only used for validation
    this.getKey = function (keyInfo) {
        return this.key;
    };
}

DSSP.prototype.sign = function (data, res) {
    var encodedData = new Buffer(data).toString("base64");
    var clientSecret = crypto.randomBytes(32);
    var encodedClientSecret = clientSecret.toString("base64");
    soap.createClient("http://localhost:8080/dss-ws/dss?wsdl", function (err, client) {
        client.DigitalSignatureService.DigitalSignatureServicePortImplPort.sign({
            OptionalInputs: {
                AdditionalProfile: "urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing",
                'wst:RequestSecurityToken': {
                    'wst:TokenType': "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/sct",
                    'wst:RequestType': "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue",
                    'wst:Entropy': {
                        'wst:BinarySecret': encodedClientSecret
                    }
                }
            },
            InputDocuments: {
                Document: {
                    Base64Data: {
                        attributes: {
                            MimeType: "application/pdf"
                        },
                        '$value': encodedData
                    }
                }
            }
        }, function (err, response) {
            console.log("SOAP request: " + client.lastRequest);
            console.log(response);
            var responseID = response.OptionalOutputs.ResponseID;
            console.log("ResponseID: " + responseID);
            var encodedServerSecret = response.OptionalOutputs.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse.Entropy.BinarySecret;
            var encodedKey = psha1(encodedClientSecret, encodedServerSecret);
            var key = new Buffer(encodedKey, "base64");
            console.log(response.OptionalOutputs.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse);
            var tokenIdentifier = response.OptionalOutputs.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse.RequestedSecurityToken.SecurityContextToken.Identifier;
            console.log("token identifier: " + tokenIdentifier);
            console.log(client.describe());
            var pendingRequestData = {
                "@": {
                    "xmlns:async": "urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing:1.0",
                    "xmlns:dss": "urn:oasis:names:tc:dss:1.0:core:schema",
                    "xmlns:wsa": "http://www.w3.org/2005/08/addressing",
                    "xmlns:wsu": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
                    "Profile": "urn:be:e-contract:dssp:1.0"
                },
                "dss:OptionalInputs": {
                    "dss:AdditionalProfile": "urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing",
                    "async:ResponseID": responseID,
                    "wsa:MessageID": "uuid:a-message-id",
                    "wsu:Timestamp": {
                        "wsu:Created": "2015-10-11T18:00:00Z",
                        "wsu:Expires": "2015-10-15T20:00:00Z"
                    },
                    "wsa:ReplyTo": {
                        "wsa:Address": "https://the.landing.url"
                    }
                }
            };
            var pendingRequest = js2xmlparser("async:PendingRequest", pendingRequestData);
            var signature = new xmlCrypto.SignedXml();
            signature.signingKey = key;
            signature.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
            signature.addReference("//*[local-name(.)='PendingRequest']", ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
                    "http://www.w3.org/2000/09/xmldsig#sha1", "", "", "", true);
            signature.keyInfoProvider = new SecurityTokenReferenceKeyInfoProvider(tokenIdentifier, key);
            signature.computeSignature(pendingRequest, {
                prefix: "ds",
                location: {
                    reference: "dss:OptionalInputs"
                }
            });
            console.log("signed XML: " + signature.getSignedXml());
            var encodedPendingRequest = new Buffer(signature.getSignedXml()).toString("base64");
            var html = jade.renderFile("./lib/post.jade", {
                actionUrl: "https://local.e-contract.be/dss-ws/start",
                pendingRequestValue: encodedPendingRequest
            });
            console.log("HTML: " + html);
            res.send(html);
        });
    });
};

exports.DSSP = DSSP;