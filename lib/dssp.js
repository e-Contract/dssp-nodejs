/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2015-2016 e-Contract.be BVBA.
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
var xmldom = require('xmldom');
var https = require('https');
var moment = require('moment');

function DSSP() {
}

function SecurityTokenReferenceKeyInfoProvider(tokenIdentifier, key, tokenType) {
    this.tokenIdentifier = tokenIdentifier;
    this.key = key;
    this.tokenType = tokenType;

    this.getKeyInfo = function (key, prefix) {
        var securityTokenReferenceData = {
            "@": {
                "xmlns:wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            },
            "wsse:Reference": {
                "@": {
                    "ValueType": tokenType,
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

/**
 * Initiate a signing request towards the Digital Signature Service.
 *
 * @param {type} data
 * @param {type} session
 * @param {type} res
 * @returns {undefined}
 * @public
 */
DSSP.prototype.sign = function (data, session, res) {
    var encodedData = new Buffer(data).toString("base64");
    var clientSecret = crypto.randomBytes(32);
    var encodedClientSecret = clientSecret.toString("base64");
    soap.createClient("https://www.e-contract.be/dss-ws/dss?wsdl", function (err, client) {
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
            console.log(response.OptionalOutputs.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse.RequestedSecurityToken.SecurityContextToken);
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
                        "wsu:Created": moment(new Date()).utc().toISOString(),
                        "wsu:Expires": moment(new Date()).add(5, "m").utc().toISOString()
                    },
                    "wsa:ReplyTo": {
                        "wsa:Address": "http://0.0.0.0:3000/landing"
                    }
                }
            };
            var pendingRequest = js2xmlparser("async:PendingRequest", pendingRequestData);
            var signature = new xmlCrypto.SignedXml();
            signature.signingKey = key;
            signature.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
            signature.addReference("//*[local-name(.)='PendingRequest']", ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
                    "http://www.w3.org/2000/09/xmldsig#sha1", "", "", "", true);
            signature.keyInfoProvider = new SecurityTokenReferenceKeyInfoProvider(tokenIdentifier, key, "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/sct");
            signature.computeSignature(pendingRequest, {
                prefix: "ds",
                location: {
                    reference: "dss:OptionalInputs"
                }
            });
            console.log("signed XML: " + signature.getSignedXml());
            var encodedPendingRequest = new Buffer(signature.getSignedXml()).toString("base64");
            var html = jade.renderFile("./lib/post.jade", {
                actionUrl: "https://www.e-contract.be/dss-ws/start",
                pendingRequestValue: encodedPendingRequest
            });
            console.log("HTML: " + html);
            // cannot store Buffer in the session, only strings apparently, hence we base64 encode the key
            session.dsspKey = key.toString("base64");
            session.dsspResponseID = responseID;
            session.dsspTokenRef = response.OptionalOutputs.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse.RequestedSecurityToken.SecurityContextToken.attributes["wsu:Id"];
            session.dsspTokenIdentifier = tokenIdentifier;
            res.send(html);
        });
    });
};

DSSP.prototype.handleSignResponse = function (req) {
    console.log("handle sign response");
    console.log(req.body);
    var encodedSignResponse = req.body.SignResponse;
    var signResponse = new Buffer(encodedSignResponse, "base64").toString();
    console.log("SignResponse: " + signResponse);

    var doc = new xmldom.DOMParser().parseFromString(signResponse);
    var signatureElement = xmlCrypto.xpath(doc, "/*/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
    console.log("signature: " + signatureElement);
    var verify = new xmlCrypto.SignedXml();
    verify.loadSignature(signatureElement);
    var key = new Buffer(req.session.dsspKey, "base64");
    verify.keyInfoProvider = new SecurityTokenReferenceKeyInfoProvider(null, key);
    var result = verify.checkSignature(signResponse);
    console.log("XML signature result: " + result);

    // soap module is not capable of doing WS-Security signatures as they do not operate at the DOM level
    // hence we do the download call manually
    var soapEnvelopeData = {
        "@": {
            "xmlns:soap": "http://www.w3.org/2003/05/soap-envelope",
            "xmlns:wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
            "xmlns:async": "urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing:1.0",
            "xmlns:dss": "urn:oasis:names:tc:dss:1.0:core:schema",
            "xmlns:wsc": "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512",
            "xmlns:wsu": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
        },
        "soap:Header": {
            "wsse:Security": {
                "@": {
                    "soap:mustUnderstand": "1"
                },
                "wsu:Timestamp": {
                    "@": {
                        "wsu:Id": "timestamp"
                    },
                    "wsu:Created": moment(new Date()).utc().toISOString(),
                    "wsu:Expires": moment(new Date()).add(5, "m").utc().toISOString()
                },
                "wsc:SecurityContextToken": {
                    "@": {
                        "wsu:Id": req.session.dsspTokenRef
                    },
                    "wsc:Identifier": req.session.dsspTokenIdentifier
                }
            }
        },
        "soap:Body": {
            "@": {
                "wsu:Id": "body"
            },
            "async:PendingRequest": {
                "@": {
                    "Profile": "urn:be:e-contract:dssp:1.0"
                },
                "dss:OptionalInputs": {
                    "dss:AdditionalProfile": "urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing",
                    "async:ResponseID": req.session.dsspResponseID
                }
            }
        }
    };
    var soapEnvelope = js2xmlparser("soap:Envelope", soapEnvelopeData);
    console.log("SOAP request: " + soapEnvelope);

    var signature = new xmlCrypto.SignedXml("wssecurity");
    signature.signingKey = key;
    signature.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
    signature.addReference("//*[local-name(.)='Timestamp']", ["http://www.w3.org/2001/10/xml-exc-c14n#"],
            "http://www.w3.org/2000/09/xmldsig#sha1");
    signature.addReference("//*[local-name(.)='Body']", ["http://www.w3.org/2001/10/xml-exc-c14n#"],
            "http://www.w3.org/2000/09/xmldsig#sha1");
    signature.keyInfoProvider = new SecurityTokenReferenceKeyInfoProvider("#" + req.session.dsspTokenRef, key, null);
    signature.computeSignature(soapEnvelope, {
        prefix: "ds",
        location: {
            reference: "/soap:Envelope/soap:Header/wsse:Security"
        }
    });
    console.log("signed XML: " + signature.getSignedXml());

    var postOptions = {
        hostname: "www.e-contract.be",
        port: 443,
        path: "/dss-ws/dss",
        method: "POST",
        headers: {
            "Content-Type": "application/soap+xml; charset=utf-8"
        }
    };
    var postRequest = https.request(postOptions, function (res) {
        res.on("data", function (chunk) {
            // we indeed receive different chunks
            console.log("Response: " + chunk);
        });
        res.on("end", function () {
            console.log("No more data in response.");
        });
    });

    postRequest.on("error", function (err) {
        console.log("Download error: " + err.message);
    });

    postRequest.write(signature.getSignedXml());
    postRequest.end();
};

DSSP.prototype.verify = function (data, callback) {
    soap.createClient("https://www.e-contract.be/dss-ws/dss?wsdl", function (err, client) {
        var encodedData = new Buffer(data).toString("base64");
        client.DigitalSignatureService.DigitalSignatureServicePortImplPort.verify({
            attributes: {
                Profile: "urn:be:e-contract:dssp:1.0"
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
            console.log("error: ", err);
            console.log("response: ", response);
            var individualReport = response.OptionalOutputs.VerificationReport.IndividualReport;
            console.log("Individual report: ", individualReport);
            var signingTime = individualReport.SignedObjectIdentifier.SignedProperties.SignedSignatureProperties.SigningTime;
            console.log("signing time: %s", signingTime);
            var subject = individualReport.Details.DetailedSignatureReport.CertificatePathValidity.PathValidityDetail.CertificateValidity.Subject;
            console.log("Subject", subject);
            var signatures = [];
            signatures.push({
                signingTime: signingTime,
                subject: subject
            });
            callback(signatures);
        });
    });
};

/**
 * Initialize a new DSSP client.
 *
 * @return {DSSP} the DSSP client.
 * @public
 */
exports.DSSP = DSSP;