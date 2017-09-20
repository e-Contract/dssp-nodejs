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

var soap = require('soap');
var pug = require('pug');
var js2xmlparser = require("js2xmlparser");
var psha1 = require("psha1");
var xmlCrypto = require('xml-crypto');
var crypto = require("crypto");
var xmldom = require('xmldom');
var moment = require('moment');
var util = require('util');
var wssc = require("./wssc");

/**
 * Constructor of the DSSP NodeJS client.
 * 
 * @param {string} wsLocation optional location of the DSS web service
 * @param {string} postLocation optional location of the DSS browser post
 * @class
 * @constructor
 * @memberof module:dssp
 */
function DSSP(wsLocation, postLocation) {
    if (typeof wsLocation === "undefined") {
        this.wsLocation = "https://www.e-contract.be/dss-ws/dss?wsdl";
    } else {
        this.wsLocation = wsLocation;
    }

    if (typeof postLocation === "undefined") {
        this.postLocation = "https://www.e-contract.be/dss-ws/start";
    } else {
        this.postLocation = postLocation;
    }
}

/**
 * @private
 */
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
        var result = js2xmlparser.parse("wsse:SecurityTokenReference", securityTokenReferenceData, {
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
 * Sets the credential used during document uploading.
 * 
 * @memberof DSSP
 * @param {string} username the username.
 * @param {string} password the password
 */
DSSP.prototype.setCredential = function (username, password) {
    this.username = username;
    this.password = password;
};

/**
 * Initiate a signing request towards the Digital Signature Service.
 *
 * @param {Buffer} data the document to be signed.
 * @param {Express.Session} session the Express session object.
 * @param {string} landingUrl the URL used by the DSS to callback to our web application.
 * @param {Response} res the Express response object.
 */
DSSP.prototype.sign = function (data, session, landingUrl, res) {
    var encodedData = new Buffer(data).toString("base64");
    var clientSecret = crypto.randomBytes(32);
    var encodedClientSecret = clientSecret.toString("base64");
    var dssp = this;
    soap.createClient(dssp.wsLocation, function (err, client) {
        if (typeof dssp.username !== "undefined") {
            var options = {
                passwordType: "PasswordDigest"
            };
            var wsSecurity = new soap.WSSecurity(dssp.username, dssp.password, options);
            client.setSecurity(wsSecurity);
        }
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
            //console.log("SOAP request: " + client.lastRequest);
            //console.log(response);
            var responseID = response.OptionalOutputs.ResponseID;
            //console.log("ResponseID: " + responseID);
            var encodedServerSecret = response.OptionalOutputs.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse.Entropy.BinarySecret;
            var encodedKey = psha1(encodedClientSecret, encodedServerSecret);
            var key = new Buffer(encodedKey, "base64");
            //console.log(response.OptionalOutputs.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse.RequestedSecurityToken.SecurityContextToken);
            var tokenIdentifier = response.OptionalOutputs.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse.RequestedSecurityToken.SecurityContextToken.Identifier;
            //console.log("token identifier: " + tokenIdentifier);
            //console.log(client.describe());
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
                        "wsa:Address": landingUrl
                    }
                }
            };
            var pendingRequest = js2xmlparser.parse("async:PendingRequest", pendingRequestData);
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
            //console.log("signed XML: " + signature.getSignedXml());
            var encodedPendingRequest = new Buffer(signature.getSignedXml()).toString("base64");
            var html = pug.renderFile("./lib/post.pug", {
                actionUrl: dssp.postLocation,
                pendingRequestValue: encodedPendingRequest
            });
            //console.log("HTML: " + html);
            // cannot store Buffer in the session, only strings apparently, hence we base64 encode the key
            session.dsspKey = key.toString("base64");
            session.dsspResponseID = responseID;
            session.dsspTokenRef = response.OptionalOutputs.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse.RequestedSecurityToken.SecurityContextToken.attributes["wsu:Id"];
            session.dsspTokenIdentifier = tokenIdentifier;
            res.send(html);
        });
    });
};

var DSSP_RESULT = {
    SUCCESS: 0,
    GENERIC_ERROR: 1,
    RESPONSE_SIGNATURE_ERROR: 2,
    USER_CANCEL: 3
};

/**
 * Handles the sign response from the DSS.
 * @param {Request} req
 * @param {function(string, string):void} callback
 */
DSSP.prototype.handleSignResponse = function (req, callback) {
    var dssp = this;
    //console.log("handle sign response");
    //console.log(req.body);
    var encodedSignResponse = req.body.SignResponse;
    var signResponse = new Buffer(encodedSignResponse, "base64").toString();
    //console.log("SignResponse: " + signResponse);

    var doc = new xmldom.DOMParser().parseFromString(signResponse);
    var signatureElement = xmlCrypto.xpath(doc, "/*/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
    //console.log("signature: " + signatureElement);
    var verify = new xmlCrypto.SignedXml();
    verify.loadSignature(signatureElement);
    //console.log("session key: " + req.session.dsspKey);
    var key = new Buffer(req.session.dsspKey, "base64");
    verify.keyInfoProvider = new SecurityTokenReferenceKeyInfoProvider(null, key);
    var result = verify.checkSignature(signResponse);
    //console.log("XML signature result: " + result);
    if (!result) {
        callback({
            result: DSSP_RESULT.RESPONSE_SIGNATURE_ERROR
        });
        return;
    }
    var resultMajorValue = xmlCrypto.xpath(doc, "/*/*/*[local-name(.)='ResultMajor' and namespace-uri(.)='urn:oasis:names:tc:dss:1.0:core:schema']/text()")[0].nodeValue;
    if ("urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing:resultmajor:Pending" !== resultMajorValue) {
        var resultMinorValue = xmlCrypto.xpath(doc, "/*/*/*[local-name(.)='ResultMinor' and namespace-uri(.)='urn:oasis:names:tc:dss:1.0:core:schema']/text()")[0].nodeValue;
        if (resultMinorValue === "urn:be:e-contract:dssp:1.0:resultminor:user-cancelled") {
            callback({
                result: DSSP_RESULT.USER_CANCEL
            });
            return;
        }
        callback({
            result: DSSP_RESULT.GENERIC_ERROR
        });
        return;
    }
    //console.log(resultMajorValue);

    soap.createClient(dssp.wsLocation, function (err, client) {
        var wsSecurity = new wssc.WSSecureConversation(req.session.dsspTokenRef, req.session.dsspTokenIdentifier, key);
        client.setSecurity(wsSecurity);
        client.DigitalSignatureService.DigitalSignatureServicePortImplPort.pendingRequest({
            "dss:OptionalInputs": {
                "dss:AdditionalProfile": "urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing",
                "async:ResponseID": req.session.dsspResponseID
            }
        }, function (err, response) {
            //console.log("SOAP request: " + client.lastRequest);
            //console.log(response);
            var signedDocument = new Buffer(response.OptionalOutputs.DocumentWithSignature.Document.Base64Data.$value, "base64");
            //console.log("signed document: " + signedDocument);
            callback({
                result: DSSP_RESULT.SUCCESS
            }, signedDocument);
        });
    });
};

/**
 * Verify the signatures on a given document.
 *  
 * @param {Buffer} data
 * @param {function(object,object):void} callback
 *
 */
DSSP.prototype.verify = function (data, callback) {
    var dssp = this;
    soap.createClient(dssp.wsLocation, function (err, client) {
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
            //console.log("error: ", err);
            //console.log("response: ", response);
            var individualReport = response.OptionalOutputs.VerificationReport.IndividualReport;
            //console.log("Individual report: ", individualReport);
            var signatures = [];
            if (util.isArray(individualReport)) {
                //console.log("result array");
                individualReport.forEach(function (report) {
                    var signingTime = report.SignedObjectIdentifier.SignedProperties.SignedSignatureProperties.SigningTime;
                    //console.log("signing time: %s", signingTime);
                    var subject = report.Details.DetailedSignatureReport.CertificatePathValidity.PathValidityDetail.CertificateValidity.Subject;
                    //console.log("Subject", subject);
                    signatures.push({
                        signingTime: signingTime,
                        subject: subject
                    });
                });
            } else {
                var signingTime = individualReport.SignedObjectIdentifier.SignedProperties.SignedSignatureProperties.SigningTime;
                //console.log("signing time: %s", signingTime);
                var subject = individualReport.Details.DetailedSignatureReport.CertificatePathValidity.PathValidityDetail.CertificateValidity.Subject;
                //console.log("Subject", subject);
                signatures.push({
                    signingTime: signingTime,
                    subject: subject
                });
            }
            var result = {
                result: DSSP_RESULT.SUCCESS
            };
            callback(result, signatures);
        });
    });
};

exports.DSSP = DSSP;
exports.DSSP_RESULT = DSSP_RESULT;