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

function DSSP() {
}

DSSP.prototype.sign = function (data, res) {
    var encodedData = new Buffer(data).toString("base64");
    soap.createClient("https://www.e-contract.be/dss-ws/dss?wsdl", function (err, client) {
        client.DigitalSignatureService.DigitalSignatureServicePortImplPort.sign({
            OptionalInputs: {
                AdditionalProfile: "urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing",
                'wst:RequestSecurityToken': {
                    'wst:TokenType': "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/sct",
                    'wst:RequestType': "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue",
                    'wst:Entropy': {
                        'wst:BinarySecret': "12345678"
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
                        "wsu:Expires": "2015-10-11T20:00:00Z"
                    },
                    "wsa:ReplyTo": {
                        "wsa:Address": "https://the.landing.url"
                    }
                }
            };
            var pendingRequest = js2xmlparser("async:PendingRequest", pendingRequestData);
            var encodedPendingRequest = new Buffer(pendingRequest).toString("base64");
            var html = jade.renderFile("./lib/post.jade", {
                actionUrl: "https://www.e-contract.be/dss-ws/start",
                pendingRequestValue: encodedPendingRequest
            });
            res.send(html);
        });
    });
};

exports.DSSP = DSSP;