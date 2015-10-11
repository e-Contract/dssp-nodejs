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

var soap = require('soap');

function DSSP() {
}

DSSP.prototype.upload = function (data) {
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
            console.log(client.describe());
        });
    });
};

exports.DSSP = DSSP;