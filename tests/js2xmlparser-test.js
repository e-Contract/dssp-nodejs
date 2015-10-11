"use strict";

var js2xmlparser = require("js2xmlparser");

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
    test.done();
};