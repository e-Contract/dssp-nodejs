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

var fs = require('fs');
var path = require('path');
var ejs = require('ejs');
var SignedXml = require('xml-crypto').SignedXml;
var wsseSecurityHeaderTemplate = ejs.compile(fs.readFileSync(path.join(__dirname, 'templates', 'wsse-security-header.ejs')).toString());
var js2xmlparser = require("js2xmlparser");

function addMinutes(date, minutes) {
    return new Date(date.getTime() + minutes * 60000);
}

function dateStringForSOAP(date) {
    return date.getUTCFullYear() + '-' + ('0' + (date.getUTCMonth() + 1)).slice(-2) + '-' +
            ('0' + date.getUTCDate()).slice(-2) + 'T' + ('0' + date.getUTCHours()).slice(-2) + ":" +
            ('0' + date.getUTCMinutes()).slice(-2) + ":" + ('0' + date.getUTCSeconds()).slice(-2) + "Z";
}

function generateCreated() {
    return dateStringForSOAP(new Date());
}

function generateExpires() {
    return dateStringForSOAP(addMinutes(new Date(), 10));
}

function insertStr(src, dst, pos) {
    return [dst.slice(0, pos), src, dst.slice(pos)].join('');
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

function WSSecureConversation(dsspTokenRef, tokenId, key) {
    this.tokenRefId = dsspTokenRef;
    this.tokenId = tokenId;

    this.signer = new SignedXml();
    this.signer.signingKey = key;
    this.signer.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
    this.signer.keyInfoProvider = new SecurityTokenReferenceKeyInfoProvider("#" + dsspTokenRef, key, null);
}

WSSecureConversation.prototype.postProcess = function (xml, envelopeKey) {
    this.created = generateCreated();
    this.expires = generateExpires();

    var secHeader = wsseSecurityHeaderTemplate({
        tokenRefId: this.tokenRefId,
        tokenId: this.tokenId,
        created: this.created,
        expires: this.expires
    });

    var xmlWithSec = insertStr(secHeader, xml, xml.indexOf('</soap:Header>'));

    var references = ["http://www.w3.org/2001/10/xml-exc-c14n#"];

    this.signer.addReference("//*[name(.)='" + envelopeKey + ":Body']", references);
    this.signer.addReference("//*[name(.)='wsse:Security']/*[local-name(.)='Timestamp']", references);

    this.signer.computeSignature(xmlWithSec);

    return insertStr(this.signer.getSignatureXml(), xmlWithSec, xmlWithSec.indexOf('</wsse:Security>'));
};

module.exports = WSSecureConversation;
