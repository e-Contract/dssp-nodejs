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
var dssp = require("../index");

var fs = require("fs");

var express = require('express');
var app = express();

var bodyParser = require('body-parser');

app.use(bodyParser.urlencoded({extended: false}));

var session = require('express-session');
app.use(session({
    secret: 'mySecretKey',
    resave: false,
    saveUninitialized: true
}));

app.get("/sign", function (req, res) {
    var dssClient = new dssp.DSSP();
    fs.readFile("tests/document.pdf", function (err, data) {
        if (err) {
            console.log(err);
        } else {
            dssClient.upload(data);
        }
    });
});

app.use(express.static(__dirname + "/public"));

var server = app.listen(3000, function () {
    var host = server.address().address;
    var port = server.address().port;
    console.log('Example app listening at http://%s:%s', host, port);
});

