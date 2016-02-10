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
var dssp = require("../index");

var ansi = require('ansi');
var cursor = ansi(process.stdout);

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
            dssClient.sign(data, req.session, res);
        }
    });
});

app.post("/landing", function (req, res, next) {
    console.log("landing");
    var dssClient = new dssp.DSSP();
    dssClient.handleSignResponse(req);
    res.redirect("index.html");
});

app.use(express.static(__dirname + "/public"));

var server = app.listen(3000, function () {
    var host = server.address().address;
    var port = server.address().port;
    cursor.fg.blue();
    cursor.bold();
    cursor.write("Example app listening at http://" + host + ":" + port);
    cursor.fg.reset();
    cursor.write("\n");
});

