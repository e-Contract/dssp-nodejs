"use strict";

var pug = require('pug');

exports['test Pug'] = function (test) {
    var pendingRequestValue = new Buffer("PendingRequestValue").toString("base64");
    var html = pug.renderFile("./lib/post.pug", {
        actionUrl: "http://hello",
        pendingRequestValue: pendingRequestValue
    });
    console.log(html);
    test.done();
};