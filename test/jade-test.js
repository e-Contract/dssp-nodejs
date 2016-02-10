"use strict";

var jade = require('jade');

exports['test Jade'] = function (test) {
    var pendingRequestValue = new Buffer("PendingRequestValue").toString("base64");
    var html = jade.renderFile("./lib/post.jade", {
        actionUrl: "http://hello",
        pendingRequestValue: pendingRequestValue
    });
    console.log(html);
    test.done();
};