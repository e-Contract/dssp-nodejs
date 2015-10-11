"use strict";

var jade = require('jade');

exports['test Jade'] = function (test) {
    var html = jade.renderFile("./lib/post.jade", {
        actionUrl: "http://hello",
        pendingRequestValue: "PendingRequestValue"
    });
    console.log(html);
    test.done();
};