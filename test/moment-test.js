"use strict";

var moment = require('moment');

exports['test moment'] = function (test) {
    console.log(moment().format());
    console.log(moment(new Date()).utc().toISOString());
    console.log(moment(new Date()).add(5, "m").utc().toISOString());
    test.done();
};