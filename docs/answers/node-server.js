var http = require("http");

var server = http.createServer(function (req, res) {
    res.writeHead(200, {"Content-Type": "text/plain"});
    res.end("Sample node.js server, returns contents in any path.\n");
});

var port = process.env.PORT || 8081;
server.listen(port, function() {
    console.log("Do curl http://localhost:" + port);
});
