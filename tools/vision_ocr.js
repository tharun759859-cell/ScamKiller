// SCAM KILLER — Native macOS Apple Vision Framework OCR Helper
// Uses Apple's built-in Vision Framework via JavaScript for Automation (JXA)
// Offline, zero external dependencies, privacy-preserving.

ObjC.import("Foundation");
ObjC.import("Vision");

function run(argv) {
    if (!argv || argv.length < 1) {
        return "";
    }
    var imagePath = argv[0];
    var url = $.NSURL.fileURLWithPath($(imagePath));
    var handler = $.VNImageRequestHandler.alloc.initWithURLOptions(url, $());
    if (!handler) {
        return "";
    }

    var request = $.VNRecognizeTextRequest.alloc.init;
    request.recognitionLevel = 0; // 0 = Accurate, 1 = Fast
    request.usesLanguageCorrection = true;

    var requests = $.NSArray.arrayWithObject(request);
    var err = Ref();
    var ok = handler.performRequestsError(requests, err);
    if (!ok) {
        return "";
    }

    var results = request.results;
    if (!results || results.count === 0) {
        return "";
    }

    var count = results.count;
    var lines = [];
    for (var i = 0; i < count; i++) {
        var obs = results.objectAtIndex(i);
        var candidates = obs.topCandidates(1);
        if (candidates.count > 0) {
            lines.push(ObjC.unwrap(candidates.objectAtIndex(0).string));
        }
    }
    return lines.join("\n");
}
