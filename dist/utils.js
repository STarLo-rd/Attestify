"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AttestationError = exports.Attest = void 0;
var Attest;
(function (Attest) {
    Attest["INITIATED"] = "INITIATED";
    Attest["ACKNOWLEDGED"] = "ACKNOWLEDGED";
    Attest["EFFECTIVE"] = "EFFECTIVE";
    Attest["DISCHARGED"] = "DISCHARGED";
})(Attest || (exports.Attest = Attest = {}));
class AttestationError extends Error {
    constructor(message, code) {
        super(message);
        this.code = code;
        this.name = 'AttestationError';
    }
}
exports.AttestationError = AttestationError;
