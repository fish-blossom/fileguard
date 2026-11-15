'use strict';
function daysBetween(a, b) { return Math.round((new Date(b) - new Date(a)) / 86400000); }
console.log(daysBetween('2026-01-01', process.argv[2] || '2026-12-31'));
