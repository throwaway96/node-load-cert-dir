const fs = require("fs");
const path = require("path");

function createLogger(logLevel) {
  if (typeof logLevel !== "number") {
    throw new Error("invalid argument type (logLevel): " + typeof logLevel);
  }

  function _ignore() {}

  return {
    debug: logLevel <= 0 ? console.log : _ignore,
    verbose: logLevel <= 1 ? console.log : _ignore,
    info: logLevel <= 2 ? console.log : _ignore,
    warn: logLevel <= 3 ? console.warn : _ignore,
    error: logLevel <= 4 ? console.error : _ignore,
  };
}

const pemRegex =
  /-----BEGIN CERTIFICATE-----\n[^]+?\n-----END CERTIFICATE-----/g;

function readPem(file) {
  var results, content;

  if (typeof file !== "string") {
    throw new Error("invalid argument type: " + typeof file);
  }

  const newCAs = [];

  try {
    content = fs
      .readFileSync(file, { encoding: "ascii" })
      .trim()
      .replace(/\r\n/g, "\n");
  } catch (err) {
    throw new Error("error in read(" + file + "): " + err.message, {
      cause: err,
    });
  }

  if ((results = content.match(pemRegex)) === null) {
    throw new Error("could not parse PEM certificate(s)");
  }

  results.forEach(function pemIterate(match) {
    newCAs.push(match.trim());
  });

  return newCAs;
};

module.exports.loadCertDir = function loadCertDir(dir, options) {
  const rootCerts = [];
  var files, dirStat, logLevel, filterFunc = null;

  if (typeof dir !== "string") {
    throw new Error("invalid argument type (dir): " + typeof dir);
  }

  if (typeof options === "undefined") {
    options = {};
  } else if (typeof options !== "object") {
    throw new Error("invalid argument type (options): " + typeof options);
  }

  if (typeof options.filterFunc === "undefined") {
    filterFunc = null;
  } else if (typeof options.filterFunc === "function") {
    filterFunc = options.filterFunc;
  } else {
    throw new Error(
      "invalid argument type (options.filterFunc): " + typeof options.filterFunc
    );
  }

  if (typeof options.logLevel === "undefined") {
    logLevel = 3; /* 3 -> warnings */
  } else if (typeof options.logLevel === "number") {
    logLevel = options.logLevel;
  } else {
    throw new Error(
      "invalid argument type (options.logLevel): " + typeof options.logLevel
    );
  }

  const log = createLogger(logLevel);

  try {
    dirStat = fs.statSync(dir);
  } catch (err) {
    if (err.code === "ENOENT") {
      throw new Error("directory does not exist: " + dir, { cause: err });
    } else {
      throw new Error("error in stat(" + dir + "): " + err.message, {
        cause: err,
      });
    }
  }

  if (!dirStat.isDirectory()) {
    throw new Error("not a directory: " + dir);
  }

  try {
    files = fs.readdirSync(dir);
  } catch (err) {
    throw new Error("error in readdir(" + dir + "): " + err.message, {
      cause: err,
    });
  }

  files
    .map(function resolvePath(filename) {
      return path.resolve(dir, filename);
    })
    .forEach(function processFile(file) {
      var stat;

      try {
        stat = fs.statSync(file);
      } catch (err) {
        log.verbose("error in stat(" + file + "): " + err.message);
        return;
      }

      if (stat.isFile()) {
        try {
          readPem(file).forEach(function certIterate(cert) {
            if (rootCerts.indexOf(cert) !== -1) {
              log.debug("duplicate cert from " + file);
            } else if (filterFunc !== null && !filterFunc(cert, file)) {
              log.verbose("not adding filtered cert from " + file);
            } else {
              rootCerts.push(cert);
            }
          });
        } catch (err) {
          log.verbose("failed to read cert file " + file + ": " + err.message);
        }
      }
    });

  return rootCerts;
}
