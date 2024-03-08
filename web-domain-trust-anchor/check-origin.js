const fs = require('fs');
const { program } = require('commander');

function getOriginUrl(json) {
    const assertions = json.assertions;
    for (const assertion of assertions) {
      if (assertion.data && assertion.data.author) {
        for (const author of assertion.data.author) {
          if (author.url) {
            return author.url;
          }
        }
      }
    }
    return null;
  }

  function pemToString(pem) {
    // Remove the "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----" lines, as well as newline characters
    return pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\r\n|\n|\r/gm, '');
  }

const main = async (options) => {
    if (!options.manifest || !options.certs) {
        console.log("Missing --manifest or --certs argument");
        program.help();
    }
    try {
        // read the manifest.json file
        const manifest = JSON.parse(fs.readFileSync(options.manifest, 'utf8'));
        if (!manifest) {
            throw new Error("Invalid manifest");
        }
        if (manifest.validation_status) {
            throw "Asset validation failed: " + JSON.stringify(manifest.validation_status);
        }

        // get the active manifest
        const activeManifest = manifest.manifests[manifest.active_manifest];
        // get the certificate in the JSON Web Key set (JWKS) located at "<origin URL>/c2pa.json"
        let signerCert;
        let originUrl;
        if (activeManifest) {
            originUrl = getOriginUrl(activeManifest);
            if (originUrl) {
                console.log("Origin URL: " + originUrl);
                const jwksUrl = new URL(originUrl + "/c2pa.json");
                console.log("Fetching JWKS from: " + jwksUrl);
                // fetch the origin URL
                const response = await fetch(jwksUrl);
                // parse the response as a JSON object
                const jwks = await response.json();
                if (jwks && jwks.keys) {
                    // get the first key
                    const key = jwks.keys[0];
                    // check if a x5c property is present
                    if (key.x5c) {
                        signerCert = key.x5c[0];
                    } 
                } else {
                    throw new Error("Invalid JWKS: no certficate found");
                }
            }
        }

        // read the certificate chain
        const cert = fs.readFileSync(options.certs, 'utf8');
        if (!cert) {
            throw new Error("Invalid certificate chain in " + options.certs);
        }

        // compare the retrieved cert with the one in the certificate chain
        if (signerCert !== pemToString(cert)) {
            throw new Error("Certificate mismatch between the asset and the origin URL");
        }

        console.log("Valid asset signed by " + originUrl);
    } catch (err) {
        console.log(err);
    }
}

program.option('-m, --manifest <manifest>', 'path to a c2pa manifest');
program.option('-c, --certs <certs>', 'path to a certificate chain');
program.parse(process.argv);
main(program.opts());
