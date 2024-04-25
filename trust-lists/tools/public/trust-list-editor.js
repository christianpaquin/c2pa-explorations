const currentVersion = "0.1";

function getCurrentIsoTime() {
    return new Date().toISOString().slice(0, "YYYY-MM-DDTHH:MM:SS".length) + 'Z';
}

function isoToLocalTime(isoTime) {
    if (!isoTime) {
        return '';
    }
    return new Date(isoTime).toLocaleString();
}

let trustList = {
    name: "",
    download_url: "",
    description: "",
    website: "",
    last_updated: getCurrentIsoTime(),
    version: currentVersion,
    entities: []
};

function showError(errMsg) {
    errMsgElem = document.getElementById('errorMsg');
    errMsgElem.textContent = errMsg;
    errMsgElem.style.display = 'block';
}

function clearError() {
    errMsgElem = document.getElementById('errorMsg');
    errMsgElem.textContent = '';
    errMsgElem.style.display = 'none';
}

function validateAndUpdateName(inputValue, inputElement, field = undefined, index = 0) {
    clearError();
    inputValue = inputValue.trim();
    let name = inputValue;
    if (field === 'entity-display_name') {
        trustList.entities[index].display_name = name;
    } else if (field === 'info-name') {
        trustList.name = name;
    }
    // update value in the input field
    inputElement.value = name;
}

function validateAndUpdateURL(inputValue, inputElement, field, index = 0) {
    clearError();
    inputValue = inputValue.trim();
    if (inputValue) {
        let validatedURL = inputValue; // initial value
        // prepend 'https://' if missing
        if (!/^https?:\/\//i.test(inputValue)) {
            validatedURL = 'https://' + inputValue;
        }
        // validate the URL
        const nonDomainChars = "a-zA-Z0-9-_.!~*'();:@&=+$,";
        const fullUrlPattern = `(\\?[${nonDomainChars}/%]+)?(#[a-zA-Z0-9-_.!~*'();:@&=+$,/%]+)?`;
        const validURLPattern = new RegExp(`^https:\\/\\/` + // https protocol
                                    `[a-zA-Z0-9.-]+` + // (sub)domain name
                                    `(\\.[a-zA-Z]{2,})` + // top level domain
                                    `(\\/[${nonDomainChars}]+(\\/[${nonDomainChars}]+)*)?\\/??` + // path
                                    `${fullUrlPattern}$`, "i"); // query params and anchor
        if (!validURLPattern.test(validatedURL)) {
            let urlField;
            if (field === 'info-download_url') {
                urlField = "trust list's download URL";
            } else if (field === 'info-website') {
                urlField = "trust list's website";
            } else if (field === 'entity-contact') {
                urlField = "entity's contact";
            }
            showError(`Please enter a valid URL for the ${urlField}`);
            return;
        }
        // update the trust list
        if (field === 'info-download_url') {
            trustList.download_url = validatedURL;
        } else if (field === 'info-website') {
            trustList.website = validatedURL;
        } else if (field === 'entity-contact') {
            trustList.entities[index].contact = validatedURL;
        }
        // update value in the input field
        inputElement.value = validatedURL;
    }
}

function validateAndUpdateBoolean(inputValue, inputElement, field, index) {
    const booleanValue = inputValue === 'true';
    if (field === 'entity-display_name') {
        trustList.entities[index].isCA = booleanValue;
    }
}

function saveTrustList() {
    const trustListJson = document.getElementById('trustListTextArea').value;
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(trustListJson);
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", "trust-list.json");
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
}

function initializeTrustListInfo() {
    clearError();
    document.getElementById('trustListName').value = trustList.name || '';
    document.getElementById('trustListDownloadUrl').value = trustList.download_url || '';
    document.getElementById('trustListDescription').value = trustList.description || '';
    document.getElementById('trustListWebsite').value = trustList.website || '';
    document.getElementById('trustListVersion').value = currentVersion; // always save to latest version
    document.getElementById('trustListUpdated').value = isoToLocalTime(getCurrentIsoTime());
}

function createNewTrustList() {
    // Re-initialize the trust list fields (if edited previously)
    trustList.name = "";
    trustList.download_url = "";
    trustList.description = "";
    trustList.website = "";
    trustList.entities = [];
    // Display the initialized trust list info and clear entities table
    initializeTrustListInfo();
    updateEntitiesTable();
    document.getElementById('trustListContent').style.display = 'block';
}

function loadFile(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            trustList = JSON.parse(e.target.result);
            displayTrustList();
            document.getElementById('trustListContent').style.display = 'block';
        } catch (err) {
            showError("Failed to parse the trust list.");
        }
    };
    reader.readAsText(file);
}

function displayTrustList() {
    initializeTrustListInfo();
    updateEntitiesTable();
}

function addEntity() {
    trustList.entities.push({ display_name: "", contact: "", isCA: false, jwks: ""});
    updateEntitiesTable();
}

function convertIsoToDatetimeLocal(isoString) {
    if(!isoString) return '';
    
    let date = new Date(isoString);
    if(isNaN(date)) return ''; // return an empty string if the date is invalid
    
    let year = date.getUTCFullYear();
    let month = (date.getUTCMonth() + 1).toString().padStart(2, '0'); // months are 0-indexed in JS
    let day = date.getUTCDate().toString().padStart(2, '0');
    let hours = date.getUTCHours().toString().padStart(2, '0');
    let minutes = date.getUTCMinutes().toString().padStart(2, '0');
    
    return `${year}-${month}-${day}T${hours}:${minutes}`;
}

function deleteEntity(index) {
    trustList.entities.splice(index, 1);
    updateEntitiesTable();
}

function saveToFile() {
    // Update timestamp
    trustList.last_updated = getCurrentIsoTime();
    // Make sure we save to the latest version (in case we read an older version)
    trustList.version = currentVersion;
    // Delete the accounts and content arrays if they are empty
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(trustList, null, 4));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", "trust-list.json");
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
}
