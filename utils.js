export function sync_fetch(url) {
    const xhr = new XMLHttpRequest();
    xhr.open("GET", url, false); // Synchronous request
    xhr.send();
    if (xhr.status === 200) {
        return xhr.responseText;
    } else {
        throw new Error(`Request failed with status: ${xhr.status}`);
    }
}
