export function sync_fetch(url) {
    const xhr = new XMLHttpRequest();
    xhr.open("GET", url, false);
    xhr.send();
    if (xhr.status === 200) {
        return xhr.responseText;
    } else {
        throw new Error(`Request failed with status: ${xhr.status}`);
    }
}

export function create_div(children) {
    let div = document.createElement('div');
    children.forEach(child => div.appendChild(child));
    return div;
}

export function create_p(text) {
    let p = document.createElement('p');
    p.innerHTML = text;
    return p;
}

export function create_ul(lis) {
    let ul = document.createElement('ul');
    lis.forEach(li => ul.appendChild(li));
    return ul;
}

export function create_li(content) {
    let li = document.createElement('li');
    li.innerHTML = content;
    return li;
}
