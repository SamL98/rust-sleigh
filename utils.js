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

export function generate_guid() {
    var S4 = function() {
       return (((1+Math.random())*0x10000)|0).toString(16).substring(1);
    };
    return (S4()+S4()+"-"+S4()+"-"+S4()+"-"+S4()+"-"+S4()+S4()+S4());
}

export function create_div(children) {
    let div = document.createElement('div');
    children.forEach(child => div.appendChild(child));
    return div;
}

export function create_span(text) {
    let span = document.createElement('span');
    span.innerText = text;
    return span;
}

export function create_p(text) {
    let p = document.createElement('p');
    p.innerText = text;
    return p;
}

export function create_button(text) {
    let button = document.createElement('button');
    button.innerText = text;
    return button;
}

export function create_ul(lis) {
    let ul = document.createElement('ul');
    ul.classList.add('no-bullets');
    lis.forEach(li => ul.appendChild(li));
    return ul;
}

export function create_li(child) {
    let li = document.createElement('li');
    li.appendChild(child);
    return li;
}

export function toggle_visible(elem) {
    elem.style.display = elem.style.display !== 'none' ? 'none' : 'block';
}
