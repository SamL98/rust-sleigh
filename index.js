import init, { 
    disassemble, bytes, context
} from "./pkg/sleigh.js";

let sleighCtx = undefined;
let fileBytes = undefined;

function setColor(off, color) {
    for (let i = 0; i < 4; i++) {
        let o = off + i;
        if (o < fileBytes.length) {
            let elem = document.getElementById('byte' + o);
            elem.style.color = color;
        }
    }
}

function getWord(off) {
    let word = 0;
    for (let i = 0; i < 4; i++) {
        let o = off + i;
        if (o < fileBytes.length)
            word = (word << 8) | fileBytes[o];
    }
    return word;
}

function displayInstruction(insn) {
    const container = document.getElementById('list-container');

    const collapsible = document.createElement('div');
    collapsible.className = 'collapsible';
    collapsible.textContent = insn['address'].to_string() + ' ' + insn['asm'];
    container.appendChild(collapsible);

    insn['ops'].forEach((op) => {
        const content = document.createElement('div');
        content.className = 'content';
        content.textContent = '  ' + op.to_string();

        collapsible.addEventListener('click', () => {
            content.style.display = content.style.display === 'block' ? 'none' : 'block';
        });

        container.appendChild(content);
    });
}

function displayEvent(state, idx, off) {
    const wordView = document.getElementById('event-view');
    wordView.innerHTML = ''
    wordView.appendChild(state.render_event(idx, sleighCtx));

    let dtView = document.getElementById('decision-tree');

    if (dtView !== undefined) {
        let path = dtView.getAttribute('path').split(',').map((e) => parseInt(e));
        console.log(path);
        let nodeView = dtView;

        path.forEach((ix, j) => {
            nodeView = nodeView.firstElementChild.nextSibling.firstElementChild;

            for (let i = 0; i < ix; i++)
                nodeView = nodeView.nextSibling;

            if (j < path.length - 1)
                nodeView = nodeView.firstElementChild;
        });

        dtView.scrollTop = nodeView.offsetTop - dtView.offsetTop;
        nodeView.classList.add('selected');
    }
};

init().then(() => {
    sleighCtx = context();
    fileBytes = bytes();
    let insnStates = disassemble(sleighCtx);
    let off = 0;

    const hexView = document.getElementById('hex-view');
    let byteStrings = [];

    // Cannot map because it converts to Uint8Array.
    fileBytes.forEach((n, i) => { 
        let s = n.toString(16).padStart(2, '0');
        byteStrings.push('<span id=byte' + i + '>' + s + '</span>');
    });
    hexView.innerHTML = byteStrings.join(' ');

    setColor(0, fileBytes.length, 'red');
    insnStates.forEach(state => displayInstruction(state['insn']));

    let insnIdx = 0;
    let eventIdx = 0;

    displayEvent(insnStates[0], eventIdx, off);

    document.getElementById('next').addEventListener('click', () => {
        if (eventIdx == insnStates[insnIdx]['num_events'] - 1 && insnIdx < insn.length - 1) {
            setColor(off, 'black');
            off += insnStates[insnIdx]['insn']['bit_len'] / 8;
            setColor(off, 'red');

            insnIdx += 1;
            eventIdx = 0;
        } else if (eventIdx < insnStates[insnIdx]['num_events']) {
            eventIdx += 1;
        }

        displayEvent(insnStates[insnIdx], eventIdx, off);
    });

    document.getElementById('prev').addEventListener('click', () => {
        if (eventIdx == 0 && insnIdx > 0) {
            setColor(off, 'black');
            off -= insnStates[insIdx - 1]['insn']['bit_len'] / 8;
            setColor(off, 'red');

            insnIdx -= 1;
            eventIdx = insnStates[insnIdx]['num_events'] - 1;
        } else if (eventIdx > 0) {
            eventIdx -= 1;
        }

        displayEvent(insnStates[insnIdx], eventIdx, off);
    });
});
