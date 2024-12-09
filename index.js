import init, { 
    disassemble, bytes, context
} from "./pkg/sleigh.js";

function highlightSelectedDecisionNode() {
    let dtView = document.getElementById('decision-tree');

    if (dtView !== undefined && dtView !== null) {
        document.querySelectorAll('.selected').forEach(e => {
            e.classList.remove("selected")
        });

        let path = dtView.getAttribute('path').split(',').map((e) => parseInt(e));
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
}

class App {
    constructor(sleighCtx, fileBytes) {
        this.sleighCtx = sleighCtx;
        this.setBytes(fileBytes);
    }

    setBytes(bytes) {
        this.fileBytes = bytes;
        this.insnStates = disassemble(this.sleighCtx, this.fileBytes);

        this.displayInstructions();
        this.setInstructionIdx(0);

        let existingView = document.getElementById('hex-view');

        let hexView = document.createElement('div');
        hexView.id = 'hex-view';
        let byteStrings = [];

        // Cannot map because it converts to Uint8Array.
        this.fileBytes.forEach((n, i) => { 
            let s = n.toString(16).padStart(2, '0');
            byteStrings.push('<span id=byte' + i + '>' + s + '</span>');
        });
        hexView.innerHTML = byteStrings.join(' ');

        existingView.parentNode.replaceChild(hexView, existingView);
    }

    displayInstructions() {
        const container = document.getElementById('list-container');
        container.innerHTML = '';

        this.insnStates.forEach((state, i) => {
            let insn = state['insn'];

            const collapsible = document.createElement('div');
            collapsible.className = 'collapsible';
            collapsible.textContent = insn['address'].to_string() + ' ' + insn['asm'];
            container.appendChild(collapsible);

            container.addEventListener('click', () => {
                this.setInstructionIdx(i);
            });

            insn['ops'].forEach((op) => {
                const content = document.createElement('div');
                content.className = 'content';
                content.textContent = '  ' + op.to_string();

                collapsible.addEventListener('click', () => {
                    content.style.display = content.style.display === 'block' ? 'none' : 'block';
                });

                container.appendChild(content);
            });
        });
    }

    setInstructionIdx(insnIdx) {
        if (insnIdx != this.insnIdx) {
            this.insnIdx = insnIdx;
            this.insn = this.insnStates[this.insnIdx]['insn'];
            this.numEvents = this.insnStates[this.insnIdx]['num_events'];
            this.setEventIdx(0);
            console.log(this.numEvents + ' events for instruction');
        }
    }

    setEventIdx(eventIdx) {
        if (eventIdx != this.eventIdx) {
            console.log('Event ' + eventIdx);
            this.eventIdx = eventIdx;

            let state = this.insnStates[this.insnIdx];
            state.render_event(this.eventIdx, this.sleighCtx);

            highlightSelectedDecisionNode();
        }
    };

    editBytes() {
        let existingView = document.getElementById('hex-view');

        let editView = document.createElement('textarea');
        editView.id = 'hex-view';

        this.fileBytes.forEach((b, i) => {
            let s = b.toString(16);

            while (s.length < 2)
                s = '0' + s;

            editView.value += s;

            if (i < this.fileBytes.length - 1)
                editView.value += ' ';
        });

        existingView.parentNode.replaceChild(editView, existingView);
    }

    saveBytes() {
        let existingView = document.getElementById('hex-view');
        let newBytes = existingView.value.split(' ').map((b) => parseInt(b, 16));
        this.setBytes(newBytes);
    }

    incrementEventIdx() {
        if (this.eventIdx == this.numEvents - 1 && this.insnIdx < this.insnStates.length - 1) {
            this.off += this.insn['bit_len'] / 8;
            this.setInstructionIdx(this.insnIdx + 1);
        } else if (this.eventIdx < this.numEvents - 1) {
            this.setEventIdx(this.eventIdx + 1);
        }
    }

    decrementEventIdx() {
        if (this.eventIdx == 0 && this.insnIdx > 0) {
            this.off -= this.insnStates[this.insnIdx - 1]['insn']['bit_len'] / 8;
            this.setInstructionIdx(this.insnIdx - 1);
            this.setEventIdx(this.numEvents - 1);
        } else if (this.eventIdx > 0) {
            this.setEventIdx(this.eventIdx - 1);
        }
    }
}

init().then(() => {
    let sleighCtx = context();
    let fileBytes = bytes();
    let app = new App(sleighCtx, fileBytes);

    let editButton = document.getElementById('edit');
    let saveButton = document.getElementById('save');

    editButton.addEventListener('click', () => {
        editButton.disabled = true;
        saveButton.disabled = false;
        app.editBytes();
    });

    saveButton.addEventListener('click', () => {
        editButton.disabled = false;
        saveButton.disabled = true;
        app.saveBytes();
    });

    document.getElementById('next').addEventListener('click', () => {
        app.incrementEventIdx();
    });

    document.getElementById('prev').addEventListener('click', () => {
        app.decrementEventIdx();
    });
});
