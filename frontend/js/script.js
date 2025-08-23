document.addEventListener('DOMContentLoaded', () => {
    const content = document.getElementById('app-content');
    const navLinks = document.querySelectorAll('.nav-link');
    const pages = {
        training: document.getElementById('page-training').innerHTML,
        predict: document.getElementById('page-predict').innerHTML,
        dashboard: document.getElementById('page-dashboard').innerHTML,
    };

    const socket = io("http://127.0.0.1:5000");
    let totalGraphsAvailable = 0;
    let currentGraphIndex = 0;

    // --- Socket.IO Event Handlers ---
    socket.on('connect', () => {
        console.log('Connected to backend server.');
        const activeTerminal = document.querySelector('.terminal');
        if (activeTerminal && activeTerminal.querySelector('p').textContent === 'Waiting for backend connection...') {
            activeTerminal.innerHTML = '<p>Backend connected. Ready for instructions.</p><div class="cursor"></div>';
        }
    });

    socket.on('disconnect', () => {
        console.log('Disconnected from backend server.');
        const activeTerminal = document.querySelector('.terminal');
        if (activeTerminal) {
            addTextToTerminal(activeTerminal, '\nError: Disconnected from backend server.');
        }
    });

    socket.on('terminal_output', (msg) => {
        const activeTerminal = document.querySelector('.terminal');
        if (activeTerminal) {
            addTextToTerminal(activeTerminal, msg.data);
        }
    });

    socket.on('visualizations_ready', (data) => {
        totalGraphsAvailable = data.num_graphs;
        const timestamp = new Date().getTime();

        const plotImg = document.querySelector('.dashboard-item img');
        if (plotImg) plotImg.src = `${data.plot_url}?v=${timestamp}`;

        const trainingDashboard = document.getElementById('training-dashboard');
        if (trainingDashboard) {
            currentGraphIndex = 0;
            renderGraph('train');
            trainingDashboard.classList.remove('hidden');
        }
        const mainDashboard = document.querySelector('#app-content .dashboard-container:not(#training-dashboard)');
        if (mainDashboard) {
            currentGraphIndex = 0;
            renderGraph('main');
        }
    });

    socket.on('dashboard_status', (data) => {
        totalGraphsAvailable = data.num_graphs;
        const timestamp = new Date().getTime();

        const plotImg = document.getElementById('dashboard-tsne-plot-img');
        if (plotImg && data.plot_exists) {
            plotImg.src = `/viz/embedding_plot.png?v=${timestamp}`;
        }

        if (totalGraphsAvailable > 0) {
            currentGraphIndex = 0;
            renderGraph('main');
        }
    });

    // --- Core Functions ---
    function renderGraph(prefix) {
        const frame = document.getElementById(`${prefix}-graph-viz-frame`);
        const infoEl = document.getElementById(`${prefix}-graph-info`);
        const prevBtn = document.getElementById(`${prefix}-prev-graph-btn`);
        const nextBtn = document.getElementById(`${prefix}-next-graph-btn`);

        if (!frame || !infoEl || !prevBtn || !nextBtn) return;

        if (totalGraphsAvailable > 0) {
            const timestamp = new Date().getTime();
            frame.src = `/viz/graph/${currentGraphIndex}?v=${timestamp}`;
            infoEl.textContent = `Graph ${currentGraphIndex + 1} / ${totalGraphsAvailable}`;
            prevBtn.disabled = currentGraphIndex === 0;
            nextBtn.disabled = currentGraphIndex >= totalGraphsAvailable - 1;
        } else {
            infoEl.textContent = `Graph 0 / 0`;
            prevBtn.disabled = true;
            nextBtn.disabled = true;
        }
    }

    function setupGraphControls(prefix) {
        const prevBtn = document.getElementById(`${prefix}-prev-graph-btn`);
        const nextBtn = document.getElementById(`${prefix}-next-graph-btn`);
        if (prevBtn && nextBtn) {
            prevBtn.addEventListener('click', () => {
                if (currentGraphIndex > 0) {
                    currentGraphIndex--;
                    renderGraph(prefix);
                }
            });
            nextBtn.addEventListener('click', () => {
                if (currentGraphIndex < totalGraphsAvailable - 1) {
                    currentGraphIndex++;
                    renderGraph(prefix);
                }
            });
        }
    }

    // --- Page Initialization ---
    function loadPage(page) {
        content.innerHTML = pages[page];
        if (page === 'training') initTrainingPage();
        else if (page === 'predict') initPredictPage();
        else if (page === 'dashboard') initDashboardPage();
    }

    function initTrainingPage() {
        const fileInput = document.getElementById('file-upload');
        const fileNameEl = document.getElementById('file-name');
        const startBtn = document.getElementById('start-train-btn');
        const terminal = document.getElementById('terminal-train');
        const enableParamsCheck = document.getElementById('enable-params-train');
        const paramsContainer = document.getElementById('params-container-train');
        const depthInput = document.getElementById('depth-train');
        const workersInput = document.getElementById('workers-train');
        const isPhishCheck = document.getElementById('isphish-train');
        const trainingDashboard = document.getElementById('training-dashboard');

        const trainExistingBtn = document.getElementById('train-existing-btn');

        trainExistingBtn.addEventListener('click', () => {
            if (trainExistingBtn.classList.contains('processing') || startBtn.classList.contains('processing')) return;

            terminal.innerHTML = '<div class="cursor"></div>';
            trainingDashboard.classList.add('hidden');

            // Disable both buttons
            startBtn.classList.add('processing');
            trainExistingBtn.classList.add('processing');
            trainExistingBtn.textContent = 'Processing';
            startBtn.disabled = true;
            trainExistingBtn.disabled = true;

            socket.emit('start_training_from_existing');
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                fileNameEl.textContent = fileInput.files[0].name;
                startBtn.disabled = false;
                startBtn.textContent = 'Start Crawler & Training';
            }
        });

        enableParamsCheck.addEventListener('change', () => {
            const isDisabled = !enableParamsCheck.checked;
            paramsContainer.classList.toggle('disabled', isDisabled);
            depthInput.disabled = isDisabled;
            workersInput.disabled = isDisabled;
            isPhishCheck.disabled = isDisabled;
        });

        startBtn.addEventListener('click', () => {
            if (startBtn.classList.contains('processing') || trainExistingBtn.classList.contains('processing')) return;
            const file = fileInput.files[0];
            if (!file) { alert('Please select a file first.'); return; }

            const reader = new FileReader();
            reader.onload = (e) => {
                terminal.innerHTML = '<div class="cursor"></div>';
                trainingDashboard.classList.add('hidden');

                // Disable both buttons
                startBtn.classList.add('processing');
                trainExistingBtn.classList.add('processing');
                startBtn.textContent = 'Processing';
                startBtn.disabled = true;
                trainExistingBtn.disabled = true;

                socket.emit('start_training', {
                    fileName: file.name,
                    fileContent: e.target.result,
                    params: {
                        enable: enableParamsCheck.checked,
                        depth: depthInput.value,
                        workers: workersInput.value,
                        isPhishing: isPhishCheck.checked,
                    }
                });
            };
            reader.readAsText(file);
        });

        // UPDATE THIS FUNCTION
        socket.on('terminal_output', (msg) => {
            const currentStartBtn = document.getElementById('start-train-btn');
            const currentTrainExistingBtn = document.getElementById('train-existing-btn');
            if (!currentStartBtn) return; // Only run this logic if we are on the training page

            // On completion or failure, reset both buttons
            if (msg.data.includes('--- Visualization generation complete! ---') || msg.data.includes('--- Aborting ---')) {
                currentStartBtn.classList.remove('processing');
                currentTrainExistingBtn.classList.remove('processing');

                currentStartBtn.textContent = 'Start Crawler & Training';
                currentTrainExistingBtn.textContent = 'Train from Existing CSVs';

                // Only re-enable the file upload button if a file is selected
                currentStartBtn.disabled = !fileInput.files || fileInput.files.length === 0;
                currentTrainExistingBtn.disabled = false;
            }
        });
        setupGraphControls('train');
    }


    function initPredictPage() {
        const urlInput = document.getElementById('url-input');
        const analyzeBtn = document.getElementById('analyze-url-btn');
        const terminal = document.getElementById('terminal-predict');
        const enableParamsCheck = document.getElementById('enable-params-predict');
        const paramsContainer = document.getElementById('params-container-predict');
        const depthInput = document.getElementById('depth-predict');
        const workersInput = document.getElementById('workers-predict');

        enableParamsCheck.addEventListener('change', () => {
            const isDisabled = !enableParamsCheck.checked;
            paramsContainer.classList.toggle('disabled', isDisabled);
            depthInput.disabled = isDisabled;
            workersInput.disabled = isDisabled; 
        });

        analyzeBtn.addEventListener('click', () => {
            if (analyzeBtn.classList.contains('processing')) return;
            const url = urlInput.value;
            if (!url || !url.startsWith('http')) {
                alert('Please enter a valid URL (e.g., https://example.com).');
                return;
            }

            terminal.innerHTML = '<div class="cursor"></div>';
            analyzeBtn.classList.add('processing');
            analyzeBtn.textContent = 'Analyzing';
            analyzeBtn.disabled = true;

            socket.emit('predict_url', {
                url: url,
                params: {
                    enable: enableParamsCheck.checked,
                    depth: depthInput.value,
                    workers: workersInput.value, // Send the workers value
                }
            });
        });

        socket.on('prediction_result', (result) => {
            const currentAnalyzeBtn = document.getElementById('analyze-url-btn');
            if (!currentAnalyzeBtn) return;

            const resultText = `\n>>>> PREDICTION: ${result.verdict} | Confidence: ${(result.confidence * 100).toFixed(2)}% <<<<\n`;
            addTextToTerminal(terminal, resultText);
            currentAnalyzeBtn.classList.remove('processing');
            currentAnalyzeBtn.textContent = 'Analyze';
            currentAnalyzeBtn.disabled = false;
        });

        socket.on('terminal_output', (msg) => {
            const currentAnalyzeBtn = document.getElementById('analyze-url-btn');
            if (!currentAnalyzeBtn) return;
            if (msg.data.includes('--- Aborting ---')) {
                currentAnalyzeBtn.classList.remove('processing');
                currentAnalyzeBtn.textContent = 'Analyze';
                currentAnalyzeBtn.disabled = false;
            }
        });
    }

    function initDashboardPage() {
        socket.emit('request_dashboard_status');
        setupGraphControls('main');
    }

    // --- Initial Load & Navigation ---
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const page = e.target.getAttribute('data-page');
            navLinks.forEach(l => l.classList.remove('active'));
            e.target.classList.add('active');
            window.location.hash = page;
            loadPage(page);
        });
    });

    const initialPage = window.location.hash.substring(1) || 'training';
    navLinks.forEach(l => l.classList.toggle('active', l.getAttribute('data-page') === initialPage));
    loadPage(initialPage);


    function addTextToTerminal(terminalEl, text) {
        if (!terminalEl) return;

        // A simple check to see if the text is a progress bar update
        const isProgressBar = text.includes('%|') && text.includes('it/s');
        const cursor = terminalEl.querySelector('.cursor');

        if (isProgressBar) {
            let lastLineElement = cursor ? cursor.previousElementSibling : terminalEl.lastElementChild;

            if (lastLineElement && lastLineElement.textContent.includes('%|')) {
                lastLineElement.textContent = text.trim();
            } else {
                const p = document.createElement('p');
                p.textContent = text.trim();
                if (cursor) {
                    cursor.before(p);
                } else {
                    terminalEl.appendChild(p);
                }
            }
        } else {
            const p = document.createElement('p');
            p.textContent = text;
            if (cursor) {
                cursor.before(p);
            } else {
                terminalEl.appendChild(p);
            }
        }

        terminalEl.scrollTop = terminalEl.scrollHeight;
    }
});