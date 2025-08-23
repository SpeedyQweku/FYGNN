import os
import subprocess
import json
from flask import Flask, render_template, send_from_directory, abort
from flask_socketio import SocketIO, emit


# Configuration
BACKEND_ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.join(BACKEND_ROOT_DIR, "..", "frontend")
PHISHCRAWLER_DIR = os.path.join(BACKEND_ROOT_DIR, "..", "phishcrawler_go")
PHISHGNN_DIR = os.path.join(BACKEND_ROOT_DIR, "..", "phishgnn_model")
UPLOAD_FOLDER = os.path.join(PHISHCRAWLER_DIR, "uploads")
VIZ_FOLDER = os.path.join(PHISHGNN_DIR, "visualization")
GRAPHS_DIR = os.path.join(VIZ_FOLDER, "graphs_html")

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Flask App Initialization
app = Flask(
    __name__,
    template_folder=FRONTEND_FOLDER,
    static_folder=FRONTEND_FOLDER,
    static_url_path="",
)
app.config["SECRET_KEY"] = "your-very-secret-key!"
socketio = SocketIO(app, cors_allowed_origins="*")


# Helper Functions
def run_command_and_stream_output(command, working_dir):
    try:
        process = subprocess.Popen(
            command,
            cwd=working_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )
        for line in iter(process.stdout.readline, ""):
            print(line, end="")
            socketio.emit("terminal_output", {"data": line})
            socketio.sleep(0.01)
        process.stdout.close()
        if process.wait() != 0:
            raise subprocess.CalledProcessError(process.returncode, command)
        return True
    except Exception as e:
        error_message = f"\nAn error occurred: {str(e)}\n--- Aborting ---\n"
        socketio.emit("terminal_output", {"data": error_message})
        return False


def run_command_and_capture_output(command, working_dir, input_data=None):
    try:
        process = subprocess.Popen(
            command,
            cwd=working_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = process.communicate(input=input_data)
        if stderr:
            socketio.emit("terminal_output", {"data": stderr})
        if process.returncode != 0:
            raise subprocess.CalledProcessError(
                process.returncode, command, output=stdout, stderr=stderr
            )
        return stdout
    except Exception as e:
        error_message = (
            f"\nAn error occurred during capture: {str(e)}\n--- Aborting ---\n"
        )
        socketio.emit("terminal_output", {"data": error_message})
        return None


# Routes and SocketIO Events
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/viz/<path:filename>")
def serve_visualization(filename):
    return send_from_directory(VIZ_FOLDER, filename)


@app.route("/viz/graph/<int:index>")
def serve_graph_html(index):
    """Serves a single graph HTML file by its index."""
    filename = f"graph_{index}.html"
    try:
        return send_from_directory(GRAPHS_DIR, filename)
    except FileNotFoundError:
        abort(404)


@socketio.on("connect")
def handle_connect():
    print("Client connected")
    emit("terminal_output", {"data": "Backend server connected successfully.\n"})


@socketio.on("request_dashboard_status")
def handle_dashboard_status():
    """Checks if visualization files exist and informs the client."""
    num_graphs = 0
    if os.path.exists(GRAPHS_DIR):
        num_graphs = len(
            [
                name
                for name in os.listdir(GRAPHS_DIR)
                if name.startswith("graph_") and name.endswith(".html")
            ]
        )

    plot_exists = os.path.exists(os.path.join(VIZ_FOLDER, "embedding_plot.png"))

    emit("dashboard_status", {"num_graphs": num_graphs, "plot_exists": plot_exists})


@socketio.on("start_training")
def handle_start_training(json_data):
    file_content = json_data.get("fileContent")
    original_filename = json_data.get("fileName")
    params = json_data.get("params", {})
    uploaded_file_path = os.path.join(UPLOAD_FOLDER, original_filename)
    with open(uploaded_file_path, "w") as f:
        f.write(file_content)
    emit(
        "terminal_output", {"data": f'File "{original_filename}" saved successfully.\n'}
    )
    emit("terminal_output", {"data": "\n--- Starting Phishcrawler ---\n"})
    relative_file_path = os.path.join("uploads", original_filename)
    crawler_command = [
        "go",
        "run",
        "main.go",
        "-urls",
        relative_file_path,
        "-savecsv",
    ]
    if params.get("enable"):
        crawler_command.extend(["-depth", str(params.get("depth", 2))])
        crawler_command.extend(["-w", str(params.get("workers", 50))])
        if params.get("isPhishing"):
            crawler_command.append("-isphish")
    if not run_command_and_stream_output(crawler_command, PHISHCRAWLER_DIR):
        return
    emit("terminal_output", {"data": "\n--- Phishcrawler finished successfully. ---\n"})
    emit("terminal_output", {"data": "\n--- Starting Model Training ---\n"})
    training_command = ["python", "training.py"]
    if not run_command_and_stream_output(training_command, PHISHGNN_DIR):
        return
    emit(
        "terminal_output", {"data": "\n--- Model training finished successfully! ---\n"}
    )

    emit("terminal_output", {"data": "\n--- Generating Visualizations ---\n"})
    viz_graphs_command = [
        "python",
        "visualization.py",
        "generate-graphs",
        "--num_graphs",
        "10",
    ]
    run_command_and_stream_output(viz_graphs_command, PHISHGNN_DIR)
    viz_plot_command = ["python", "visualization.py", "plot-embeddings"]
    run_command_and_stream_output(viz_plot_command, PHISHGNN_DIR)
    emit("terminal_output", {"data": "\n--- Visualization generation complete! ---\n"})

    emit(
        "visualizations_ready",
        {"plot_url": "/viz/embedding_plot.png", "num_graphs": 10},
    )


@socketio.on('start_training_from_existing')
def handle_training_from_existing():
    """
    Starts the training and visualization process using pre-existing
    nodes.csv and edges.csv files, skipping the crawler.
    """
    nodes_path = os.path.join(PHISHGNN_DIR, 'data', 'nodes.csv')
    edges_path = os.path.join(PHISHGNN_DIR, 'data', 'edges.csv')

    if not os.path.exists(nodes_path) or not os.path.exists(edges_path):
        emit('terminal_output', {
            'data': '\n--- Error: nodes.csv or edges.csv not found. Please run the crawler first. ---\n--- Aborting ---\n'
        })
        return

    emit('terminal_output', {'data': '\n--- Skipping Phishcrawler. Starting Model Training from existing data. ---\n'})

    # Run Model Training
    training_command = ['python', 'training.py']
    if not run_command_and_stream_output(training_command, PHISHGNN_DIR):
        return
    emit('terminal_output', {'data': '\n--- Model training finished successfully! ---\n'})

    # Run Visualization Generation
    emit('terminal_output', {'data': '\n--- Generating Visualizations ---\n'})
    viz_graphs_command = ['python', 'visualization.py', 'generate-graphs', '--num_graphs', '10']
    run_command_and_stream_output(viz_graphs_command, PHISHGNN_DIR)
    viz_plot_command = ['python', 'visualization.py', 'plot-embeddings']
    run_command_and_stream_output(viz_plot_command, PHISHGNN_DIR)
    emit('terminal_output', {'data': '\n--- Visualization generation complete! ---\n'})

    # Notify the frontend that visualizations are ready
    emit('visualizations_ready', {
        'plot_url': '/viz/embedding_plot.png',
        'num_graphs': 10
    })

@socketio.on("predict_url")
def handle_predict_url(json_data):
    url_to_predict = json_data.get("url")
    params = json_data.get("params", {})
    emit(
        "terminal_output",
        {"data": f"Received prediction request for: {url_to_predict}\n"},
    )

    emit(
        "terminal_output",
        {"data": "\n--- Running Phishcrawler to extract features ---\n"},
    )

    crawler_command = ["go", "run", "main.go", "-url", url_to_predict, "-opjs"]

    # Check for custom parameters
    if params.get("enable"):
        crawler_command.extend(["-depth", str(params.get("depth", 1))])
        # Add the workers parameter to the command
        crawler_command.extend(["-w", str(params.get("workers", 50))])

    json_features_str = run_command_and_capture_output(
        crawler_command, PHISHCRAWLER_DIR
    )

    if not json_features_str:
        return

    try:
        features = json.loads(json_features_str)
        if features.get("status_code") != 200:
            emit(
                "terminal_output",
                {
                    "data": f"\n--- Error: A live URL with a status code of 200 is required. Got {features.get('status_code', 'N/A')}. ---\n--- Aborting ---\n"
                },
            )
            return
    except json.JSONDecodeError:
        emit(
            "terminal_output",
            {
                "data": "\n--- Error: Could not parse feature data from crawler. ---\n--- Aborting ---\n"
            },
        )
        return

    emit("terminal_output", {"data": "Features extracted successfully.\n"})
    emit("terminal_output", {"data": "\n--- Running GNN model for prediction ---\n"})
    prediction_command = ["python", "predict.py"]
    prediction_result_str = run_command_and_capture_output(
        prediction_command, PHISHGNN_DIR, input_data=json_features_str
    )

    if not prediction_result_str:
        return
    try:
        prediction_result = json.loads(prediction_result_str)
        emit("prediction_result", prediction_result)
        emit(
            "terminal_output",
            {
                "data": f'\n--- Prediction Complete: {prediction_result["verdict"]} (Confidence: {prediction_result["confidence"]:.2%}) ---\n'
            },
        )
    except json.JSONDecodeError:
        emit(
            "terminal_output",
            {"data": "\n--- Error: Could not parse prediction result. ---\n"},
        )


if __name__ == "__main__":
    print("Starting Flask server with SocketIO...")
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
