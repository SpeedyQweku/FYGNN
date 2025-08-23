import torch
import os
import pickle
import argparse
import matplotlib.pyplot as plt
import networkx as nx
from pyvis.network import Network
from sklearn.manifold import TSNE
from tqdm import tqdm
from torch_geometric.utils import k_hop_subgraph

import config as cfg
from dataset import PhishingDataset
from models import HybridGAT

# Constants
ROOT_COLOR = "#0096FF"
BENIGN_COLOR = "#73FCD6"
PHISHING_COLOR = "#FF7E79"

def visualize_graph_to_html(nodes_in_subgraph, edge_index_subgraph, center_node, full_data, preprocessor, html_save_path):
    """ Creates an individual, interactive HTML file for a subgraph. """
    os.makedirs(os.path.dirname(html_save_path), exist_ok=True)

    node_set = set(nodes_in_subgraph.tolist())
    edges_list = [(u, v) for u, v in edge_index_subgraph.t().tolist() if u in node_set and v in node_set]
    
    G = nx.Graph()
    G.add_nodes_from(node_set)
    G.add_edges_from(edges_list)
    
    # Initialize the network to fill its container
    net = Network(height="100%", width="100%", directed=True, notebook=False, cdn_resources="in_line")
    net.from_nx(G)

    idx_to_url = {v: k for k, v in preprocessor["url_to_idx"].items()}
    for node in net.nodes:
        node_id = node["id"]
        is_phishing = full_data.y[node_id].item() == 1
        color = PHISHING_COLOR if is_phishing else BENIGN_COLOR
        size = 15
        if node_id == center_node:
            color = ROOT_COLOR
            size = 25
        node["color"] = color
        node["size"] = size
        node["title"] = f"URL: {idx_to_url.get(node_id, 'N/A')}<br>Label: {'Phishing' if is_phishing else 'Benign'}"
    
    net.set_options("""
    var options = {
      "physics": {
        "forceAtlas2Based": {
          "gravitationalConstant": -50,
          "centralGravity": 0.005,
          "springLength": 230,
          "springConstant": 0.18
        },
        "minVelocity": 0.75,
        "solver": "forceAtlas2Based"
      }
    }
    """)

    # Inject CSS to make the graph fill the entire iframe body.
    style_fix = """
    <style>
        html, body {
            width: 100%;
            height: 100%;
            margin: 0;
            padding: 0;
        }
        .card {
            width: 100%;
            height: 100%;
        }
    </style>
    """
    
    # Generate the graph HTML as a string
    html_content = net.generate_html()
    
    # Prepend the style fix to the generated HTML
    full_html = style_fix + html_content
    
    # Manually write the modified HTML to the file
    with open(html_save_path, "w", encoding="utf-8") as f:
        f.write(full_html)


def generate_graphs(num_graphs):
    """Generates individual HTML files for multiple subgraphs."""
    print(f"--- Generating HTML files for {num_graphs} subgraphs ---")
    
    save_dir = "./visualization/graphs_html"
    os.makedirs(save_dir, exist_ok=True)

    dataset = PhishingDataset(root=cfg.PROCESSED_DATA_DIR)
    data = dataset[0]
    with open(cfg.PREPROCESSOR_SAVE_PATH, "rb") as f:
        preprocessor = pickle.load(f)

    connected_nodes = torch.unique(data.edge_index)

    for i in tqdm(range(num_graphs), desc="Generating Subgraphs"):
        rand_idx = torch.randint(0, connected_nodes.numel(), (1,)).item()
        center_node = connected_nodes[rand_idx].item()
        nodes_in_subgraph, edge_index_subgraph, _, _ = k_hop_subgraph(
            center_node, num_hops=2, edge_index=data.edge_index, relabel_nodes=False
        )
        save_path = os.path.join(save_dir, f"graph_{i}.html")
        visualize_graph_to_html(
            nodes_in_subgraph, edge_index_subgraph, center_node, data, preprocessor, save_path
        )
    print(f"\nSuccessfully created {num_graphs} graph HTML files in '{save_dir}'")


def plot_embeddings(model_path):
    """Loads a trained HybridGAT model and plots its GNN embeddings using t-SNE."""
    print("--- Generating t-SNE plot of node embeddings ---")

    dataset = PhishingDataset(root=cfg.PROCESSED_DATA_DIR)
    data = dataset[0].to(cfg.DEVICE)

    model = HybridGAT(
        in_channels=dataset.num_node_features,
        hidden_channels=cfg.GNN_HIDDEN_CHANNELS,
        out_channels=dataset.num_classes,
        edge_dim=data.edge_attr.shape[1],
        mlp_hidden_channels=cfg.MLP_HIDDEN_CHANNELS,
        heads=cfg.NUM_HEADS,
        dropout=cfg.DROPOUT,
    )
    model.load_state_dict(torch.load(model_path, map_location=cfg.DEVICE))
    model.to(cfg.DEVICE)
    model.eval()

    with torch.no_grad():
        embs = model(
            data.x, data.edge_index, data.edge_attr, return_embedding=True
        ).cpu()

    n_samples = embs.shape[0]
    adjusted_perplexity = min(30, n_samples - 1)

    if adjusted_perplexity <= 1:
        print(f"Skipping t-SNE plot: Not enough data points ({n_samples}) for a meaningful visualization.")
        return

    print(f"Running t-SNE... (Using perplexity: {adjusted_perplexity})")
    tsne = TSNE(
        n_components=2,
        perplexity=adjusted_perplexity,
        learning_rate="auto",
        max_iter=1000,
        init="pca",
        random_state=42,
    )
    embs_2d = tsne.fit_transform(embs)

    plt.figure(figsize=(12, 12))
    colors = [PHISHING_COLOR if label == 1 else BENIGN_COLOR for label in data.y.cpu()]
    plt.scatter(embs_2d[:, 0], embs_2d[:, 1], c=colors, s=10, alpha=0.7)

    plt.title("t-SNE Visualization of Node Embeddings from GNN")
    save_path = "./visualization/embedding_plot.png"
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    plt.savefig(save_path)
    print(f"Embedding plot saved to '{save_path}'")


def main():
    parser = argparse.ArgumentParser(description="Visualization tools for the PhishGNN project.")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    parser_graphs = subparsers.add_parser("generate-graphs", help="Generate interactive HTML graph visualizations.")
    parser_graphs.add_argument("--num_graphs", type=int, default=10, help="Number of graphs to generate.")

    parser_embeddings = subparsers.add_parser("plot-embeddings", help="Generate a t-SNE plot of node embeddings from the trained GAT model.")
    parser_embeddings.add_argument("--model_path", type=str, default=cfg.MODEL_SAVE_PATH, help="Path to the trained HybridGAT model file.")

    args = parser.parse_args()

    if args.command == "generate-graphs":
        generate_graphs(args.num_graphs)
    elif args.command == "plot-embeddings":
        plot_embeddings(args.model_path)


if __name__ == "__main__":
    main()