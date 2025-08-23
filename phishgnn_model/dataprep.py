import pandas as pd
import numpy as np
import torch
from sklearn.preprocessing import StandardScaler
import seaborn as sns
import matplotlib.pyplot as plt
import config as cfg

pd.options.mode.chained_assignment = None


def load_data(nodes_path, edges_path):
    """Loads node and edge data from CSV files."""
    nodes_df = pd.read_csv(
        nodes_path, encoding="latin1", low_memory=False, on_bad_lines="warn"
    )
    edges_df = pd.read_csv(
        edges_path, encoding="latin1", low_memory=False, on_bad_lines="warn"
    )
    return nodes_df, edges_df


def preprocess_data(nodes_df, edges_df):
    """
    Performs full preprocessing of nodes and edges, including text features.
    Returns all components needed to build a PyG Data object.
    """
    print(f"Original node count: {len(nodes_df)}")
    nodes_df.replace("", np.nan, inplace=True) # Replace empty strings from Go with NaN
    nodes_df["status_code"] = pd.to_numeric(
        nodes_df["status_code"], errors="coerce"
    ).fillna(-1)
    nodes_df = nodes_df[nodes_df["status_code"] == 200].copy()
    print(f"Node count after filtering for status code 200: {len(nodes_df)}")

    # Filter edges to remove any links to/from the deleted nodes
    valid_urls = set(nodes_df["url"])
    original_edge_count = len(edges_df)
    edges_df = edges_df[
        edges_df["Source"].isin(valid_urls) & edges_df["url"].isin(valid_urls)
    ].copy()
    print(
        f"Edge count filtered from {original_edge_count} to {len(edges_df)} to maintain integrity."
    )

    # Node Preprocessing
    url_to_idx = {url: i for i, url in enumerate(nodes_df["url"])}

    reliability_map = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    nodes_df["cert_reliability"] = (
        nodes_df["cert_reliability"].map(reliability_map).fillna(0)
    )

    # Process boolean columns
    for col in cfg.BOOLEAN_NODE_COLS:
        # Convert boolean-like columns to numeric, fill any NaNs with 0
        nodes_df[col] = pd.to_numeric(nodes_df[col], errors='coerce').fillna(0).astype(int)


    # For string columns, create a boolean indicating if a value is present
    for col in cfg.STRING_NODE_COLS_AS_BOOLEAN:
        nodes_df[col] = nodes_df[col].notna().astype(int)

    # THIS IS THE CORRECTED SECTION FOR NUMERICAL FEATURES ---
    # 1. Select numerical features and ensure they are numeric type
    numerical_features_df = nodes_df[cfg.NUMERICAL_NODE_COLS].apply(pd.to_numeric, errors='coerce')

    # ADD THIS CODE BLOCK FOR THE CORRELATION HEATMAP ---
    print("\n--- Generating Feature Correlation Heatmap ---")
    plt.figure(figsize=(20, 16))
    correlation_matrix = numerical_features_df.corr()
    sns.heatmap(correlation_matrix, cmap='coolwarm', annot=False)
    plt.title('Correlation Matrix of Numerical Node Features')
    plt.tight_layout()
    save_path = "feature_correlation_heatmap.png"
    plt.savefig(save_path)
    print(f"Feature correlation heatmap saved to '{save_path}'\n")
    plt.close()
    
    # 2. Calculate the mean for each column (for imputation) and save it
    imputation_values = numerical_features_df.mean().to_dict()

    # 3. Impute (fill) missing values using the calculated means
    numerical_features_df.fillna(imputation_values, inplace=True)

    # 4. Scale the clean, imputed data
    scaler = StandardScaler()
    scaled_numerical = scaler.fit_transform(numerical_features_df)
    # END OF CORRECTION

    # Combine all features
    boolean_features = nodes_df[
        cfg.BOOLEAN_NODE_COLS + cfg.STRING_NODE_COLS_AS_BOOLEAN
    ].values
    combined_features = np.concatenate([scaled_numerical, boolean_features], axis=1)
    x = torch.tensor(combined_features, dtype=torch.float)

    is_phishing_clean = pd.to_numeric(nodes_df["is_phishing"], errors="coerce").fillna(
        0
    )
    y = torch.tensor(is_phishing_clean.values, dtype=torch.long)

    # Data Summary
    print("\n--- Data Summary ---")
    counts = is_phishing_clean.value_counts()
    benign_count = counts.get(0, 0)
    phishing_count = counts.get(1, 0)
    print(f"Total Nodes: {len(nodes_df)}")
    print(f"Benign (0): {benign_count}")
    print(f"Phishing (1): {phishing_count}")
    print("--------------------\n")

    # Edge Preprocessing (no changes needed here)
    source_idx = edges_df["Source"].map(url_to_idx)
    target_idx = edges_df["url"].map(url_to_idx)

    edge_index_df = pd.DataFrame({"Source": source_idx, "Target": target_idx})
    valid_indices = edge_index_df.dropna().index

    edge_index_df = edge_index_df.loc[valid_indices]
    edges_df = edges_df.loc[valid_indices]

    edge_index_np = np.stack(
        [edge_index_df["Source"].values, edge_index_df["Target"].values]
    )
    edge_index = torch.tensor(edge_index_np, dtype=torch.long)

    numeric_edge_features = (
        edges_df[cfg.EDGE_FEATURE_COLS].apply(pd.to_numeric, errors="coerce").fillna(0)
    )
    edge_attr = torch.tensor(numeric_edge_features.values, dtype=torch.float)
    print(f"Edge features created with shape: {edge_attr.shape}")

    # Save the imputation values along with the scaler
    preprocessor = {
        "url_to_idx": url_to_idx,
        "scaler": scaler,
        "imputation_values": imputation_values,
        "feature_order": {
            "numerical": cfg.NUMERICAL_NODE_COLS,
            "boolean": cfg.BOOLEAN_NODE_COLS + cfg.STRING_NODE_COLS_AS_BOOLEAN,
        },
    }

    return x, y, edge_index, edge_attr, preprocessor