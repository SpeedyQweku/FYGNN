import torch

# --- Machine Learning Configuration ---
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
TRAIN_SPLIT = 0.8
VAL_SPLIT = 0.10  # TEST_SPLIT is automatically the remainder (0.15)


# --- MODIFIED: Added Mini-Batching Hyperparameters ---
NUM_WORKERS = 4  # For the data loader
BATCH_SIZE = 514  # Number of nodes to process in a single batch
NUM_NEIGHBORS = [
    20,
    15,
]  # For each node, sample 15 neighbors at 1 hop, and for each of those, sample 10 neighbors at 2 hops

# --- GAT Model Hyperparameters ---
GNN_HIDDEN_CHANNELS = 128  # For the GAT part of the hybrid model
MLP_HIDDEN_CHANNELS = 64  # For the MLP part of the hybrid model
NUM_HEADS = 8
DROPOUT = 0.5
# DROPOUT = 0.7
LEARNING_RATE = 0.001
# LEARNING_RATE = 0.005
# WEIGHT_DECAY = 5e-5
WEIGHT_DECAY = 1e-4
EPOCHS = 100  # We can often use fewer epochs with mini-batching
PATIENCE = 50  # For early stopping



# --- Data Paths ---
# NODES_PATH = "../../data/nodes.csv"
NODES_PATH = "./data/nodes.csv"
# EDGES_PATH = "../../data/edges.csv"
EDGES_PATH = "./data/edges.csv"
PROCESSED_DATA_DIR = "./processed_data"
MODEL_SAVE_PATH = "./saved_models/gat_model.pt"
PREPROCESSOR_SAVE_PATH = "./saved_models/preprocessor.pkl"


# --- Feature Configuration ---
NUMERICAL_NODE_COLS = [
    "url_length",
    "domain_url_length",
    "subdomain_count",
    "path_segment_count",
    "digit_letter_ratio",
    "domain_age",
    "anchors_count",
    "forms_count",
    "javascript_count",
    "obfuscated_js_count",
    "self_anchors_count",
    "use_mouseover",
    "mean_word_length",
    "distinct_words_count",
    "status_code",
    "redirects",
    "depth",
    "cert_reliability",
    "cert_age_days",
    "domain_cert_age_ratio",
]

BOOLEAN_NODE_COLS = [
    "path_starts_with_url",
    "has_at_symbol",
    "dashes_count",
    "sensitive_words_in_url",
    "is_ip_address",
    "uses_homograph_trick",
    "has_random_looking_str",
    "contains_encoded_chars",
    "is_https",
    "is_cert_valid",
    "has_spf",
    "has_dmarc",
    "has_dns_record",
    "has_whois",
    "is_valid_html",
    "is_error_page",
    "has_form_with_url",
    "has_iframe",
]

# For now, we will treat these as boolean (present or not).
# A more advanced approach could use one-hot encoding.
STRING_NODE_COLS_AS_BOOLEAN = [
    "cert_country",
    "cert_issuer_organization",
    "domain_creation_date",
    "domain_end_period",
]


# This list remains for numerical/boolean edge features
EDGE_FEATURE_COLS = ["is_same_domain", "is_form", "is_anchor", "is_iframe"]
