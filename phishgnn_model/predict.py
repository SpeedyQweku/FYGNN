import torch
import torch.nn.functional as F
import numpy as np
import pandas as pd
import pickle
import sys
import json
from models import HybridGAT
import config as cfg

# Suppress the scikit-learn warning about feature names
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

def load_predictor():
    """Loads the trained model and preprocessor."""
    with open(cfg.PREPROCESSOR_SAVE_PATH, "rb") as f:
        preprocessor = pickle.load(f)

    num_node_features = len(preprocessor['feature_order']['numerical']) + len(preprocessor['feature_order']['boolean'])
    edge_dim = len(cfg.EDGE_FEATURE_COLS)

    model = HybridGAT(
        in_channels=num_node_features,
        hidden_channels=cfg.GNN_HIDDEN_CHANNELS,
        out_channels=2,
        edge_dim=edge_dim,
        mlp_hidden_channels=cfg.MLP_HIDDEN_CHANNELS,
        num_layers=2,
        heads=cfg.NUM_HEADS,
        dropout=cfg.DROPOUT
    )

    model.load_state_dict(torch.load(cfg.MODEL_SAVE_PATH, map_location=cfg.DEVICE))
    model.to(cfg.DEVICE)
    model.eval()
    return model, preprocessor

def predict_from_features(model, preprocessor, features_json):
    """Makes a prediction from a JSON object of features."""
    with torch.no_grad():
        # Preprocess Node Features
        feature_order = preprocessor['feature_order']
        imputation_values = preprocessor['imputation_values']

        # 1. Map cert_reliability string to its numerical value
        reliability_map = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
        cert_reliability_str = features_json.get('cert_reliability', 'LOW')
        features_json['cert_reliability'] = reliability_map.get(cert_reliability_str, 0)
        
        # 2. Process boolean and string-as-boolean features
        boolean_vals = []
        for col in cfg.BOOLEAN_NODE_COLS:
            # Use .get(col, 0) to default missing booleans to 0
            boolean_vals.append(features_json.get(col, 0))

        for col in cfg.STRING_NODE_COLS_AS_BOOLEAN:
            value = features_json.get(col)
            is_present = 1 if value is not None and value != "" else 0
            boolean_vals.append(is_present)
        
        # THIS IS THE CORRECTED SECTION FOR NUMERICAL FEATURES
        # 3. Get numerical values, using the saved imputation values for missing ones
        numerical_vals = []
        for col in feature_order['numerical']:
            # Get the value, if it's missing or None, use the saved mean from training
            value = features_json.get(col)
            if value is None or value == "":
                numerical_vals.append(imputation_values[col])
            else:
                numerical_vals.append(value)
        # END OF CORRECTION

        # 4. Scale the numerical features
        scaled_numerical = preprocessor["scaler"].transform(np.array([numerical_vals]))
        
        # 5. Create the final feature vector
        node_vector = np.concatenate([scaled_numerical, np.array([boolean_vals])], axis=1)
        x = torch.tensor(node_vector, dtype=torch.float).to(cfg.DEVICE)

        # Preprocess Edge Features (no changes needed here)
        link_features = features_json.get('refs', [])
        if link_features:
            # Ensure edge features are correctly coerced to numeric, default to 0
            numeric_edge_features = []
            for link in link_features:
                feature_row = [pd.to_numeric(link.get(col, 0), errors='coerce') for col in cfg.EDGE_FEATURE_COLS]
                numeric_edge_features.append(np.nan_to_num(feature_row).tolist())
            
            edge_attr = torch.tensor(numeric_edge_features, dtype=torch.float).to(cfg.DEVICE)
            edge_index = torch.zeros((2, len(link_features)), dtype=torch.long).to(cfg.DEVICE)
        else:
            edge_attr = torch.empty((0, len(cfg.EDGE_FEATURE_COLS))).to(cfg.DEVICE)
            edge_index = torch.empty((2, 0), dtype=torch.long).to(cfg.DEVICE)

        # Make Prediction
        out = model(x, edge_index, edge_attr)
        prob = F.softmax(out, dim=1)[0]
        pred = prob.argmax().item()

        verdict = "Phishing" if pred == 1 else "Benign"
        confidence = prob[pred].item()
        return verdict, confidence


def main():
    """
    Main function to be called from the backend.
    Reads features from stdin, makes a prediction, and prints result to stdout.
    """
    try:
        # 1. Load the model and preprocessor
        model, preprocessor = load_predictor()

        # 2. Read the JSON feature string from standard input
        input_json_str = sys.stdin.read()
        features_data = json.loads(input_json_str)
        
        url_to_predict = features_data.get('url', 'URL not found in data')
        print(f"--> Predicting for URL: {url_to_predict}", file=sys.stderr)

        # 3. Make a prediction
        verdict, confidence = predict_from_features(model, preprocessor, features_data)
        
        # 4. Print the result as a JSON string to standard output
        result = {
            'verdict': verdict,
            'confidence': confidence
        }
        print(json.dumps(result))

    except Exception as e:
        # If anything goes wrong, print the error to stderr
        print(f"Prediction script error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
