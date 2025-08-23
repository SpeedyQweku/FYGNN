import torch
import pickle
import numpy as np
from torch_geometric.data import InMemoryDataset, Data
from dataprep import load_data, preprocess_data
from sklearn.model_selection import train_test_split
import config as cfg


class PhishingDataset(InMemoryDataset):
    """Dataset for HOMOGENEOUS models like GAT."""

    def __init__(self, root, transform=None, pre_transform=None):
        super().__init__(root, transform, pre_transform)
        self.data, self.slices = torch.load(self.processed_paths[0], weights_only=False)

    @property
    def raw_file_names(self):
        return [cfg.NODES_PATH, cfg.EDGES_PATH]

    @property
    def processed_file_names(self):
        return ["homogeneous_data.pt"]

    def download(self):
        pass

    def process(self):
        nodes_df, edges_df = load_data(cfg.NODES_PATH, cfg.EDGES_PATH)
        x, y, edge_index, edge_attr, preprocessor = preprocess_data(nodes_df, edges_df)

        data = Data(x=x, edge_index=edge_index, edge_attr=edge_attr, y=y)

        # Add train/val/test masks
        num_nodes = data.num_nodes
        indices = np.arange(num_nodes)
        labels = data.y.cpu().numpy()

        # Split indices into train and temp (val + test)
        train_indices, temp_indices = train_test_split(
            indices,
            train_size=cfg.TRAIN_SPLIT,
            stratify=labels, # Stratify based on the labels
            random_state=42
        )
        
        # Split temp indices into val and test
        val_indices, test_indices = train_test_split(
            temp_indices,
            test_size=0.5,
            stratify=labels[temp_indices],
            random_state=42
        )
        
        data.train_mask = torch.zeros(num_nodes, dtype=torch.bool)
        data.val_mask = torch.zeros(num_nodes, dtype=torch.bool)
        data.test_mask = torch.zeros(num_nodes, dtype=torch.bool)
        
        data.train_mask[train_indices] = True
        data.val_mask[val_indices] = True
        data.test_mask[test_indices] = True

        torch.save(self.collate([data]), self.processed_paths[0])
        with open(cfg.PREPROCESSOR_SAVE_PATH, 'wb') as f:
            pickle.dump(preprocessor, f)
