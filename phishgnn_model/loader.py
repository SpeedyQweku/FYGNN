from torch_geometric.loader import NeighborLoader
import config as cfg

def create_data_loaders(data):
    """Creates train, validation, and test data loaders with neighbor sampling."""
    
    # Create a loader for the training set
    train_loader = NeighborLoader(
        data,
        num_neighbors=cfg.NUM_NEIGHBORS,
        batch_size=cfg.BATCH_SIZE,
        input_nodes=data.train_mask,
        shuffle=True,
        num_workers=cfg.NUM_WORKERS,
        persistent_workers=True if cfg.NUM_WORKERS > 0 else False
    )

    # Create a loader for the validation set
    val_loader = NeighborLoader(
        data,
        num_neighbors=[-1], # For validation/testing, we can use all neighbors
        batch_size=cfg.BATCH_SIZE,
        input_nodes=data.val_mask,
        num_workers=cfg.NUM_WORKERS,
        persistent_workers=True if cfg.NUM_WORKERS > 0 else False
    )

    # Create a loader for the test set
    test_loader = NeighborLoader(
        data,
        num_neighbors=[-1],
        batch_size=cfg.BATCH_SIZE,
        input_nodes=data.test_mask,
        num_workers=cfg.NUM_WORKERS,
        persistent_workers=True if cfg.NUM_WORKERS > 0 else False
    )
    
    return train_loader, val_loader, test_loader