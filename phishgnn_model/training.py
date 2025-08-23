# training.py
import torch
import os
import time
from sklearn.metrics import (
    precision_recall_fscore_support,
    accuracy_score,
    confusion_matrix,
)
from tqdm import tqdm
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from dataset import PhishingDataset
from models import HybridGAT
from loader import create_data_loaders
import config as cfg


def train(model, train_loader, optimizer, criterion):
    model.train()
    total_loss = total_examples = 0

    for batch in tqdm(train_loader, desc="Training"):
        batch = batch.to(cfg.DEVICE)
        optimizer.zero_grad()

        # The model only sees the nodes in the current mini-batch
        out = model(batch.x, batch.edge_index, batch.edge_attr)

        # Loss is calculated only on the seed nodes of the batch
        loss = criterion(out[: batch.batch_size], batch.y[: batch.batch_size])

        loss.backward()
        optimizer.step()

        total_loss += loss.item() * batch.batch_size
        total_examples += batch.batch_size

    return total_loss / total_examples


@torch.no_grad()
def test(model, loader):
    model.eval()
    all_preds = []
    all_labels = []

    for batch in tqdm(loader, desc="Evaluating"):
        batch = batch.to(cfg.DEVICE)
        out = model(batch.x, batch.edge_index, batch.edge_attr)

        preds = out.argmax(dim=-1)[: batch.batch_size]
        all_preds.append(preds.cpu())
        all_labels.append(batch.y[: batch.batch_size].cpu())

    all_preds = torch.cat(all_preds, dim=0)
    all_labels = torch.cat(all_labels, dim=0)

    # Calculate additional metrics
    p, r, f1, _ = precision_recall_fscore_support(
        all_labels, all_preds, average="binary", zero_division=0
    )
    acc = accuracy_score(all_labels, all_preds)
    cm = confusion_matrix(all_labels, all_preds)

    # p, r, f1, _ = precision_recall_fscore_support(all_labels, all_preds, average='binary', zero_division=0)

    return p, r, f1, acc, cm


# Function to save results to a file
def save_metrics_to_file(train_metrics, val_metrics, test_metrics, timestamp):
    """Saves a formatted report of the model's performance to a timestamped text file."""
    # timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"training_results_{timestamp}.txt"

    # Unpack all metrics
    train_p, train_r, train_f1, train_acc, train_cm = train_metrics
    val_p, val_r, val_f1, val_acc, val_cm = val_metrics
    test_p, test_r, test_f1, test_acc, test_cm = test_metrics

    # Get confusion matrix components for the test set for detailed explanation
    tn, fp, fn, tp = test_cm.ravel()

    with open(filename, "a+") as f:
        f.write(f"Training Results - {timestamp}\n")
        f.write("=" * 40 + "\n\n")

        f.write("--- Training Set ---\n")
        f.write(f"Accuracy:  {train_acc:.4f}\n")
        f.write(f"Precision: {train_p:.4f}\n")
        f.write(f"Recall:    {train_r:.4f}\n")
        f.write(f"F1-Score:  {train_f1:.4f}\n")
        f.write(f"Confusion Matrix:\n{train_cm}\n\n")

        f.write("--- Validation Set ---\n")
        f.write(f"Accuracy:  {val_acc:.4f}\n")
        f.write(f"Precision: {val_p:.4f}\n")
        f.write(f"Recall:    {val_r:.4f}\n")
        f.write(f"F1-Score:  {val_f1:.4f}\n")
        f.write(f"Confusion Matrix:\n{val_cm}\n\n")

        f.write("--- Test Set ---\n")
        f.write(f"Accuracy:  {test_acc:.4f}\n")
        f.write(f"Precision: {test_p:.4f}\n")
        f.write(f"Recall:    {test_r:.4f}\n")
        f.write(f"F1-Score:  {test_f1:.4f}\n")
        f.write(f"Confusion Matrix:\n{test_cm}\n\n")

        f.write("--- Test Set Breakdown ---\n")
        f.write(f"True Positives (Phishing correctly identified):  {tp}\n")
        f.write(f"True Negatives (Benign correctly identified):   {tn}\n")
        f.write(f"False Positives (Benign misclassified as Phishing): {fp}\n")
        f.write(f"False Negatives (Phishing misclassified as Benign): {fn}\n")

    print(f"\nResults and metrics saved to '{filename}'")



def plot_and_save_history(history, timestamp):
    """Plots training loss and validation F1/accuracy and saves the plot."""
    fig, ax1 = plt.subplots(figsize=(12, 8))
    
    # Plot training loss
    color = 'tab:red'
    ax1.set_xlabel('Epoch')
    ax1.set_ylabel('Training Loss', color=color)
    ax1.plot(history['loss'], color=color, label='Training Loss')
    ax1.tick_params(axis='y', labelcolor=color)
    
    # Create a second y-axis for validation metrics
    ax2 = ax1.twinx()
    color = 'tab:blue'
    ax2.set_ylabel('Validation F1 / Accuracy', color=color)
    ax2.plot(history['val_f1'], color='tab:blue', linestyle='-', label='Validation F1')
    ax2.plot(history['val_acc'], color='tab:green', linestyle='--', label='Validation Accuracy')
    ax2.tick_params(axis='y', labelcolor=color)
    
    fig.suptitle('Model Training History', fontsize=16)
    fig.tight_layout(rect=[0, 0.03, 1, 0.95])
    
    # Add a single legend for all lines
    lines, labels = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax2.legend(lines + lines2, labels + labels2, loc='center right')

    save_path = f"training_history_{timestamp}.png"
    plt.savefig(save_path)
    print(f"\nTraining history plot saved to '{save_path}'")



def plot_confusion_matrix(cm, class_names, timestamp, normalize=False, output_dir="."):
    """
    Generates and saves a heatmap for the confusion matrix.
    
    Args:
        cm (array-like): Confusion matrix data.
        class_names (list): List of class names for labels.
        timestamp (str): Unique timestamp for filename.
        normalize (bool): Whether to normalize values to percentages.
        output_dir (str): Directory to save the heatmap.
    """
    if normalize:
        cm = cm.astype("float") / cm.sum(axis=1)[:, np.newaxis]
        fmt = ".2f"
    else:
        fmt = "d"

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    plt.figure(figsize=(8, 6))
    sns.heatmap(
        cm,
        annot=True,
        fmt=fmt,
        cmap="Blues",
        xticklabels=class_names,
        yticklabels=class_names
    )
    plt.ylabel("Actual Label")
    plt.xlabel("Predicted Label")
    plt.title("Confusion Matrix" + (" (Normalized)" if normalize else ""))
    plt.tight_layout()

    save_path = os.path.join(output_dir, f"confusion_matrix_{timestamp}.png")
    plt.savefig(save_path)
    print(f"Confusion matrix heatmap saved to '{save_path}'")
    plt.close()



def main():
    os.makedirs(os.path.dirname(cfg.MODEL_SAVE_PATH), exist_ok=True)

    # Data preparation is the same, it creates one large data.pt file
    dataset = PhishingDataset(root=cfg.PROCESSED_DATA_DIR)
    data = dataset[0]

    # Create the mini-batch data loaders
    train_loader, val_loader, test_loader = create_data_loaders(data)

    model = HybridGAT(
        in_channels=dataset.num_node_features,
        hidden_channels=cfg.GNN_HIDDEN_CHANNELS,
        out_channels=dataset.num_classes,
        edge_dim=data.edge_attr.shape[1],
        mlp_hidden_channels=cfg.MLP_HIDDEN_CHANNELS,
        num_layers=2,
        heads=cfg.NUM_HEADS,
        dropout=cfg.DROPOUT,
    )

    model = model.to(cfg.DEVICE)
    optimizer = torch.optim.Adam(
        model.parameters(), lr=cfg.LEARNING_RATE, weight_decay=cfg.WEIGHT_DECAY
    )

    # Class weights for imbalanced dataset (logic is the same)
    train_labels = data.y[data.train_mask]
    num_class_0 = (train_labels == 0).sum().item()
    num_class_1 = (train_labels == 1).sum().item()
    weight_for_class_1 = (
        float(num_class_0) / float(num_class_1) if num_class_1 > 0 else 1.0
    )
    class_weights = torch.tensor([1.0, weight_for_class_1], device=cfg.DEVICE)
    criterion = torch.nn.CrossEntropyLoss(weight=class_weights)

    best_val_f1 = 0
    patience_counter = 0
    
    # ADD THESE LINES
    history = {
        "loss": [],
        "val_f1": [],
        "val_acc": []
    }


    print("--- Starting Scalable Model Training with Mini-Batching ---")
    for epoch in range(1, cfg.EPOCHS + 1):
        loss = train(model, train_loader, optimizer, criterion)
        val_p, val_r, val_f1,  val_acc, _ = test(model, val_loader)
        
        print(
            f"Epoch: {epoch:03d}, Loss: {loss:.4f}, Val F1: {val_f1:.4f}, Val Precision: {val_p:.4f}, Val Recall: {val_r:.4f}, Val Accuacy: {val_acc:.4f}"
        )
        # ADD THESE LINES
        history["loss"].append(loss)
        history["val_f1"].append(val_f1)
        history["val_acc"].append(val_acc)

        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            torch.save(model.state_dict(), cfg.MODEL_SAVE_PATH)
            patience_counter = 0
            print(f"  -> New best model saved with Val F1: {val_f1:.4f}")
        else:
            patience_counter += 1

        if patience_counter >= cfg.PATIENCE:
            print("Early stopping triggered.")
            break

    print("\n--- Training Finished ---")
    if os.path.exists(cfg.MODEL_SAVE_PATH):
        print(f"Model saved to '{cfg.MODEL_SAVE_PATH}'")
        print(f"Loading best model from '{cfg.MODEL_SAVE_PATH}'")
        model.load_state_dict(torch.load(cfg.MODEL_SAVE_PATH))
    else:
        print(
            "Model did not improve and was not saved. Try adjusting hyperparameters or dataset balance."
        )
        return

    # Evaluate and save all metrics
    train_p, train_r, train_f1, train_acc, train_cm = test(model, train_loader)
    val_p, val_r, val_f1, val_acc, val_cm = test(model, val_loader)
    test_p, test_r, test_f1, test_acc, test_cm = test(model, test_loader)

    print("\n--- Final Model Performance ---")
    print(f"Train F1: {train_f1:.4f}, Precision: {train_p:.4f}, Recall: {train_r:.4f}, Accuacy: {val_acc:.4f}")
    print(f"Validation F1: {val_f1:.4f}, Precision: {val_p:.4f}, Recall: {val_r:.4f}, Accuacy: {val_acc:.4f}")
    print(f"Test F1: {test_f1:.4f}, Precision: {test_p:.4f}, Recall: {test_r:.4f}, Accuacy: {val_acc:.4f}")

    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")

    # Call the new function to save the report
    save_metrics_to_file(
        (train_p, train_r, train_f1, train_acc, train_cm),
        (val_p, val_r, val_f1, val_acc, val_cm),
        (test_p, test_r, test_f1, test_acc, test_cm),
        timestamp
    )
    plot_and_save_history(history, timestamp)
    
    # ADD THIS CALL FOR THE TEST SET
    class_names = ['Benign', 'Phishing']
    plot_confusion_matrix(test_cm, class_names, f"test_{timestamp}")


if __name__ == "__main__":
    main()
