import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATv2Conv, LayerNorm


class GAT(nn.Module):
    """
    A robust and flexible Graph Attention Network (GAT) model.
    """

    def __init__(
        self,
        in_channels,
        hidden_channels,
        out_channels,
        num_layers=2,
        heads=8,
        dropout=0.6,
        edge_dim=None,
        act=F.elu,
    ):
        super().__init__()
        self.dropout = dropout
        self.act = act
        self.convs = nn.ModuleList()
        self.norms = nn.ModuleList()
        self.skips = nn.ModuleList()

        # Input layer
        if num_layers == 1:
            self.convs.append(
                GATv2Conv(
                    in_channels, out_channels, heads=1, concat=False, edge_dim=edge_dim
                )
            )
            self.skips.append(nn.Linear(in_channels, out_channels))
        else:
            self.convs.append(
                GATv2Conv(in_channels, hidden_channels, heads=heads, edge_dim=edge_dim)
            )
            self.skips.append(nn.Linear(in_channels, hidden_channels * heads))
            self.norms.append(LayerNorm(hidden_channels * heads))

        # Hidden layers
        for _ in range(num_layers - 2):
            self.convs.append(
                GATv2Conv(
                    hidden_channels * heads,
                    hidden_channels,
                    heads=heads,
                    edge_dim=edge_dim,
                )
            )
            self.skips.append(
                nn.Linear(hidden_channels * heads, hidden_channels * heads)
            )
            self.norms.append(LayerNorm(hidden_channels * heads))

        # Output layer
        if num_layers > 1:
            self.convs.append(
                GATv2Conv(
                    hidden_channels * heads,
                    out_channels,
                    heads=1,
                    concat=False,
                    edge_dim=edge_dim,
                )
            )
            self.skips.append(nn.Linear(hidden_channels * heads, out_channels))

    def forward(self, x, edge_index, edge_attr=None, return_embedding=False):
        for i in range(len(self.convs)):
            x_res = self.skips[i](x)
            x = self.convs[i](x, edge_index, edge_attr=edge_attr) + x_res

            if i < len(self.convs) - 1:
                x = self.norms[i](x)
                x = self.act(x)
                x = F.dropout(x, p=self.dropout, training=self.training)
        return x


class HybridGAT(nn.Module):
    def __init__(
        self,
        in_channels,
        hidden_channels,
        out_channels,
        edge_dim,
        mlp_hidden_channels,
        num_layers=2,
        heads=8,
        dropout=0.6,
    ):
        super().__init__()

        self.gnn = GAT(
            in_channels=in_channels,
            hidden_channels=hidden_channels,
            out_channels=hidden_channels,
            edge_dim=edge_dim,
            num_layers=num_layers,
            heads=heads,
            dropout=dropout,
        )

        self.mlp = nn.Sequential(
            nn.Linear(in_channels + hidden_channels, mlp_hidden_channels),
            nn.ReLU(),
            nn.Dropout(p=dropout),
            nn.Linear(mlp_hidden_channels, out_channels),
        )

    def forward(self, x, edge_index, edge_attr=None, return_embedding=False):
        original_features = x
        gnn_embedding = self.gnn(x, edge_index, edge_attr)
        #  If requested, return the powerful GNN embedding for visualization
        if return_embedding:
            return gnn_embedding
        hybrid_features = torch.cat([original_features, gnn_embedding], dim=1)
        return self.mlp(hybrid_features)
