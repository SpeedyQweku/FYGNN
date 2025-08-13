import pandas as pd
import config as cfg  # Your script needs to know where the file is

try:
    # Load your nodes.csv file
    nodes_df = pd.read_csv(cfg.NODES_PATH, encoding="latin1", on_bad_lines="skip")
    print(f"--- Data Diagnosis for '{cfg.NODES_PATH}' ---")
    print("✅ Successfully loaded the file.")
    print(f"Total rows (URLs) found: {len(nodes_df)}")

    # Check if the 'status_code' column exists
    if "status_code" in nodes_df.columns:
        # Convert status_code to a numeric type, making non-numbers into NaN
        nodes_df["status_code"] = pd.to_numeric(
            nodes_df["status_code"], errors="coerce"
        )

        print("\nDistribution of Status Codes:")
        print(nodes_df["status_code"].value_counts(dropna=False))

        # Count how many rows have a status code of 200
        num_successful = (nodes_df["status_code"] == 200).sum()
        print(f"\n👉 Rows with status_code 200: {num_successful}")

        if num_successful < 50:
            print("\n🚨 WARNING: Your dataset has very few usable nodes.")
            print(
                "This is the reason your final graph is too small for t-SNE and model training."
            )

    else:
        print(
            "\n❌ ERROR: The 'status_code' column was not found in your nodes.csv file!"
        )

except FileNotFoundError:
    print(
        f"❌ ERROR: Could not find the file at '{cfg.NODES_PATH}'. Please check the path in config.py."
    )

print("\n--- End of Diagnosis ---")
