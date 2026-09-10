import pandas as pd
df = pd.read_csv("data/cybersecurity.csv")
print(df["attack_type"].value_counts())