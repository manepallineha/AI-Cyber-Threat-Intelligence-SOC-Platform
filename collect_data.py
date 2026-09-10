import pandas as pd

df = pd.read_csv("data/cybersecurity.csv")

print(df.head())
print("\nColumns:")
print(df.columns)
print("\nInfo:")
print(df.info())