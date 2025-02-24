import pandas as pd
import matplotlib.pyplot as plt
import os
import altair as alt

# ***** CONFIGURATION *****
CSV_FILE = "*.csv"  # Adjusted to use the DDSBuilder dataset
OUTPUT_DIR = "analysis_results"
# ***** END CONFIGURATION *****

# Create the output directory if it doesn't exist
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Carregar o arquivo CSV
df = pd.read_csv(CSV_FILE, sep=';', encoding='latin1')

# Convert 'published' to datetime objects
df['published'] = pd.to_datetime(df['published'], errors='coerce')

# Extract year, month, day of the week, and quarter
df['year'] = df['published'].dt.year
df['month'] = df['published'].dt.month
df['day_of_week'] = df['published'].dt.day_name()
df['quarter'] = df['published'].dt.quarter

# Normalize the 'vendor' column
#df['vendor'] = df['vendor'].str.lower().str.strip()

# Normalize the 'title' column to identify DDS implementations
dds_implementations = {
    "opendds": "Open DDS",
    "fastdds": "Fast DDS",
    "rti connext dds": "RTI Connext DDS",
    "Real Time Innovations (RTI)": "RTI Connext DDS",
    "cyclonedds": "Cyclone DDS",
    "coredx dds": "CoreDX DDS",
    "gurum dds": "Gurum DDS",
    "opensplice dds": "OpenSplice DDS",
    "mildds": "MilDDS",
    "All vendors": "Todos os Fabricantes",
    "Unknown": "Desconhecido",
    "Eclipse Foundation (Fast DDS)": "Fast DDS",
    "OpenImageIO Project": "Desconhecido",
    "JustSystems Corporation": "Desconhecido",
}

def normalize_implementation(vendor):
    for key, value in dds_implementations.items():
        if key in vendor.lower():
            return value
        
#df['vendor'] = df['vendor'].apply(normalize_implementation)

# --- Descriptive Analysis ---

# 1. Total Number of Vulnerabilities
total_vulnerabilities = len(df)
print(f"Total Number of Vulnerabilities: {total_vulnerabilities}")

# 2. Distribution of Vulnerabilities by Vendor
vendor_counts = df['vendor'].value_counts()
print("\nDistribution of Vulnerabilities by Vendor:")
print(vendor_counts)

# 3. Distribution of Vulnerabilities by Year
vulnerabilities_per_year = df['year'].value_counts().sort_index()
print("\nDistribution of Vulnerabilities by Year:")
print(vulnerabilities_per_year)

# 4. Distribution of CVSS Scores
print("\nDescriptive Statistics of CVSS Scores:")
print(df['cvss_score'].describe())

# 5. Top 5 Most Frequent CWE Categories
cwe_counts = df['cwe_category'].value_counts().head(5)
print("\nTop 5 Most Frequent CWE Categories:")
print(cwe_counts)

# 6. Correlation between Severity and Vendor
print("\nContingency Table between Severity and Vendor:")
contingency_table = pd.crosstab(df['vendor'], df['severity'])
print(contingency_table)

# --- Generating Charts ---

# Assuming df is the pandas DataFrame with the 'cvss_score' column
df['cvss_score'] = df['cvss_score'] / 10
df['vendor'] = df['vendor'].str.upper()  # Convert vendor names to uppercase
vendor_counts.index = vendor_counts.index.str.upper()  # Convert vendor names to uppercase
# Set font size
font_size = 14

# 1. Distribution of Vulnerabilities by Vendor (Bar Chart)
plt.figure(figsize=(10, 6))
vendor_counts.plot(kind='bar')
plt.title("Distribution of Vulnerabilities by Vendor", fontsize=font_size)
plt.xlabel("Vendor", fontsize=font_size)
plt.ylabel("Number of Vulnerabilities", fontsize=font_size)
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "vulnerabilities_by_vendor.png"))
plt.close()

# 2. Distribution of Vulnerabilities by Year (Line Chart)
plt.figure(figsize=(10, 6))
vulnerabilities_per_year.plot(kind='line', marker='o')
plt.title("Distribution of Vulnerabilities by Year", fontsize=font_size)
plt.xlabel("Year", fontsize=font_size)
plt.ylabel("Number of Vulnerabilities", fontsize=font_size)
plt.grid(True)
plt.savefig(os.path.join(OUTPUT_DIR, "vulnerabilities_by_year.png"))
plt.close()

# 3. Distribution of CVSS Scores (Histogram)
plt.figure(figsize=(10, 6))
plt.hist(df['cvss_score'], bins=10, edgecolor='black')
plt.title("Distribution of CVSS Scores", fontsize=font_size)
plt.xlabel("CVSS Score", fontsize=font_size)
plt.ylabel("Frequency", fontsize=font_size)
plt.savefig(os.path.join(OUTPUT_DIR, "cvss_distribution.png"))
plt.close()

# 4. Top 5 Most Frequent CWE Categories (Pie Chart)
plt.figure(figsize=(8, 8))
plt.pie(cwe_counts.values, labels=cwe_counts.index, autopct='%1.1f%%', startangle=90)
plt.title("Top 5 Most Frequent CWE Categories", fontsize=font_size)
plt.savefig(os.path.join(OUTPUT_DIR, "top_5_cwe.png"))
plt.close()

# --- Generating Reports with Altair ---

# 1. Vulnerabilities by Year and Vendor
chart_year_vendor = alt.Chart(df).mark_bar().encode(
    x='year:O',
    y='count()',
    color='vendor:N',
    tooltip=['vendor:N', 'count()']
).properties(
    title='Vulnerabilities by Year and Vendor'
).interactive()
chart_year_vendor.save(os.path.join(OUTPUT_DIR, 'vulnerabilities_year_vendor.html'))

# Set chart width and font size
chart_width = 800
font_size = 18  # Font size

# Suggested Charts

# Distribution of Top CWEs Over Time
top_cwes = df['cwe_category'].value_counts().head(5).index.tolist()
df_top_cwes = df[df['cwe_category'].isin(top_cwes)]

chart_cwe_trend = alt.Chart(df_top_cwes).mark_bar().encode(
    x=alt.X('year:O', axis=alt.Axis(labelFontSize=font_size, titleFontSize=font_size)),
    y=alt.Y('count()', axis=alt.Axis(labelFontSize=font_size, titleFontSize=font_size)),
    color=alt.Color('cwe_category:N', legend=alt.Legend(labelFontSize=25, titleFontSize=25)),  # Increase legend font size
    tooltip=['year:O', 'cwe_category:N', 'count()']
).properties(
    width=chart_width
).interactive()
chart_cwe_trend.save(os.path.join(OUTPUT_DIR, 'cwe_trend.html'))

# Distribution of Top CWEs by Volume
chart_cwe_volume = alt.Chart(df_top_cwes).mark_bar().encode(
    x=alt.X('cwe_category:N', axis=alt.Axis(labelFontSize=font_size, titleFontSize=font_size)),
    y=alt.Y('count()', axis=alt.Axis(labelFontSize=font_size, titleFontSize=font_size)),
    color=alt.Color('cwe_category:N', legend=alt.Legend(labelFontSize=25, titleFontSize=25)),  # Increase legend font size
    tooltip=['cwe_category:N', 'count()']
).properties(
    width=chart_width
).interactive()
chart_cwe_volume.save(os.path.join(OUTPUT_DIR, 'cwe_volume.html'))

# 2. Distribution of Severity by Vendor
chart_severity_vendor = alt.Chart(df).mark_bar().encode(
    x=alt.X('vendor:N', axis=alt.Axis(labelFontSize=font_size, titleFontSize=font_size)),
    y=alt.Y('count()', axis=alt.Axis(labelFontSize=font_size, titleFontSize=font_size)),
    color='severity:N',
    tooltip=['vendor:N', 'severity:N', 'count()']
).properties(
    title='Distribution of Severity by Vendor',
    width=chart_width
).interactive()
chart_severity_vendor.save(os.path.join(OUTPUT_DIR, 'severity_vendor.html'))

# 3. Trend of CVSS Scores Over Time
chart_cvss_trend = alt.Chart(df).mark_line().encode(
    x=alt.X('published:T', axis=alt.Axis(labelFontSize=font_size, titleFontSize=font_size)),
    y=alt.Y('mean(cvss_score):Q', axis=alt.Axis(labelFontSize=font_size, titleFontSize=font_size)),
    tooltip=[alt.Tooltip('published:T', title='Published', formatType='time'),
             alt.Tooltip('mean(cvss_score):Q', title='Mean CVSS Score', formatType='number')]
).properties(
    title='Trend of CVSS Scores Over Time',
    width=chart_width
).interactive()
chart_cvss_trend.save(os.path.join(OUTPUT_DIR, 'cvss_trend.html'))