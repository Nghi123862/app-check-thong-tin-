import os
from pyspark.sql import SparkSession
from pyspark.sql.functions import broadcast, col, lower, regexp_replace

def create_spark_session(app_name="URLViolationDetector"):
    """Creates and returns a Spark session."""
    return SparkSession.builder.appName(app_name).master("local[*]").getOrCreate()

def main():
    """
    Main function to process URLs, detect violations using a broadcast join, and save the results.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)

    urls_csv_path = os.path.join(project_root, 'data', 'urls.csv')
    keywords_txt_path = os.path.join(project_root, 'data', 'keywords_violation.txt')
    output_csv_path = os.path.join(script_dir, 'violated_urls.csv')

    spark = create_spark_session()

    # Load keywords into a DataFrame
    try:
        keywords_df = spark.read.text(keywords_txt_path).toDF("keyword")
        keywords_df = keywords_df.filter(~col("keyword").startswith("#") & (col("keyword") != ""))\
                                 .select(lower(col("keyword")).alias("keyword"))

        if keywords_df.count() == 0:
            print(f"Warning: No violation keywords found in '{keywords_txt_path}'. The output will be empty.")
            spark.stop()
            return
    except Exception as e:
        print(f"Error reading keywords file '{keywords_txt_path}': {e}")
        spark.stop()
        return

    # Read the URLs CSV file
    try:
        urls_df = spark.read.option("encoding", "UTF-8").csv(urls_csv_path, header=True, inferSchema=True)
        if "url" not in urls_df.columns:
            print(f"Error: The CSV file at '{urls_csv_path}' must contain a 'url' column.")
            spark.stop()
            return
    except Exception as e:
        print(f"Error reading '{urls_csv_path}': {e}")
        spark.stop()
        return

    # Prepare the URL data by replacing hyphens with spaces and converting to lowercase
    urls_to_check_df = urls_df.withColumn(
        "processed_url",
        lower(regexp_replace(col("url"), "-", " "))
    )

    # Use a broadcast join with a filter condition to find matches.
    violated_urls_df = urls_to_check_df.join(
        broadcast(keywords_df),
        urls_to_check_df.processed_url.contains(keywords_df.keyword)
    ).select(urls_df["url"], urls_df["date"]).distinct()

    # Save the results
    try:
        violated_urls_df.coalesce(1).write.mode("overwrite").csv(output_csv_path, header=True)
        print(f"Violated URLs have been saved to '{output_csv_path}'")
    except Exception as e:
        print(f"Error saving data to '{output_csv_path}': {e}")
        spark.stop()
        return

    # Show the first 10 results
    print("\n--- First 10 Violated URLs ---")
    violated_urls_df.show(10, truncate=False)

    spark.stop()

if __name__ == "__main__":
    main()