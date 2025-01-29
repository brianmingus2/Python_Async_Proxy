#!/bin/bash

# Define proxy credentials
PROXY_URL="http://localhost:8888"
PROXY_USER="username"
PROXY_PASSWORD="password"

# List of domains for testing
URLS=(
    "https://example.com"
    "https://google.com"
    "https://facebook.com"
    "https://youtube.com"
    "https://twitter.com"
    "https://amazon.com"
    "https://wikipedia.org"
    "https://linkedin.com"
    "https://reddit.com"
    "https://instagram.com"
    "https://microsoft.com"
    "https://apple.com"
    "https://github.com"
    "https://stackoverflow.com"
    "https://netflix.com"
    "https://yahoo.com"
    "https://bing.com"
    "https://pinterest.com"
    "https://quora.com"
    "https://medium.com"
    "https://cnn.com"
    "https://bbc.com"
    "https://hulu.com"
    "https://ebay.com"
    "https://adobe.com"
    "https://nytimes.com"
    "https://nasa.gov"
    "https://weather.com"
    "https://forbes.com"
    "https://washingtonpost.com"
    "https://paypal.com"
    "https://dropbox.com"
    "https://slack.com"
    "https://zoom.us"
    "https://salesforce.com"
    "https://airbnb.com"
    "https://booking.com"
    "https://expedia.com"
    "https://tripadvisor.com"
    "https://spotify.com"
    "https://soundcloud.com"
    "https://tiktok.com"
    "https://discord.com"
    "https://shopify.com"
    "https://theguardian.com"
    "https://reuters.com"
    "https://wsj.com"
    "https://bloomberg.com"
    "https://cnbc.com"
    "https://alskdjasldkfjalskdfjalskdfjalskdfja.com"
    "http://example.com"
)

# Create a base directory for storing results
BASE_DIR="domains"
rm -fr $BASE_DIR
mkdir -p "$BASE_DIR"

# Perform concurrent requests using curl
echo "Starting concurrent requests to ${#URLS[@]} domains..."

for URL in "${URLS[@]}"; do
    # Extract the domain name for directory creation
    DOMAIN=$(echo "$URL" | awk -F[/:] '{print $4}')
    DOMAIN_DIR="$BASE_DIR/$DOMAIN"
    mkdir -p "$DOMAIN_DIR"

    # Save the response to domain.html in the appropriate subdirectory
    curl -s -x $PROXY_URL --proxy-user $PROXY_USER:$PROXY_PASSWORD -L "$URL" > "$DOMAIN_DIR/domain.html" 2>&1 &
done

# Wait for all background jobs to complete
wait
echo "All requests completed. Responses saved in the $BASE_DIR directory."

# Fetch and print the proxy metrics
echo "Fetching proxy metrics..."
METRICS=$(curl -s http://localhost:8888/metrics | jq)

# Check if metrics were successfully fetched
if [ -z "$METRICS" ]; then
    echo "Failed to fetch proxy metrics."
    exit 1
fi

echo "Proxy Metrics: $METRICS"

wrk -t1 -c100 -d30 --latency -H "Proxy-Authorization: Basic $(echo -n 'username:password' | base64)" http://127.0.0.1:8888/index.html

siege -c100 -t30s --header="Proxy-Authorization: Basic $(echo -n 'username:password' | base64)" http://127.0.0.1:8888/index.html
