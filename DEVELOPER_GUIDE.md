# Developer Guide

This guide helps developers get started with building and testing the OpenSearch Storage Encryption plugin.

## Prerequisites

1. JDK 21 or higher
2. Git
3. Gradle
4. AWS Account (for KMS integration testing)

## Environment Setup

Create an environment file for your AWS credentials and KMS configuration:

```bash
# Create environment file for sensitive information
cat > .env << 'EOF'
# AWS Credentials for KMS
AWS_ACCESS_KEY_ID="your_access_key_here"
AWS_SECRET_ACCESS_KEY="your_secret_key_here"
AWS_SESSION_TOKEN="your_session_token_here"

# AWS KMS configuration
KMS_REGION="us-east-1"
KMS_KEY_ARN="arn:aws:kms:us-east-1:ACCOUNT_ID:key/KEY_ID"
EOF

# Edit the file with your actual values
# Then source the environment file
source .env
```

## Building the Plugin Alone

If you only need to build the plugin without setting up a full OpenSearch environment:

```bash
# Clone the Storage Encryption plugin
git clone https://github.com/opensearch-project/opensearch-storage-encryption.git
cd opensearch-storage-encryption

# Build the plugin
./gradlew clean assemble

# Run all checks including tests
./gradlew check
```

## Development Setup with OpenSearch

For a complete development environment:

```bash
# Set up required variables
OPENSEARCH_VERSION="3.1.0-SNAPSHOT"
BASE_DIR="$(pwd)"
OPENSEARCH_DIR="${BASE_DIR}/OpenSearch"
STORAGE_ENCRYPTION_DIR="${BASE_DIR}/opensearch-storage-encryption"
OPENSEARCH_DIST_DIR="${OPENSEARCH_DIR}/build/distribution/local/opensearch-${OPENSEARCH_VERSION}"
JVM_HEAP_SIZE="4g"
JVM_DIRECT_MEM_SIZE="4g"
DEBUG_PORT="5005"

# Create and navigate to your workspace directory
mkdir -p "${BASE_DIR}" && cd "${BASE_DIR}"

# Clone OpenSearch
git clone https://github.com/opensearch-project/OpenSearch.git "${OPENSEARCH_DIR}"

# Clone Storage Encryption plugin
git clone https://github.com/opensearch-project/opensearch-storage-encryption.git "${STORAGE_ENCRYPTION_DIR}"

# Build Storage Encryption plugin
cd "${STORAGE_ENCRYPTION_DIR}"
./gradlew clean assemble

# Build Crypto KMS plugin (required dependency)
cd "${OPENSEARCH_DIR}"
./gradlew :plugins:crypto-kms:assemble

# Build local distribution
./gradlew localDistro
```

## Installing and Configuring Plugins

```bash
# Navigate to the OpenSearch distribution directory
cd "${OPENSEARCH_DIST_DIR}/bin"

# Install Storage Encryption plugin
./opensearch-plugin install file:${STORAGE_ENCRYPTION_DIR}/build/distributions/storage-encryption.zip

# Install Crypto KMS plugin
./opensearch-plugin install file:${OPENSEARCH_DIR}/plugins/crypto-kms/build/distributions/crypto-kms-${OPENSEARCH_VERSION}.zip

# Create keystore and add credentials from environment variables
./opensearch-keystore create
echo "${AWS_SESSION_TOKEN}" | ./opensearch-keystore add -x kms.session_token
echo "${AWS_ACCESS_KEY_ID}" | ./opensearch-keystore add -x kms.access_key
echo "${AWS_SECRET_ACCESS_KEY}" | ./opensearch-keystore add -x kms.secret_key

# Append KMS configuration to opensearch.yml
cat >> "${OPENSEARCH_DIST_DIR}/config/opensearch.yml" << EOF

# KMS Configuration
kms.region: ${KMS_REGION}
kms.key_arn: ${KMS_KEY_ARN}
EOF

# Update JVM settings
JVM_OPTIONS_FILE="${OPENSEARCH_DIST_DIR}/config/jvm.options"

# Update heap size
sed -i "s/^-Xms1g/-Xms${JVM_HEAP_SIZE}/" "${JVM_OPTIONS_FILE}"
sed -i "s/^-Xmx1g/-Xmx${JVM_HEAP_SIZE}/" "${JVM_OPTIONS_FILE}"

# Add required JVM options if not present
grep -qxF '--enable-preview' "${JVM_OPTIONS_FILE}" || echo '--enable-preview' >> "${JVM_OPTIONS_FILE}"
grep -qxF '--enable-native-access=ALL-UNNAMED' "${JVM_OPTIONS_FILE}" || echo '--enable-native-access=ALL-UNNAMED' >> "${JVM_OPTIONS_FILE}"
grep -qxF "-XX:MaxDirectMemorySize=${JVM_DIRECT_MEM_SIZE}" "${JVM_OPTIONS_FILE}" || echo "-XX:MaxDirectMemorySize=${JVM_DIRECT_MEM_SIZE}" >> "${JVM_OPTIONS_FILE}"
```

## Running and Testing OpenSearch

```bash
# Start OpenSearch
./opensearch
```

## Running Tests

### Unit Tests

```bash
cd "${STORAGE_ENCRYPTION_DIR}"
./gradlew test
```

### Integration Tests

```bash
./gradlew integrationTest
```

### YAML Rest Tests

```bash
./gradlew yamlRestTest
```

## Debugging

To debug the plugin:

```bash
# Add debug options to JVM configuration
grep -qxF '-Xdebug' "${JVM_OPTIONS_FILE}" || echo '-Xdebug' >> "${JVM_OPTIONS_FILE}"
grep -qxF "-Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=*:${DEBUG_PORT}" "${JVM_OPTIONS_FILE}" || \
echo "-Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=*:${DEBUG_PORT}" >> "${JVM_OPTIONS_FILE}"

# Connect your IDE debugger to the specified debug port
```

## Code Style

This project uses the OpenSearch code style. To apply the style:

```bash
./gradlew spotlessApply
```

## Contributing

1. Fork the repository
2. Create a new branch for your changes
3. Make your changes
4. Run tests
5. Submit a pull request

## Troubleshooting

Common issues and their solutions:

- **Plugin installation fails**: Ensure compatible versions of OpenSearch and plugins
- **KMS integration issues**: Verify AWS credentials in your `.env` file
- **Memory issues**: Adjust JVM heap size and direct memory settings
- **Path issues**: Check that all directory paths are correct