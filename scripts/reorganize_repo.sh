#!/bin/bash
set -e

echo "Creating backup..."
timestamp=$(date +%Y%m%d_%H%M%S)
backup_dir="../InfraSpectre_backup_${timestamp}"
cp -r . "$backup_dir"

echo "Moving files from inner InfraSpectre directory..."
# Move everything from inner InfraSpectre to root, avoiding conflicts
cp -r InfraSpectre/proto_stubs ./
cp -r InfraSpectre/common/* common/
cp -r InfraSpectre/agents/* agents/

echo "Creating new virtual environment..."
python3 -m venv .venv

echo "Removing duplicate directories..."
rm -rf InfraSpectre/proto InfraSpectre/common InfraSpectre/agents
rm -rf InfraSpectre/IS InfraSpectre/agents/IS InfraSpectre/agents/activate

echo "Consolidating requirements..."
cat InfraSpectre/requirements.txt >> requirements.txt
sort -u requirements.txt -o requirements.txt

echo "Updating import paths..."
find . -type f -name "*.py" -exec sed -i '' 's/from InfraSpectre\./from /g' {} +
find . -type f -name "*.py" -exec sed -i '' 's/import InfraSpectre\./import /g' {} +

echo "Cleaning up..."
rm -rf InfraSpectre/LICENSE InfraSpectre/README.md InfraSpectre/requirements.txt
rmdir InfraSpectre 2>/dev/null || true

echo "Done! A backup has been created at: $backup_dir"
echo "Please verify the changes and then remove the backup if everything is working correctly."
