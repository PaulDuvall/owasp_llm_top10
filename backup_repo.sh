#!/bin/bash
# Bi-directional backup/restore script for OWASP LLM Top 10 repo
# Usage: ./backup_repo.sh [backup|restore]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="$HOME/Code/_backups/owasp_llm_top10"

mkdir -p "$BACKUP_DIR"

cd "$REPO_ROOT"

MODE="${1:-backup}"

if [[ "$MODE" == "backup" ]]; then
    # Use git to list all files not ignored and not in .git
    git ls-files --others --cached --exclude-standard > /tmp/backup_filelist.txt
    # Copy files, preserving directory structure
    rsync -av --files-from=/tmp/backup_filelist.txt --exclude='.git/' ./ "$BACKUP_DIR"
    echo "Backup complete: $BACKUP_DIR"
elif [[ "$MODE" == "restore" ]]; then
    # Restore from backup to repo, excluding .git and files in .gitignore
    cd "$BACKUP_DIR"
    # Use the repo's .gitignore for excludes
    RSYNC_EXCLUDES=()
    if [[ -f "$REPO_ROOT/.gitignore" ]]; then
        while IFS= read -r pattern; do
            [[ -z "$pattern" || "$pattern" =~ ^# ]] && continue
            RSYNC_EXCLUDES+=(--exclude="$pattern")
        done < "$REPO_ROOT/.gitignore"
    fi
    rsync -av --exclude='.git/' "${RSYNC_EXCLUDES[@]}" ./ "$REPO_ROOT"
    echo "Restore complete: $REPO_ROOT"
else
    echo "Usage: $0 [backup|restore]"
    exit 1
fi