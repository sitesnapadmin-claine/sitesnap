#!/bin/bash
# SiteSnap — push changes to GitHub → triggers Railway auto-deploy
# Usage: bash "deploy.sh" from Terminal

set -e
cd "$(dirname "$0")"

echo "🧹 Cleaning up any incomplete git state..."
rm -rf .git

echo "📦 Initializing fresh git repo..."
git init -b main
git add -A
git commit -m "Add edit wizard, live preview, and DNS check"

echo ""
echo "✅ Committed! Now run the two lines below in Terminal:"
echo "   (replace YOUR_USERNAME with your GitHub username)"
echo ""
echo "   git remote add origin https://github.com/YOUR_USERNAME/sitesnap.git"
echo "   git push --force -u origin main"
echo ""
echo "Railway will auto-redeploy in ~2 minutes after the push."
