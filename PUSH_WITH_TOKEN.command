#!/bin/bash
# Double-click this to push SiteSnap to GitHub using a Personal Access Token
cd "$(dirname "$0")"

echo "============================================"
echo "  SiteSnap — Push to GitHub"
echo "============================================"
echo ""
echo "You need a GitHub Personal Access Token to push."
echo ""
echo "If you don't have one yet:"
echo "  1. Go to: https://github.com/settings/tokens"
echo "  2. Click 'Generate new token (classic)'"
echo "  3. Give it a name, set expiry, check the 'repo' scope"
echo "  4. Click 'Generate token' and copy it"
echo ""
echo "Paste your GitHub token below (input is hidden):"
read -rs GH_TOKEN
echo ""

if [ -z "$GH_TOKEN" ]; then
  echo "❌ No token entered. Exiting."
  read -n 1
  exit 1
fi

# Set remote URL with token embedded
git remote set-url origin "https://sitesnapadmin-claine:${GH_TOKEN}@github.com/sitesnapadmin-claine/sitesnap.git"

echo "🚀 Pushing to GitHub..."
git push --force -u origin main

if [ $? -eq 0 ]; then
  echo ""
  echo "✅ Pushed successfully!"
  echo "   Railway will auto-redeploy in ~2 minutes."
  echo "   Check: https://railway.app/dashboard"
else
  echo ""
  echo "❌ Push failed. Double-check your token has 'repo' scope."
fi

# Remove token from remote URL for security
git remote set-url origin "https://github.com/sitesnapadmin-claine/sitesnap.git"

echo ""
echo "Press any key to close..."
read -n 1
