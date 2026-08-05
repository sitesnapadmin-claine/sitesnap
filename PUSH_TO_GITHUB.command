#!/bin/bash
# Double-click this file to push SiteSnap to GitHub → Railway auto-deploys
cd "$(dirname "$0")"

echo "============================================"
echo "  SiteSnap — Deploy to Railway via GitHub"
echo "============================================"
echo ""

# Clean up sandbox-created git state
rm -rf .git 2>/dev/null

# Initialize git
git init -b main
git add -A
git commit -m "Add edit wizard, live preview, and DNS check"

echo ""
echo "✅ Code committed!"
echo ""

# Check if remote already exists
if git remote get-url origin &>/dev/null; then
  echo "📡 Remote found: $(git remote get-url origin)"
  git push --force -u origin main
  echo ""
  echo "🚀 Pushed! Railway will redeploy in ~2 minutes."
  echo "   Check: https://railway.app/dashboard"
else
  echo "⚠️  No GitHub remote set yet."
  echo ""
  GH_USER="sitesnapadmin-claine"
  echo "Using GitHub username: $GH_USER"
  echo ""
  git remote add origin "https://github.com/${GH_USER}/sitesnap.git"
  git push --force -u origin main
  echo ""
  echo "🚀 Pushed! Railway will redeploy in ~2 minutes."
  echo "   Check: https://railway.app/dashboard"
fi

echo ""
echo "Press any key to close..."
read -n 1
