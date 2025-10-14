#!/usr/bin/env bash
# Script to squash PR#3 commits
#
# This script performs the commit squashing for PR#3, replacing the merge commit
# and 8 individual commits with a single squashed commit.
#
# IMPORTANT: This script requires force push privileges on the repository.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}PR#3 Commit Squashing Script${NC}"
echo "========================================"
echo ""

# Get current branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "Current branch: $CURRENT_BRANCH"

if [ "$CURRENT_BRANCH" != "copilot/squash-commits-pr3" ]; then
    echo -e "${RED}Error: This script should be run from the copilot/squash-commits-pr3 branch${NC}"
    echo "Current branch is: $CURRENT_BRANCH"
    exit 1
fi

# Confirm with user
echo ""
echo -e "${YELLOW}WARNING:${NC} This will rewrite git history!"
echo "The following changes will be made:"
echo "  - Reset to commit 5a4e61b6 (before PR#3 merge)"
echo "  - Squash 8 commits from PR#3 into a single commit"
echo "  - Force push the new history to origin/copilot/squash-commits-pr3"
echo ""
read -p "Do you want to continue? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

echo ""
echo "Step 1: Resetting to base commit 5a4e61b6..."
git reset --hard 5a4e61b6

echo "Step 2: Squash merging PR#3 commits (f144342f through 58581038)..."
git merge --squash 58581038

echo "Step 3: Creating squashed commit..."
git commit -m "Add --testcase-timeout CLI option

Add functionality to set a default timeout for all testcases via the
--testcase-timeout CLI option. The implementation includes:

- CLI option --testcase-timeout to specify default testcase timeout
- Support for value of 0 to disable timeout completely
- Comprehensive tests for the functionality
- Documentation updates in multitest.rst
- Terminology fixes to use 'testsuite' consistently

This squashes the following commits from PR#3:
- f144342f Initial plan
- 1ddbc9b9 Add CLI option for default testcase timeout
- 7c78d9c5 Add tests and documentation for default testcase timeout
- 565a4e5b Rename example file and improve documentation
- b098c68c Allow 0 as valid testcase_timeout value to disable timeout
- 94f645e5 Make default testcase timeout documentation more succinct
- a546315d Fix terminology: use 'testsuite' instead of 'test suite'
- 58581038 Remove CLI timeout example file

Covered by DCO"

echo ""
echo "Step 4: Force pushing to origin..."
git push --force-with-lease origin copilot/squash-commits-pr3

echo ""
echo -e "${GREEN}Success!${NC} PR#3 commits have been squashed."
echo ""
echo "Summary:"
echo "  - Original: 8 commits + 1 merge commit"
echo "  - New: 1 squashed commit"
echo "  - Files changed: 6 files, 153 insertions"
echo ""
echo "To verify the changes:"
echo "  git log --oneline --graph -10"
