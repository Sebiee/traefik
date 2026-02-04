#!/usr/bin/env bash
set -e

if [ -n "${VERSION}" ]; then
  echo "Deploying..."
else
  echo "Skipping deploy"
  exit 0
fi

git config --global user.email "${DEPLOYER_EMAIL}"
git config --global user.name "Release Bot"

# load ssh key
eval "$(ssh-agent -s)"
chmod 600 ~/.ssh/deploy_rsa
ssh-add ~/.ssh/deploy_rsa

# update traefik-library-image repo (Docker image)
echo "Updating traefik-library-image repo..."
git clone git@github.com:Sebiee/traefik-library-image.git
cd traefik-library-image
./updatev3.sh "${VERSION}"
git add -A
echo "${VERSION}" | git commit --file -
echo "${VERSION}" | git tag -a "${VERSION}" --file -
git push -q --follow-tags -u origin master > /dev/null 2>&1

cd ..
rm -Rf traefik-library-image/

echo "Deployed"
