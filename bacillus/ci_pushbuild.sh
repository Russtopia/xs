#!/bin/bash
#
## bacillus (https://gogs.blitter.com/Russtopia/bacillus) build/test CI script

export GOPATH="${HOME}/go"
export PATH=/usr/local/bin:/usr/bin:/usr/lib/ccache/bin:/bin:$GOPATH/bin
export GO111MODULE=on
# GOCACHE will be phased out in v1.12. [github.com/golang/go/issues/26809]
export GOCACHE="${HOME}/.cache/go-build"

echo "workdir: ${BACILLUS_WORKDIR}"
mkdir -p "${BACILLUS_ARTFDIR}"

echo "---"
go env
echo "---"
echo "passed env:"
env
echo "---"

cd ${REPO}
branch=$(git for-each-ref --sort=-committerdate --format='%(refname)' | head -n 1)
echo "Building most recent push on branch $branch"
git checkout "$branch"
ls

############
stage "Build"
############
make all

############
stage "UnitTests"
############
go test -v .

############
stage "Test(Authtoken)"
############
if [ -f ~/.xs_id ]; then
  echo "Clearing test user $USER ~/.xs_id file ..."
  mv ~/.xs_id ~/.xs_id.bak
fi
echo "Setting dummy authtoken in ~/.xs_id ..."
echo "localhost:asdfasdfasdf" >~/.xs_id
echo "Performing remote command on @localhost via authtoken login ..."
tokentest=$(timeout 10 xs -x "echo -n FOO" @localhost)
if [ "${tokentest}" != "FOO" ]; then
  echo "AUTHTOKEN LOGIN FAILED"
  exit 1
else
  echo "client cmd performed OK."
  unset tokentest
fi

############
stage "Test(S->C)"
############
echo "Testing secure copy from server -> client ..."
tmpdir=$$
mkdir -p /tmp/$tmpdir
cd /tmp/$tmpdir
xc @localhost:${BACILLUS_WORKDIR}/build/xs/cptest .
echo -n "Integrity check on copied files (sha1sum) ..."
sha1sum $(find cptest -type f | sort) >sc.sha1sum
diff sc.sha1sum ${BACILLUS_WORKDIR}/build/xs/cptest.sha1sum
stat=$?
cd -

rm -rf /tmp/$tmpdir
if [ $stat -eq "0" ]; then
  echo "OK."
else
  echo "FAILED!"
  exit $stat
fi

############
stage "Test(C->S)"
############
echo "TODO ..."

if [ -f ~/.xs_id.bak ]; then
  echo "Restoring test user $USER ~/.xs_id file ..."
  mv ~/.xs_id.bak ~/.xs_id
fi

############
stage "Lint"
############
make lint

############
stage "Artifacts"
############
echo -n "Creating tarfile ..."
tar -cz --exclude=.git --exclude=cptest -f ${BACILLUS_ARTFDIR}/xs.tgz .

############
stage "Cleanup"
############
# nop

echo
echo "--Done--"
