#!/bin/sh

function die() {
	echo ${@}
	exit 1;
}

git fetch || die "Unable to fetch from git...";
git rebase origin || die "Error rebasing...";
git submodule init || die "Error with submodules..."
git submodule update || die "Error updating submodules..."
ant clean jar || die "Error building...";

rm -Rf DMDircRelay
mkdir DMDircRelay || die "Error creating directory..."
ln -s ${PWD}/src DMDircRelay || die "Error linking src..."
ln -s ${PWD}/build.xml DMDircRelay || die "Error linking build.xml..."
ln -s ${PWD}/manifest.mf DMDircRelay || die "Error linking manifest.mf..."
ln -s ${PWD}/modules DMDircRelay || die "Error linking modules..."
ln -s ${PWD}/nbproject DMDircRelay || die "Error linking nbproject..."
ln -s ${PWD}/README DMDircRelay || die "Error linking README..."

zip -r DMDircRelay.zip DMDircRelay -x DMDircRelay/modules/parser/.git/\* DMDircRelay/nbproject/private/\* || die "Unable to zip...";

rm -Rf DMDircRelay || die "Unable to cleanup..."

echo "Done!"
exit 0;