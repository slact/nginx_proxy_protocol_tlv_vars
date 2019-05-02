#!/usr/bin/zsh
version=$1

echo $version
echo `pwd`

ALL_OFF="\e[1;0m"
YELLOW="${BOLD}\e[1;33m"
GREEN="${BOLD}\e[1;32m"

prompt() {
  echo "${YELLOW}${BOLD}==>${ALL_OFF} $1"
  echo -n "${BLUE}${BOLD}==>${ALL_OFF} "
  read "$2"
}
confirm() {
  prompt "$1 ${YELLOW}[y/N]${ALL_OFF}" _yn
  case $_yn in
    [Yy]* ) return 0;;
    * ) return 1;;
  esac
}


base=nginx-$version
patched=nginx-$version-proxy_protocol_vars

rm .genpatch -Rf
mkdir .genpatch
cd .genpatch
wget "http://nginx.org/download/nginx-$version.tar.gz"
tar xzf $base.tar.gz
cp $base $patched -Rf

cp ../../src $patched/ -Rfv
rm $patched/src/nginx-source
rm $patched/src/nginx
#meld $base $patched
diff -ur -x '*~' -x '*.swp' $base/src $patched/src |colordiff
if confirm "Patch for $base looks ok?"; then
  diff -ur -x '*~' -x '*.swp' $base/src $patched/src > ../../$patched.patch
  cat ../../$patched.patch
  echo "${GREEN}saved to $patched.patch${ALL_OFF}"
else
  echo "${YELLOW}ok, double-check it then${ALL_OFF}"
fi
rm .genpatch -Rf

