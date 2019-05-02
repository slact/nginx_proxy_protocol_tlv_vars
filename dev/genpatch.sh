#!/usr/bin/zsh
version=$1

echo $version
echo `pwd`

ALL_OFF="\e[1;0m"
BOLD="\e[1;1m"
BLUE="${BOLD}\e[1;34m"
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

mkdir .genpatch 2>/dev/null
rm ".genpatch/$base" -Rf 2>/dev/null
rm ".genpatch/$patched"  -Rf 2>/dev/null
cd .genpatch
if [[ ! -e $base.tar.gz ]]; then
  wget "http://nginx.org/download/$base.tar.gz"
else
  echo "$base.tar.gz already present"
fi
tar xzf $base.tar.gz
cp $base $patched -Rf

cp ../../src $patched/ -Rfv
rm $patched/src/nginx-source
rm $patched/src/nginx
if [[ $2 == "meld" ]]; then
  meld -a  $patched $base
else
  diff -ur -x '*~' -x '*.swp' $base/src $patched/src |colordiff
fi
if confirm "Patch for $base looks ok?"; then
  diff -ur -x '*~' -x '*.swp' $base/src $patched/src > ../../$patched.patch
  cat ../../$patched.patch
  echo "${GREEN}saved to $patched.patch${ALL_OFF}"
else
  echo "${YELLOW}ok, double-check it then${ALL_OFF}"
fi
rm ".genpatch/$base" ".genpatch/$patched" -Rf

